const net = require('net');

/**
 * Registro central de puertos para evitar colisiones entre los cuatro
 * subsistemas que reservan puertos locales en el host:
 *  - `localRunner`     (proyectos locales en desarrollo)
 *  - `deployManager`   (contenedores de producción Citadel: 20000–24999)
 *  - `catalogManager`  (servicios 1-clic del catálogo: 42000–42999)
 *  - `databaseManager` (exposiciones opcionales de BDs: 28000–29999)
 *
 * Protege también los puertos de contenedores detenidos usados como ancla de
 * rollback (`previous`) para que otro servicio jamás los robe, e impide que
 * `localRunner.killProcessOnPort` mate un proxy de Docker o un servicio ajeno.
 */

const RANGES = {
  local: { start: 15000, end: 19999 },
  deploy: { start: 20000, end: 24999 },
  database: { start: 28000, end: 29999 },
  catalog: { start: 42000, end: 42999 }
};

/** @param {number} port @param {string} [host] */
function probePortFree(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.unref();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, host);
  });
}

class PortRegistry {
  constructor() {
    /** Puertos actualmente prestados en vuelo o reservados en memoria: port -> { owner, kind, at } */
    /** @type {Map<number, { owner: string, kind: string, at: number }>} */
    this.leases = new Map();
    /** Proveedores externos de puertos persistidos (p. ej. deployManager.store, catalogManager.state) */
    /** @type {Map<string, () => Iterable<number>>} */
    this.providers = new Map();
  }

  /** @param {string} name @param {() => Iterable<number>} fn */
  registerProvider(name, fn) {
    if (typeof fn === 'function') this.providers.set(name, fn);
  }

  /** Conjunto completo de puertos ocupados o reservados entre todos los subsistemas. */
  getAllReservedPorts() {
    /** @type {Set<number>} */
    const set = new Set(this.leases.keys());
    for (const fn of this.providers.values()) {
      try {
        for (const p of fn()) {
          const n = Number(p);
          if (Number.isInteger(n) && n > 0 && n <= 65535) set.add(n);
        }
      } catch (e) {}
    }
    return set;
  }

  /**
   * ¿Está este puerto reservado por algún subsistema de Culkibo (Docker, catálogo, BD o deploy)?
   * @param {number} port
   * @param {string | null} [excludeKind]
   */
  isProtectedPort(port, excludeKind = null) {
    const n = Number(port);
    if (!Number.isInteger(n)) return false;
    const lease = this.leases.get(n);
    if (lease && (!excludeKind || lease.kind !== excludeKind)) return true;
    for (const [name, fn] of this.providers.entries()) {
      if (excludeKind && name === excludeKind) continue;
      try {
        for (const p of fn()) {
          if (Number(p) === n) return true;
        }
      } catch (e) {}
    }
    return false;
  }

  /** Reserva explícita (idempotente) de un puerto mientras se levanta un contenedor/proceso. */
  lease(port, owner, kind = 'generic') {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return false;
    const existing = this.leases.get(n);
    if (existing && existing.owner !== owner) return false;
    this.leases.set(n, { owner: String(owner || 'unknown'), kind, at: Date.now() });
    return true;
  }

  /**
   * Libera una reserva por número de puerto (o solo si pertenece a `owner`).
   * @param {number} port
   * @param {string | null} [owner]
   */
  release(port, owner = null) {
    const n = Number(port);
    const existing = this.leases.get(n);
    if (!existing) return;
    if (owner && existing.owner !== owner) return;
    this.leases.delete(n);
  }

  /** Libera todas las reservas de un propietario (p. ej. al borrar/fallar un despliegue). */
  releaseOwner(owner) {
    for (const [port, info] of this.leases.entries()) {
      if (info.owner === owner) this.leases.delete(port);
    }
  }

  /**
   * Asigna atómicamente un puerto libre dentro del rango del subsistema,
   * evitando colisiones entre invocaciones concurrentes (`leases` en memoria)
   * y comprobando tanto el registro global como el socket real del SO.
   *
   * @param {{
   *   kind?: 'local' | 'deploy' | 'catalog' | 'database',
   *   owner?: string,
   *   start?: number,
   *   end?: number,
   *   preferred?: number | null,
   *   extraExcluded?: Set<number> | number[] | null,
   *   host?: string
   * }} [opts]
   */
  async allocate({
    kind = 'deploy',
    owner = `lease_${Date.now()}`,
    start = undefined,
    end = undefined,
    preferred = null,
    extraExcluded = null,
    host = '127.0.0.1'
  } = {}) {
    const def = RANGES[kind] || RANGES.deploy;
    const rangeStart = Number.isInteger(start) ? Number(start) : def.start;
    const rangeEnd = Number.isInteger(end) ? Number(end) : def.end;
    const reserved = this.getAllReservedPorts();
    if (extraExcluded) {
      for (const p of extraExcluded) reserved.add(Number(p));
    }

    // Probar puerto preferido primero si se pidió y está libre
    if (Number.isInteger(preferred) && Number(preferred) >= 1024 && Number(preferred) <= 65535) {
      const pref = Number(preferred);
      if (!reserved.has(pref) && !this.leases.has(pref)) {
        this.leases.set(pref, { owner, kind, at: Date.now() });
        const ok = await probePortFree(pref, host);
        if (ok) return pref;
        this.leases.delete(pref);
      }
    }

    const span = Math.max(1, rangeEnd - rangeStart + 1);
    const offset = Math.floor(Math.random() * span);
    for (let i = 0; i < span; i++) {
      const candidate = rangeStart + ((offset + i) % span);
      if (reserved.has(candidate) || this.leases.has(candidate)) continue;
      // Reservar antes del await para cerrar la ventana TOCTOU entre tareas concurrentes
      this.leases.set(candidate, { owner, kind, at: Date.now() });
      const ok = await probePortFree(candidate, host);
      if (ok) return candidate;
      this.leases.delete(candidate);
    }

    throw new Error(`No quedan puertos libres en el rango ${rangeStart}–${rangeEnd} (${kind})`);
  }
}

const instance = Object.assign(new PortRegistry(), { PortRegistry, RANGES, probePortFree });
module.exports = instance;
