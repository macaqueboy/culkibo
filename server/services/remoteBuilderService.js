const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { atomicWriteJsonSync } = require('./ssrfGuard');

/**
 * Distributed Remote Build-Node Offloader with Active-Build SSH Mux Ref-Count Pinning
 * (cures `coolify#11372`/`#10853` mid-build `ssh -O exit` kills, `dokploy#3226` shared-queue
 * stalls, and `dokploy#3450` PR preview offload).
 *
 * Garantías:
 *  - 0 dependencias npm externas, 0 invocaciones de shell, carga perezosa.
 *  - Persistencia atómica (`0o600`) en `CULKIBO_DATA_DIR/data/remote-builders.json`.
 *  - Colas y contadores `activeBuilds` estrictamente independientes por nodo constructor.
 *  - `canRecycleMux(builderId)` impide reciclar/cerrar el túnel SSH ControlMaster mientras
 *    `activeBuilds > 0` (`ACTIVE_BUILDS_IN_FLIGHT`).
 */

const BUILDER_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const SAFE_HOST_RE = /^[a-zA-Z0-9._:-]{1,253}$/;
const VALID_ARCHES = new Set(['linux/amd64', 'linux/arm64', 'multi']);
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** @param {string | null} [overrideDir] */
function resolveDataDir(overrideDir = null) {
  if (overrideDir) return path.resolve(overrideDir);
  if (process.env.CULKIBO_DATA_DIR) {
    return path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data');
  }
  return path.resolve(__dirname, '..', '..', 'data');
}

/**
 * Genera el array de argumentos `docker buildx prune` acotado (cero shell, `coolify#12542`).
 * @param {{ keepStorageGb?: number }} [opts]
 * @returns {string[]}
 */
function buildPruneArgs(opts = {}) {
  const gb = Math.min(500, Math.max(1, Math.round(Number(opts.keepStorageGb ?? 20) || 20)));
  return ['buildx', 'prune', '--force', '--keep-storage', `${gb}GB`];
}

class RemoteBuilderService {
  /**
   * @param {{ dataDir?: string | null }} [opts]
   */
  constructor(opts = {}) {
    this._dataDirOverride = opts.dataDir || null;
    this._loaded = false;
    /** @type {{ version: number, builders: Record<string, any> }} */
    this.state = { version: 1, builders: Object.create(null) };
    /**
     * Contadores en memoria de builds activos y colas independientes por builderId.
     * @type {Map<string, { activeBuilds: number, leases: Set<string>, queue: Array<{ queueId: string, projectId: string, isPreview: boolean, enqueuedAt: string }> }>}
     */
    this._runtime = new Map();
    /** @type {Map<string, { leaseId: string, builderId: string, projectId: string, isPreview: boolean, acquiredAt: string }>} */
    this._leases = new Map();
  }

  get dataDir() {
    return resolveDataDir(this._dataDirOverride);
  }

  get storeFile() {
    return path.join(this.dataDir, 'remote-builders.json');
  }

  _ensureLoaded() {
    if (this._loaded) return;
    this._loaded = true;
    const bakFile = `${this.storeFile}.bak`;
    for (const candidate of [this.storeFile, bakFile]) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
        if (parsed && typeof parsed === 'object' && parsed.builders && typeof parsed.builders === 'object') {
          const clean = Object.create(null);
          for (const [bid, b] of Object.entries(parsed.builders)) {
            if (!FORBIDDEN_PROTO_KEYS.has(bid) && b && typeof b === 'object') {
              clean[bid] = b;
            }
          }
          this.state = { version: 1, builders: clean };
          return;
        }
      } catch (e) {}
    }
    this.state = { version: 1, builders: Object.create(null) };
  }

  _save() {
    this._ensureLoaded();
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.storeFile)) {
      try { fs.copyFileSync(this.storeFile, `${this.storeFile}.bak`); } catch (e) {}
    }
    atomicWriteJsonSync(this.storeFile, this.state, 0o600);
  }

  /** @param {string} builderId */
  _getRuntimeSlot(builderId) {
    let slot = this._runtime.get(builderId);
    if (!slot) {
      slot = { activeBuilds: 0, leases: new Set(), queue: [] };
      this._runtime.set(builderId, slot);
    }
    return slot;
  }

  /**
   * Registra o actualiza un nodo constructor remoto.
   *
   * @param {{
   *   id?: string,
   *   name: string,
   *   host: string,
   *   arch?: 'linux/amd64' | 'linux/arm64' | 'multi' | string,
   *   maxConcurrency?: number,
   *   allowPreviews?: boolean,
   *   keepStorageGb?: number,
   *   sshPort?: number
   * }} opts
   */
  registerBuilder(opts) {
    this._ensureLoaded();
    const name = String((opts && opts.name) || '').trim().slice(0, 80);
    if (!name) {
      const err = new Error('registerBuilder requiere name');
      /** @type {any} */ (err).status = 400;
      throw err;
    }
    const host = String((opts && opts.host) || '').trim();
    if (!host || !SAFE_HOST_RE.test(host) || host.includes('..') || /[;|&`$\s\r\n\0]/.test(host)) {
      const err = new Error(`Host de builder remoto inválido: "${host.slice(0, 60)}"`);
      /** @type {any} */ (err).status = 400;
      throw err;
    }

    const rawId = opts && opts.id
      ? String(opts.id).trim()
      : `bld_${name.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24) || 'node'}_${crypto.randomBytes(2).toString('hex')}`;
    if (!BUILDER_ID_RE.test(rawId) || FORBIDDEN_PROTO_KEYS.has(rawId)) {
      const err = new Error(`ID de builder inválido: "${rawId.slice(0, 60)}"`);
      /** @type {any} */ (err).status = 400;
      throw err;
    }

    const rawArch = String((opts && opts.arch) || 'linux/amd64').trim().toLowerCase();
    const arch = VALID_ARCHES.has(rawArch) ? rawArch : 'linux/amd64';
    const maxConcurrency = Math.min(32, Math.max(1, Math.round(Number((opts && opts.maxConcurrency) ?? 2) || 2)));
    const allowPreviews = opts && opts.allowPreviews !== undefined ? Boolean(opts.allowPreviews) : true;
    const keepStorageGb = Math.min(500, Math.max(1, Math.round(Number((opts && opts.keepStorageGb) ?? 20) || 20)));
    const sshPort = Math.min(65535, Math.max(1, Math.round(Number((opts && opts.sshPort) ?? 22) || 22)));

    const nowIso = new Date().toISOString();
    const prev = this.state.builders[rawId];
    const record = {
      id: rawId,
      name,
      host,
      sshPort,
      arch,
      maxConcurrency,
      allowPreviews,
      keepStorageGb,
      createdAt: (prev && prev.createdAt) || nowIso,
      updatedAt: nowIso
    };

    this.state.builders[rawId] = record;
    this._save();

    const rt = this._getRuntimeSlot(rawId);
    return {
      ok: true,
      builder: {
        ...record,
        activeBuilds: rt.activeBuilds,
        queuedBuilds: rt.queue.length,
        availableSlots: Math.max(0, record.maxConcurrency - rt.activeBuilds),
        sshMuxPinned: rt.activeBuilds > 0,
        pruneArgs: buildPruneArgs({ keepStorageGb: record.keepStorageGb })
      }
    };
  }

  /** Lista todos los nodos constructores registrados con sus colas y estado de pinning SSH mux. */
  listBuilders() {
    this._ensureLoaded();
    const builders = Object.values(this.state.builders)
      .filter(Boolean)
      .map((b) => {
        const rt = this._getRuntimeSlot(b.id);
        return {
          ...b,
          activeBuilds: rt.activeBuilds,
          queuedBuilds: rt.queue.length,
          availableSlots: Math.max(0, b.maxConcurrency - rt.activeBuilds),
          sshMuxPinned: rt.activeBuilds > 0,
          pruneArgs: buildPruneArgs({ keepStorageGb: b.keepStorageGb })
        };
      })
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));

    return {
      ok: true,
      count: builders.length,
      builders
    };
  }

  /**
   * Adquiere un slot de build en un constructor remoto, fijando el ref-count del túnel
   * SSH ControlMaster (`sshMuxPinned: true`) para impedir desmontajes mid-build (`coolify#11372`).
   * Respeta colas independientes por constructor (`dokploy#3226`) y enrutado de PR previews
   * hacia builders con `allowPreviews: true` (`dokploy#3450`).
   *
   * @param {{
   *   builderId?: string | null,
   *   arch?: string,
   *   isPreview?: boolean,
   *   projectId?: string
   * }} [opts]
   */
  acquireBuildSlot(opts = {}) {
    this._ensureLoaded();
    const arch = String(opts.arch || 'linux/amd64').trim().toLowerCase();
    const isPreview = Boolean(opts.isPreview);
    const projectId = String(opts.projectId || '').trim().slice(0, 80);

    /** @type {any} */
    let chosen = null;
    if (opts.builderId) {
      chosen = this.state.builders[String(opts.builderId).trim()] || null;
      if (!chosen) {
        const err = new Error(`Builder remoto no encontrado: "${opts.builderId}"`);
        /** @type {any} */ (err).status = 404;
        throw err;
      }
      if (isPreview && !chosen.allowPreviews) {
        const err = new Error(`Builder "${chosen.id}" tiene deshabilitado el offload de PR previews (allowPreviews=false)`);
        /** @type {any} */ (err).status = 400;
        /** @type {any} */ (err).code = 'BUILDER_PREVIEWS_DISABLED';
        throw err;
      }
    } else {
      const candidates = Object.values(this.state.builders).filter((b) => {
        if (!b) return false;
        if (isPreview && !b.allowPreviews) return false;
        if (b.arch !== 'multi' && b.arch !== arch) return false;
        return true;
      });
      if (candidates.length === 0) {
        const err = new Error(
          isPreview
            ? `No hay ningún builder remoto compatible (${arch}) con allowPreviews=true`
            : `No hay ningún builder remoto registrado para arquitectura ${arch}`
        );
        /** @type {any} */ (err).status = 404;
        /** @type {any} */ (err).code = 'NO_ELIGIBLE_BUILDER';
        throw err;
      }
      // Elegir builder con mayor capacidad libre (y menor cola en empate)
      candidates.sort((a, b) => {
        const ra = this._getRuntimeSlot(a.id);
        const rb = this._getRuntimeSlot(b.id);
        const freeA = a.maxConcurrency - ra.activeBuilds;
        const freeB = b.maxConcurrency - rb.activeBuilds;
        if (freeB !== freeA) return freeB - freeA;
        if (ra.queue.length !== rb.queue.length) return ra.queue.length - rb.queue.length;
        return ra.activeBuilds - rb.activeBuilds;
      });
      chosen = candidates[0];
    }

    const rt = this._getRuntimeSlot(chosen.id);
    if (rt.activeBuilds < chosen.maxConcurrency) {
      const leaseId = `blease_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
      rt.activeBuilds++;
      rt.leases.add(leaseId);
      this._leases.set(leaseId, {
        leaseId,
        builderId: chosen.id,
        projectId,
        isPreview,
        acquiredAt: new Date().toISOString()
      });

      return {
        ok: true,
        leased: true,
        queued: false,
        leaseId,
        builderId: chosen.id,
        builderName: chosen.name,
        arch: chosen.arch,
        isPreview,
        projectId,
        activeBuilds: rt.activeBuilds,
        maxConcurrency: chosen.maxConcurrency,
        sshMuxPinned: true,
        directPushTarget: {
          host: chosen.host,
          port: chosen.sshPort || 22,
          protocol: 'oci-ssh-delta'
        }
      };
    }

    // Cola independiente por builder (nunca bloquea otros nodos — dokploy#3226)
    const queueId = `bqueue_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    rt.queue.push({ queueId, projectId, isPreview, enqueuedAt: new Date().toISOString() });
    return {
      ok: true,
      leased: false,
      queued: true,
      queueId,
      queuePosition: rt.queue.length,
      builderId: chosen.id,
      builderName: chosen.name,
      isPreview,
      projectId,
      activeBuilds: rt.activeBuilds,
      maxConcurrency: chosen.maxConcurrency,
      sshMuxPinned: rt.activeBuilds > 0
    };
  }

  /**
   * Libera un lease de build y despinea el SSH ControlMaster cuando `activeBuilds === 0`.
   * @param {string} leaseId
   */
  releaseBuildSlot(leaseId) {
    const rec = this._leases.get(String(leaseId || ''));
    if (!rec) {
      return { ok: true, released: false, reason: 'LEASE_NOT_FOUND' };
    }
    this._leases.delete(rec.leaseId);
    const rt = this._getRuntimeSlot(rec.builderId);
    rt.leases.delete(rec.leaseId);
    rt.activeBuilds = Math.max(0, rt.activeBuilds - 1);
    const nextQueued = rt.queue.length > 0 ? rt.queue.shift() : null;

    return {
      ok: true,
      released: true,
      leaseId: rec.leaseId,
      builderId: rec.builderId,
      activeBuilds: rt.activeBuilds,
      sshMuxPinned: rt.activeBuilds > 0,
      canRecycleMux: rt.activeBuilds === 0,
      nextQueued
    };
  }

  /**
   * Determina si es seguro reciclar/cerrar el túnel SSH mux de un builder.
   * Bloquea terminantemente el cierre mientras `activeBuilds > 0` (cura `coolify#11372`/`#10853`).
   *
   * @param {string} builderId
   */
  canRecycleMux(builderId) {
    this._ensureLoaded();
    const bid = String(builderId || '').trim();
    const rt = this._getRuntimeSlot(bid);
    if (rt.activeBuilds > 0) {
      return {
        ok: true,
        builderId: bid,
        allowed: false,
        reason: 'ACTIVE_BUILDS_IN_FLIGHT',
        activeBuilds: rt.activeBuilds,
        sshMuxPinned: true
      };
    }
    return {
      ok: true,
      builderId: bid,
      allowed: true,
      reason: 'IDLE',
      activeBuilds: 0,
      sshMuxPinned: false
    };
  }
}

const instance = /** @type {any} */ (new RemoteBuilderService());
instance.RemoteBuilderService = RemoteBuilderService;
instance.buildPruneArgs = buildPruneArgs;
module.exports = instance;
