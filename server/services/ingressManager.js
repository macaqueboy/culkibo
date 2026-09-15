const tls = require('tls');
const dns = require('dns').promises;

const caddyManager = require('./caddyManager');
const domainManager = require('./domainManager');
const projectManager = require('./projectManager');
const localRunner = require('./localRunner');
const containerOrchestrator = require('./containerOrchestrator');

/**
 * Plano de control del ingress: traduce el estado de Culkibo (proyectos +
 * dominios) a rutas de Caddy, y cuenta la verdad sobre lo que realmente se
 * sirve.
 *
 * Por qué existe este módulo y no se llama a caddyManager desde cada endpoint:
 *
 *   1. El estado deseado se deriva de DOS fuentes (proyectos y dominios) y de
 *      lo que el runner tiene vivo de verdad. Derivarlo en un solo sitio es lo
 *      que permite que `reconcile()` sea fiable: si cada endpoint construyera
 *      su propia idea de la ruta, el arranque y el ciclo de vida divergirían.
 *   2. La degradación cuando no hay Caddy tiene que ser idéntica en todos los
 *      caminos. Aquí ninguna función lanza: devuelven `{ applied: false,
 *      reason }` y el daemon sigue sirviendo el panel. Es la misma regla
 *      camaleón que usamos con Docker.
 *
 * Dokploy tiene abierto el fallo #4057 por exactamente lo contrario: tras un
 * reinicio sucio el estado real deja de coincidir con el modelo y nadie avisa.
 * Por eso `bootstrap()` reconcilia en cada arranque y `status()` publica la
 * deriva en vez de esconderla.
 */

const FORGE_PORT = 3001;
const CITADEL_PORT = 8080;

/** Tope de sondeos TLS por consulta: el panel no puede colgarse por 200 dominios. */
const MAX_TLS_PROBES = 24;

class IngressManager {
  constructor() {
    this.daemonPort = Number(process.env.PORT) || 3030;
    this.httpPort = Number(process.env.CULKIBO_INGRESS_HTTP_PORT) || 80;
    this.httpsPort = Number(process.env.CULKIBO_INGRESS_HTTPS_PORT) || 443;
    this.lastReconcile = null;
    this.bootstrapped = false;
    /** @ids que este proceso sabe publicados en Caddy. Ver `mayHaveRoute()`. */
    this.publishedIds = new Set();
    /** Marca temporal de la última comprobación del servidor en Caddy. */
    this.serverReadyAt = 0;
    this.serverReadyTtlMs = 15000;
  }

  /**
   * ¿Tiene sentido preguntarle a Caddy por este proyecto?
   *
   * Si no hay ningún dominio vinculado y este proceso no ha publicado nunca una
   * ruta suya, no hay nada que consultar. Importa porque arrancar, parar y
   * borrar proyectos son las operaciones más frecuentes del panel y la inmensa
   * mayoría de los proyectos no tienen dominio: sin este corte, cada una pagaba
   * dos o tres idas y vueltas a la admin API y la latencia media del daemon se
   * multiplicaba por cinco. Lo que este atajo pudiera dejar atrás lo arregla la
   * reconciliación de arranque.
   */
  mayHaveRoute(projectId) {
    if (this.publishedIds.has(caddyManager.routeId(projectId))) return true;
    const project = projectManager.getById(projectId);
    const hostnames = project && Array.isArray(project.domains) ? project.domains : [];
    return (domainManager.domains || []).some(d => d.projectId === projectId || hostnames.includes(d.hostname));
  }

  /**
   * Endpoint que Caddy consulta antes de emitir un certificado.
   *
   * Es configurable porque Caddy puede estar en un contenedor, donde
   * `127.0.0.1` es el propio contenedor y no el daemon. En ese caso hay que
   * apuntar a `host.docker.internal` o a la IP del host.
   */
  askEndpoint() {
    return process.env.CULKIBO_ASK_ENDPOINT || `http://127.0.0.1:${this.daemonPort}/api/ingress/ask`;
  }

  // ---------------------------------------------------------------------
  // Estado deseado
  // ---------------------------------------------------------------------

  /** El proyecto al que pertenece un dominio, o null si no está vinculado. */
  projectForDomain(domain, projects) {
    if (domain.projectId) {
      const byId = projects.find(p => p.id === domain.projectId);
      if (byId) return byId;
    }
    // Modelo anterior: `Project.domains` es una lista de hostnames. Se sigue
    // respetando para no romper los proyectos ya guardados.
    return projects.find(p => Array.isArray(p.domains) && p.domains.includes(domain.hostname)) || null;
  }

  /**
   * Destino real de un proyecto, o null si no hay ninguno.
   *
   * La fuente de verdad es el runner, no el JSON: el registro puede seguir
   * diciendo `localRunning: true` después de que el proceso haya muerto, y
   * publicar una ruta hacia un puerto muerto es justo el tipo de mentira que
   * este trabajo elimina.
   */
  upstreamForProject(project) {
    if (!project) return null;
    const livePort = localRunner.isRunning(project.id) ? localRunner.getPort(project.id) : null;
    const port = livePort || (project.localRunning ? project.localPort : null);
    if (!port) return null;
    return `127.0.0.1:${port}`;
  }

  /**
   * Ruta de un dominio que no pertenece a ningún proyecto: va directo al pod
   * que el usuario configuró.
   *
   * Cuando el tráfico está repartido entre Forge y Citadel, el reparto lo
   * ejecuta Caddy con `weighted_round_robin`. Antes lo hacía un `Math.random()`
   * dentro de Express que no repartía nada, porque ninguna petición llegaba a
   * salir de Node.
   */
  podRouteFor(domain, traffic) {
    const port = Number(domain.targetPort) || (domain.targetPod === 'citadel' ? CITADEL_PORT : FORGE_PORT);
    const isPodPort = port === FORGE_PORT || port === CITADEL_PORT;

    if (isPodPort && traffic.forge > 0 && traffic.citadel > 0) {
      return {
        projectId: domain.id,
        hostnames: [domain.hostname],
        upstreams: [`127.0.0.1:${FORGE_PORT}`, `127.0.0.1:${CITADEL_PORT}`],
        weights: [traffic.forge, traffic.citadel],
        kind: 'pod',
        label: `Reparto ${traffic.forge}/${traffic.citadel} entre Desarrollo y Producción`
      };
    }

    return {
      projectId: domain.id,
      hostnames: [domain.hostname],
      upstreams: [`127.0.0.1:${port}`],
      kind: 'pod',
      label: domain.targetPod === 'citadel' ? 'Producción' : 'Desarrollo'
    };
  }

  /**
   * Las rutas que deberían existir ahora mismo, y los dominios que se quedan
   * fuera con el motivo. Lo segundo importa tanto como lo primero: un dominio
   * sin ruta tiene que poder explicarse en el panel.
   */
  buildDesiredState() {
    const projects = projectManager.getAll();
    const domains = domainManager.domains || [];
    const traffic = containerOrchestrator.trafficAllocation || { forge: 0, citadel: 100 };

    const specs = [];
    const skipped = [];
    const grouped = new Map();

    for (const domain of domains) {
      if (domain.status === 'disabled') {
        skipped.push({ hostnames: [domain.hostname], reason: 'El dominio está deshabilitado' });
        continue;
      }

      const project = this.projectForDomain(domain, projects);
      if (project) {
        if (!grouped.has(project.id)) grouped.set(project.id, { project, domains: [] });
        grouped.get(project.id).domains.push(domain);
        continue;
      }

      specs.push(this.podRouteFor(domain, traffic));
    }

    // Una sola ruta por proyecto, con todos sus hostnames: así el @id del
    // proyecto es la unidad de alta y de baja, y no quedan restos sueltos.
    for (const entry of grouped.values()) {
      const project = entry.project;
      const upstream = this.upstreamForProject(project);
      if (!upstream) {
        skipped.push({
          hostnames: entry.domains.map(d => d.hostname),
          projectId: project.id,
          reason: `El proyecto «${project.name}» no está en ejecución: no hay ningún destino real al que enrutar`
        });
        continue;
      }
      specs.push({
        projectId: project.id,
        hostnames: entry.domains.map(d => d.hostname),
        upstreams: [upstream],
        kind: 'project',
        label: project.name
      });
    }

    return { specs, skipped };
  }

  // ---------------------------------------------------------------------
  // Aplicación
  // ---------------------------------------------------------------------

  /**
   * Asegura que existe el servidor `culkibo` dentro de Caddy, y que su lista de
   * rutas está presente.
   *
   * Dos detalles que solo se descubren probando contra un Caddy real:
   *
   *  1. `routes` lleva `omitempty`, así que cuando la lista está VACÍA el campo
   *     desaparece del objeto padre. Deducir «no hay servidor» de «no viene
   *     routes» hacía que la primera alta después de quedarse sin rutas se
   *     rechazara en silencio. La existencia se comprueba sobre el objeto, y la
   *     lista se repone si falta.
   *  2. `POST /load` reemplaza la configuración ENTERA. Sobre un Caddy que ya
   *     sirve otras cosas, eso borraría el trabajo de otro. Solo se usa cuando
   *     Caddy está vacío; si ya tiene aplicaciones, se AÑADE nuestro servidor
   *     con un PUT sobre su propia clave y no se toca nada más.
   */
  async ensureServer() {
    // Comprobación cacheada: el servidor no aparece y desaparece entre dos
    // escrituras seguidas, y preguntarlo cada vez duplicaba el tráfico contra
    // la admin API.
    if (Date.now() - this.serverReadyAt < this.serverReadyTtlMs) {
      return { ready: true, created: false, cached: true };
    }

    // Sin `.catch()`: `get()` ya devuelve null para un 404, así que atrapar
    // aquí convertiría un fallo transitorio de red en la conclusión «Caddy
    // tiene otra configuración», que es falsa y lleva a escribir de más. Que
    // suba el error y que `guard()` lo cuente como lo que es.
    const server = await caddyManager.get('/config/apps/http/servers/culkibo');
    if (server && typeof server === 'object' && !Array.isArray(server)) {
      if (!Array.isArray(server.routes)) {
        // PUT crea la clave; si otro proceso la ha creado entretanto, el error
        // es inofensivo y la siguiente escritura funciona igual.
        await caddyManager.write('PUT', '/config/apps/http/servers/culkibo/routes', []).catch(() => {});
      }
      this.serverReadyAt = Date.now();
      return { ready: true, created: false };
    }

    const full = await caddyManager.get('/config/');
    const hasApps = Boolean(full && full.apps && Object.keys(full.apps).length > 0);
    const base = caddyManager.buildBaseConfig({
      askEndpoint: this.askEndpoint(),
      httpPort: this.httpPort,
      httpsPort: this.httpsPort
    });

    if (!hasApps) {
      await caddyManager.loadBaseConfig({
        askEndpoint: this.askEndpoint(),
        httpPort: this.httpPort,
        httpsPort: this.httpsPort
      });
      this.serverReadyAt = Date.now();
      return { ready: true, created: true, mode: 'base' };
    }

    await caddyManager.write('PUT', '/config/apps/http/servers/culkibo', base.apps.http.servers.culkibo);

    // La política de TLS bajo demanda solo se instala si Caddy no tiene ya la
    // suya. Pisarla sería decidir por el usuario cómo emite certificados.
    let note = null;
    if (!full.apps.tls) {
      await caddyManager.write('PUT', '/config/apps/tls', base.apps.tls);
    } else {
      note = 'Caddy ya tenía configuración de TLS propia: Culkibo no la ha tocado, así que la emisión de certificados bajo demanda depende de ella.';
      this.log('WARN', note);
    }
    this.serverReadyAt = Date.now();
    return { ready: true, created: true, mode: 'merge', note };
  }

  /**
   * Envoltorio común: detecta, prepara el servidor y ejecuta. Nunca lanza.
   *
   * Que no lance es el contrato: sin Caddy, arrancar o parar un proyecto tiene
   * que seguir funcionando y limitarse a decir que no hay ingress.
   */
  async guard(fn) {
    const detection = await caddyManager.detect();
    if (!detection.available) {
      return {
        applied: false,
        available: false,
        reason: detection.reason,
        message: `Ingress no disponible: ${detection.reason}`
      };
    }

    try {
      const ready = await this.ensureServer();
      if (!ready.ready) {
        return { applied: false, available: true, reason: ready.reason, message: ready.reason };
      }
      const out = await fn();
      return { available: true, ...out };
    } catch (err) {
      const message = `No se pudo aplicar la configuración de ingress: ${err.message}`;
      this.log('ERROR', message);
      return { applied: false, available: true, error: err.message, message };
    }
  }

  log(level, message) {
    try {
      containerOrchestrator.addLog(level, 'edge', `[Edge:Ingress] ${message}`);
    } catch (e) {}
  }

  /**
   * Respuesta para cuando no hay nada que hacer en el plano de datos.
   *
   * `checked: false` es deliberado: no se ha hablado con Caddy, así que esta
   * respuesta no afirma nada sobre si está disponible.
   */
  nothingToDo(projectId, reason) {
    return {
      applied: true,
      action: 'noop',
      skipped: true,
      checked: false,
      routeId: caddyManager.routeId(projectId),
      reason,
      message: reason
    };
  }

  /** Da de alta o refresca la ruta de un proyecto; la retira si ya no procede. */
  async syncProject(projectId) {
    if (!this.mayHaveRoute(projectId)) {
      return this.nothingToDo(projectId, 'El proyecto no tiene ningún dominio vinculado');
    }

    return this.guard(async () => {
      const state = this.buildDesiredState();
      const spec = state.specs.find(s => s.kind === 'project' && s.projectId === projectId);

      if (!spec) {
        const removal = await caddyManager.removeRoute(projectId);
        this.publishedIds.delete(removal.id);
        const match = state.skipped.find(s => s.projectId === projectId);
        const reason = match ? match.reason : 'El proyecto no tiene ningún dominio vinculado';
        if (removal.removed) this.log('INFO', `Ruta retirada de ${projectId}: ${reason}`);
        return { applied: true, action: removal.removed ? 'removed' : 'noop', routeId: removal.id, reason };
      }

      const result = await caddyManager.upsertRoute(spec);
      this.publishedIds.add(result.id);
      this.log('SUCCESS', `${result.created ? 'Alta' : 'Actualización'} de ${spec.hostnames.join(', ')} → ${spec.upstreams.join(', ')}`);
      return {
        applied: true,
        action: result.created ? 'created' : 'updated',
        routeId: result.id,
        hostnames: spec.hostnames,
        upstreams: spec.upstreams
      };
    });
  }

  /** Retira la ruta de un proyecto. Idempotente. */
  async removeProject(projectId) {
    if (!this.mayHaveRoute(projectId)) {
      return this.nothingToDo(projectId, 'No había ninguna ruta publicada para este proyecto');
    }

    return this.guard(async () => {
      const removal = await caddyManager.removeRoute(projectId);
      this.publishedIds.delete(removal.id);
      if (removal.removed) this.log('INFO', `Ruta retirada de ${projectId}`);
      return { applied: true, action: removal.removed ? 'removed' : 'noop', routeId: removal.id };
    });
  }

  /** Retira la ruta de un dominio suelto (los que no pertenecen a un proyecto). */
  async removeDomain(domainId) {
    return this.removeProject(domainId);
  }

  /**
   * Converge Caddy al estado deseado completo: aplica lo que falta y retira lo
   * que sobra de entre nuestras rutas. Las ajenas no se tocan: caddyManager las
   * distingue por el prefijo del @id.
   */
  async reconcile() {
    return this.guard(async () => {
      const state = this.buildDesiredState();
      const result = await caddyManager.reconcile(state.specs);
      this.publishedIds = new Set(result.applied);
      this.lastReconcile = {
        at: new Date().toISOString(),
        applied: result.applied.length,
        removed: result.removed.length,
        skipped: state.skipped.length
      };
      this.log('INFO', `Reconciliación: ${result.applied.length} ruta(s) aplicadas, ${result.removed.length} retirada(s), ${state.skipped.length} dominio(s) sin destino`);
      return { applied: true, routes: result.applied, removed: result.removed, skipped: state.skipped };
    });
  }

  /**
   * Reconciliación de arranque.
   *
   * Es el punto que impide la deriva silenciosa tras un reinicio: Caddy puede
   * haber perdido su configuración, o haber sido editado por fuera, y sin esto
   * nuestra idea del mundo y la suya se separan sin que nadie lo note.
   */
  async bootstrap({ port } = {}) {
    if (port) this.daemonPort = Number(port);

    const detection = await caddyManager.detect({ force: true });
    if (!detection.available) {
      const message = `Sin plano de datos: ${detection.reason}. Culkibo funciona igual, pero ningún dominio se sirve desde aquí hasta que haya un Caddy accesible.`;
      console.warn(`[Edge:Ingress] ${message}`);
      this.log('WARN', message);
      return { available: false, applied: false, reason: detection.reason, message };
    }

    const result = await this.reconcile();
    this.bootstrapped = Boolean(result.applied);
    if (result.applied) {
      console.log(`[Edge:Ingress] Caddy reconciliado: ${result.routes.length} ruta(s) activas en ${detection.adminUrl}`);
    } else {
      console.warn(`[Edge:Ingress] ${result.message || result.reason}`);
    }
    return result;
  }

  // ---------------------------------------------------------------------
  // Verdad sobre lo que se sirve
  // ---------------------------------------------------------------------

  /**
   * Handshake TLS real contra el dominio, para leer el certificado que se está
   * sirviendo de verdad.
   *
   * El registro de certificados de Culkibo se inventaba `status: 'active'` y
   * una caducidad a 90 días en el momento de "emitir". Un campo en nuestro
   * propio JSON no demuestra nada sobre lo que recibe un navegador: lo único
   * que lo demuestra es abrir la conexión y mirar el certificado.
   *
   * `rejectUnauthorized: false` es deliberado: queremos poder INFORMAR de un
   * certificado caducado, autofirmado o emitido para otro nombre. Rechazarlo
   * nos dejaría sin el dato justo cuando más falta hace. La validez real se
   * reporta aparte, en `trusted`/`trustError`.
   */
  /**
   * Resolución con c-ares (`resolve4`/`resolve6`), no con `dns.lookup`.
   *
   * No es un detalle: `dns.lookup` —el que usa `tls.connect` por defecto— llama
   * a `getaddrinfo` en el pool de hilos de libuv, que tiene CUATRO. Una consulta
   * lenta no se puede cancelar aunque cerremos el socket, así que unos pocos
   * dominios que no resuelven dejan el pool ocupado y bloquean al resto del
   * proceso: en las pruebas, sondear tres dominios dejaba sin hilos a la propia
   * llamada a la admin API de Caddy, que caducaba a los 5 s y hacía parecer que
   * no había ninguna ruta publicada. c-ares hace E/S asíncrona de verdad.
   */
  async resolveAddress(hostname, timeoutMs) {
    const attempt = async (fn) => {
      const list = await fn(hostname);
      return Array.isArray(list) && list.length ? list[0] : null;
    };
    const race = (p) => Promise.race([
      p,
      new Promise((_, reject) => {
        const t = setTimeout(() => reject(new Error('Tiempo de espera agotado en la resolución DNS')), timeoutMs);
        if (t.unref) t.unref();
      })
    ]);

    try {
      return { address: await race(attempt(dns.resolve4)), family: 4 };
    } catch (e4) {
      try {
        return { address: await race(attempt(dns.resolve6)), family: 6 };
      } catch (e6) {
        return { address: null, error: `El dominio no resuelve en DNS (${e4.code || e4.message})` };
      }
    }
  }

  async probeTls(hostname, { timeoutMs = 3000, port = 443 } = {}) {
    const raw = String(hostname || '').trim().toLowerCase();
    const target = raw.replace(/^\*\./, '');
    const base = { hostname: raw, probed: target, wildcard: raw.startsWith('*.') };

    if (!target) return { ...base, reachable: false, error: 'Hostname vacío' };

    const startedResolve = Date.now();
    const resolved = await this.resolveAddress(target, timeoutMs);
    if (!resolved.address) {
      return { ...base, handshakeMs: Date.now() - startedResolve, reachable: false, error: resolved.error };
    }

    return new Promise((resolve) => {
      const startedAt = Date.now();
      let socket = null;
      let settled = false;

      const finish = (value) => {
        if (settled) return;
        settled = true;
        try { if (socket) socket.destroy(); } catch (e) {}
        resolve({ ...base, address: resolved.address, handshakeMs: Date.now() - startedAt, ...value });
      };

      try {
        socket = tls.connect({
          // Se conecta a la IP ya resuelta y se envía el nombre por SNI: así el
          // socket no vuelve a pasar por `dns.lookup`.
          host: resolved.address,
          port,
          servername: target,
          rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1']
        }, () => {
          const cert = socket.getPeerCertificate(false) || {};
          if (!cert.valid_to) {
            return finish({ reachable: true, error: 'El servidor no presentó ningún certificado' });
          }
          const notAfter = new Date(cert.valid_to);
          const notBefore = new Date(cert.valid_from);
          const hasNotAfter = !Number.isNaN(notAfter.getTime());
          finish({
            reachable: true,
            issuer: (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null,
            issuerCN: (cert.issuer && cert.issuer.CN) || null,
            subject: (cert.subject && cert.subject.CN) || null,
            sans: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, '')) : [],
            notBefore: Number.isNaN(notBefore.getTime()) ? null : notBefore.toISOString(),
            notAfter: hasNotAfter ? notAfter.toISOString() : null,
            daysRemaining: hasNotAfter ? Math.floor((notAfter.getTime() - Date.now()) / 86400000) : null,
            expired: hasNotAfter ? notAfter.getTime() <= Date.now() : null,
            trusted: socket.authorized === true,
            trustError: socket.authorized ? null : (socket.authorizationError ? String(socket.authorizationError) : null),
            protocol: typeof socket.getProtocol === 'function' ? socket.getProtocol() : null,
            alpn: socket.alpnProtocol || null
          });
        });

        socket.setTimeout(timeoutMs, () => finish({ reachable: false, error: `Sin respuesta TLS en ${timeoutMs} ms` }));
        socket.on('error', (err) => finish({ reachable: false, error: err.message }));
      } catch (err) {
        finish({ reachable: false, error: err.message });
      }
    });
  }

  /**
   * Estado honesto del ingress: qué hay realmente en Caddy, en qué difiere de
   * lo que Culkibo cree, y qué certificado sirve de verdad cada dominio.
   */
  async status({ probe = true, force = false, probeTimeoutMs = 3000 } = {}) {
    const detection = await caddyManager.detect({ force });
    const state = this.buildDesiredState();
    const desiredIds = state.specs.map(s => caddyManager.routeId(s.projectId));

    let liveRoutes = [];
    let routesError = null;
    if (detection.available) {
      try {
        liveRoutes = await caddyManager.listRoutes();
      } catch (err) {
        routesError = err.message;
      }
    }

    const liveIds = liveRoutes.map(r => r['@id']);
    // Consultar el estado real es la ocasión más barata de corregir lo que este
    // proceso cree tener publicado.
    if (detection.available && !routesError) this.publishedIds = new Set(liveIds);
    const drift = {
      missing: desiredIds.filter(id => !liveIds.includes(id)),
      unexpected: liveIds.filter(id => !desiredIds.includes(id))
    };

    const hostnames = Array.from(new Set((domainManager.domains || []).map(d => d.hostname))).slice(0, MAX_TLS_PROBES);
    const tlsProbes = probe && hostnames.length
      ? await Promise.all(hostnames.map(h => this.probeTls(h, { timeoutMs: probeTimeoutMs })))
      : [];

    return {
      dataPlane: 'caddy',
      available: detection.available,
      adminUrl: detection.adminUrl,
      version: detection.version,
      reason: detection.reason,
      message: detection.available
        ? 'Caddy responde en su API de administración. El tráfico de los dominios lo sirve Caddy, no el daemon.'
        : `Ingress no disponible: ${detection.reason}. Culkibo sigue funcionando, pero ningún dominio se sirve desde aquí.`,
      routesManaged: liveRoutes.length,
      routesError,
      routes: liveRoutes.map(r => ({
        id: r['@id'],
        hosts: (r.match && r.match[0] && r.match[0].host) || [],
        upstreams: ((r.handle && r.handle[0] && r.handle[0].upstreams) || []).map(u => u.dial),
        weights: (r.handle && r.handle[0] && r.handle[0].load_balancing
          && r.handle[0].load_balancing.selection_policy
          && r.handle[0].load_balancing.selection_policy.weights) || null
      })),
      desired: state.specs.map(s => ({
        id: caddyManager.routeId(s.projectId),
        kind: s.kind,
        label: s.label,
        hosts: s.hostnames,
        upstreams: s.upstreams,
        weights: s.weights || null
      })),
      skipped: state.skipped,
      drift,
      inSync: detection.available && drift.missing.length === 0 && drift.unexpected.length === 0,
      lastReconcile: this.lastReconcile,
      tlsProbed: Boolean(probe),
      tls: tlsProbes,
      checkedAt: new Date().toISOString()
    };
  }
}

module.exports = new IngressManager();
module.exports.IngressManager = IngressManager;
