const fs = require('fs');
const path = require('path');

const caddyManager = require('./caddyManager');
const domainManager = require('./domainManager');
const projectManager = require('./projectManager');
const containerOrchestrator = require('./containerOrchestrator');
const { isPrivateIp, isMetadataIp, atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

const INGRESS_CONFIG_FILE = path.join(__dirname, '..', '..', 'data', 'ingress.json');
const DEPLOYMENTS_FILE = path.join(__dirname, '..', '..', 'data', 'deployments.json');

/** Carga perezosa de módulos pesados de red/TLS/despliegue (ahorra ~2.5-3 MB RSS en arranque). */
/** @type {typeof import('tls') | null} */
let _tlsMod = null;
function getTls() {
  if (!_tlsMod) _tlsMod = require('tls');
  return _tlsMod;
}
/** @type {typeof import('dns').promises | null} */
let _dnsMod = null;
function getDns() {
  if (!_dnsMod) _dnsMod = require('dns').promises;
  return _dnsMod;
}
/** @type {typeof import('net') | null} */
let _netMod = null;
function getNet() {
  if (!_netMod) _netMod = require('net');
  return _netMod;
}
/** @type {any} */
let _sslManager = null;
function getSslManager() {
  if (!_sslManager) _sslManager = require('./sslManager');
  return _sslManager;
}
/** @type {any} */
let _deployManager = null;
function getDeployManager() {
  if (!_deployManager) {
    // Evitar arrastrar deployManager (93 KB + repoSync) si nunca hubo despliegues en disco ni está cargado en memoria
    const resolved = require.resolve('./deployManager');
    if (!require.cache[resolved] && !fs.existsSync(DEPLOYMENTS_FILE)) return null;
    try { _deployManager = require('./deployManager'); } catch (e) {}
  }
  return _deployManager;
}

/** Traduce códigos crudos de OpenSSL/Node a explicaciones claras en castellano. */
function humanizeTlsError(errMsg) {
  const s = String(errMsg || '');
  if (/ENOTFOUND|EAI_AGAIN/i.test(s)) return 'El dominio aún no resuelve en DNS. Crea o revisa el registro A.';
  if (/ECONNREFUSED/i.test(s)) return 'El puerto 443 no responde. Comprueba que Caddy esté activo y el cortafuegos abierto.';
  if (/ETIMEDOUT|Tiempo de espera|Sin respuesta TLS/i.test(s)) return 'Tiempo de espera agotado al conectar por HTTPS (puerto 443 bloqueado o IP incorrecta).';
  if (/ERR_TLS_CERT_ALTNAME_INVALID|altnames/i.test(s)) return 'El certificado servido pertenece a otro dominio.';
  if (/CERT_HAS_EXPIRED/i.test(s)) return 'El certificado HTTPS ha caducado.';
  if (/SELF_SIGNED|DEPTH_ZERO_SELF_SIGNED/i.test(s)) return 'Certificado autofirmado (no emitido por una autoridad de confianza).';
  if (/tlsv1 alert internal error|handshake failure/i.test(s)) return 'Caddy todavía no ha podido emitir el certificado (revisa que DNS y puertos 80/443 sean públicos).';
  return s || 'Error desconocido al comprobar HTTPS';
}

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
  /**
   * @param {{
   *   dataDir?: string | null,
   *   configFile?: string | null,
   *   caddyManager?: any,
   *   domainManager?: any,
   *   sslManager?: any,
   *   cloudflareService?: any,
   *   notificationService?: any
   * }} [opts]
   */
  constructor(opts = {}) {
    this.configFile = opts.configFile
      ? path.resolve(opts.configFile)
      : (opts.dataDir
          ? path.join(path.resolve(opts.dataDir), 'ingress.json')
          : (process.env.CULKIBO_DATA_DIR
              ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data', 'ingress.json')
              : INGRESS_CONFIG_FILE));
    this._caddy = opts.caddyManager || caddyManager;
    this._domains = opts.domainManager || domainManager;
    this._customSsl = opts.sslManager || null;
    this._customCf = opts.cloudflareService || null;
    this._customNotifier = opts.notificationService || null;

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
    /** Caché de sondeos TLS de 30 s por hostname para evitar bloquear el panel. */
    this._tlsCache = new Map();
    /** Estado persistido en `data/ingress.json`: panelDomain, wildcardPolicies, acmeEmail, tunnelConfig. */
    const persisted = this._loadConfig();
    this.panelDomain = persisted.panelDomain;
    /** @type {Array<{ rootDomain: string, provider: string, tokenEnv?: string | null, credentialsEnv?: Record<string, string> | null, includeApex: boolean, enabled: boolean, createdAt: string }>} */
    this.wildcardPolicies = persisted.wildcardPolicies;
    /** @type {string | null} */
    this.acmeEmail = persisted.acmeEmail;
    /** @type {{ enabled: boolean, tunnelId: string | null, mode: 'per_hostname' | 'all_to_caddy', containerName: string, caddyUpstream: string, lastSyncedAt: string | null }} */
    this.tunnelConfig = persisted.tunnelConfig;
    /** @type {Map<string, { hostname: string, upstream: string, projectId: string, prNumber: number }>} */
    this.previewRoutes = new Map();
    /** @type {any} */
    this.lastTlsAudit = null;
    /** Deduplicación 24h por clave (`hostname:kind`) para alertas TLS. */
    /** @type {Map<string, number>} */
    this._tlsAlertSentAt = new Map();
    /** Marca si el Caddy externo traía su propia apps.tls ajena a Culkibo. */
    this._hasForeignTls = false;
  }

  _getSsl() {
    return this._customSsl || getSslManager();
  }

  _getCloudflare() {
    if (this._customCf) return this._customCf;
    return require('./cloudflareService');
  }

  _loadConfig() {
    /** @type {{ panelDomain: string | null, wildcardPolicies: any[], acmeEmail: string | null, tunnelConfig: { enabled: boolean, tunnelId: string | null, mode: 'per_hostname' | 'all_to_caddy', containerName: string, caddyUpstream: string, lastSyncedAt: string | null } }} */
    const out = {
      panelDomain: process.env.CULKIBO_PANEL_DOMAIN ? String(process.env.CULKIBO_PANEL_DOMAIN).trim().toLowerCase() : null,
      wildcardPolicies: [],
      acmeEmail: process.env.CULKIBO_ACME_EMAIL ? String(process.env.CULKIBO_ACME_EMAIL).trim().toLowerCase() : null,
      tunnelConfig: {
        enabled: false,
        tunnelId: null,
        mode: 'per_hostname',
        containerName: 'culkibo-cloudflared',
        caddyUpstream: 'http://127.0.0.1:80',
        lastSyncedAt: null
      }
    };
    const loaded = loadJsonWithBackupSync(this.configFile, {
      validate: (parsed) => Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed))
    });
    if (loaded.corrupt) {
      this._corruptReadOnly = true;
      console.error(`[IngressManager] ${this.configFile} corrupto; archivado en ${loaded.quarantinePath}. Guardado bloqueado para evitar pérdida.`);
      return out;
    }
    if (loaded.ok && loaded.data) {
      const cfg = loaded.data;
      if (typeof cfg.panelDomain === 'string' && cfg.panelDomain.trim()) {
        out.panelDomain = cfg.panelDomain.trim().toLowerCase();
      }
      if (Array.isArray(cfg.wildcardPolicies)) {
        out.wildcardPolicies = cfg.wildcardPolicies.filter((p) => p && typeof p.rootDomain === 'string' && p.rootDomain.trim());
      }
      if (typeof cfg.acmeEmail === 'string' && cfg.acmeEmail.trim()) {
        out.acmeEmail = cfg.acmeEmail.trim().toLowerCase();
      }
      if (cfg.tunnelConfig && typeof cfg.tunnelConfig === 'object' && !Array.isArray(cfg.tunnelConfig)) {
        out.tunnelConfig = {
          enabled: Boolean(cfg.tunnelConfig.enabled),
          tunnelId: typeof cfg.tunnelConfig.tunnelId === 'string' && cfg.tunnelConfig.tunnelId.trim() ? cfg.tunnelConfig.tunnelId.trim() : null,
          mode: cfg.tunnelConfig.mode === 'all_to_caddy' ? 'all_to_caddy' : 'per_hostname',
          containerName: typeof cfg.tunnelConfig.containerName === 'string' && cfg.tunnelConfig.containerName.trim() ? cfg.tunnelConfig.containerName.trim() : 'culkibo-cloudflared',
          caddyUpstream: typeof cfg.tunnelConfig.caddyUpstream === 'string' && cfg.tunnelConfig.caddyUpstream.trim() ? cfg.tunnelConfig.caddyUpstream.trim() : 'http://127.0.0.1:80',
          lastSyncedAt: typeof cfg.tunnelConfig.lastSyncedAt === 'string' ? cfg.tunnelConfig.lastSyncedAt : null
        };
      }
    }
    return out;
  }

  _saveConfig() {
    if (this._corruptReadOnly) return;
    try {
      atomicWriteJsonSync(this.configFile, {
        panelDomain: this.panelDomain,
        wildcardPolicies: this.wildcardPolicies,
        acmeEmail: this.acmeEmail,
        tunnelConfig: this.tunnelConfig,
        updatedAt: new Date().toISOString()
      }, { mode: 0o600, backup: true });
    } catch (e) {
      console.warn('[IngressManager] No se pudo persistir ingress.json:', e.message);
    }
  }

  /** Persiste el dominio propio del panel en `data/ingress.json` para sobrevivir reinicios (P1-18). */
  setPanelDomain(hostname) {
    const clean = hostname ? String(hostname).trim().toLowerCase() : null;
    this.panelDomain = clean || null;
    this._saveConfig();
    return this.panelDomain;
  }

  /** Configura opcionalmente el correo de contacto ACME (Let's Encrypt / ZeroSSL). */
  setAcmeEmail(email) {
    const clean = email ? String(email).trim().toLowerCase() : null;
    if (clean && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      throw new Error('Correo electrónico ACME inválido');
    }
    this.acmeEmail = clean || null;
    this._saveConfig();
    return this.acmeEmail;
  }

  listWildcardPolicies() {
    return this.wildcardPolicies.map((p) => ({ ...p }));
  }

  listSupportedDnsProviders() {
    return typeof this._caddy.listDnsProviders === 'function'
      ? this._caddy.listDnsProviders()
      : caddyManager.listDnsProviders();
  }

  /**
   * Añade o actualiza una política Wildcard DNS-01 persistida multiproveedor
   * (Cloudflare, Hetzner v2, DigitalOcean, Route53, Porkbun, Bunny, DuckDNS).
   *
   * @param {string} rootDomain
   * @param {{
   *   provider?: string,
   *   tokenEnv?: string | null,
   *   credentialsEnv?: Record<string, string> | null,
   *   includeApex?: boolean
   * }} [opts]
   */
  async addWildcardPolicy(rootDomain, { provider = 'cloudflare', tokenEnv = null, credentialsEnv = null, includeApex = true } = {}) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!cleanRoot || !/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(cleanRoot)) {
      throw new Error(`Dominio raíz inválido para wildcard DNS-01: ${rootDomain}`);
    }
    const cleanProvider = String(provider || 'cloudflare').trim().toLowerCase();
    // Validar estrictamente proveedor y nombres de variables de entorno antes de persistir
    const { schema, resolvedEnvMap } = caddyManager.buildDnsProviderConfig(cleanProvider, {
      tokenEnv,
      credentialsEnv
    });
    const primaryEnv = resolvedEnvMap[schema.primaryField] || null;
    const entry = {
      rootDomain: cleanRoot,
      provider: cleanProvider,
      tokenEnv: primaryEnv,
      credentialsEnv: resolvedEnvMap,
      includeApex: includeApex !== false,
      enabled: true,
      createdAt: new Date().toISOString()
    };
    this.wildcardPolicies = [
      entry,
      ...this.wildcardPolicies.filter((p) => p.rootDomain !== cleanRoot)
    ];
    this._saveConfig();

    const applied = await this.guard(async () => {
      const tlsRes = await this.reconcileTlsOnly();
      return { ...tlsRes, applied: Boolean(tlsRes.applied) };
    });
    return {
      policy: entry,
      policies: this.listWildcardPolicies(),
      subjects: entry.includeApex ? [`*.${cleanRoot}`, cleanRoot] : [`*.${cleanRoot}`],
      provider: entry.provider,
      caddyModule: schema.caddyModule,
      tokenEnv: entry.tokenEnv,
      credentialsEnv: entry.credentialsEnv,
      ...applied
    };
  }

  async removeWildcardPolicy(rootDomain) {
    const cleanRoot = String(rootDomain || '').trim().toLowerCase().replace(/^\*\./, '');
    const before = this.wildcardPolicies.length;
    this.wildcardPolicies = this.wildcardPolicies.filter((p) => p.rootDomain !== cleanRoot);
    if (this.wildcardPolicies.length !== before) {
      this._saveConfig();
    }
    const applied = await this.guard(async () => {
      const tlsRes = await this.reconcileTlsOnly();
      return { ...tlsRes, applied: Boolean(tlsRes.applied) };
    });
    return { removed: this.wildcardPolicies.length !== before, rootDomain: cleanRoot, policies: this.listWildcardPolicies(), ...applied };
  }

  _buildTlsOptions() {
    const sslManager = this._getSsl();
    const containerMountPrefix = this._caddy.isContainerized ? '/etc/culkibo-certs' : null;
    const customCertFiles = sslManager.listCaddyLoadFiles({ containerMountPrefix });

    // Si el usuario guardó un token real en Cloudflare Settings pero CF_API_TOKEN no está en process.env,
    // pasarlo solo en memoria a políticas Cloudflare DNS-01 (jamás se persiste en ingress.json).
    /** @type {string | null} */
    let runtimeCfToken = null;
    if (!process.env.CF_API_TOKEN && !process.env.CLOUDFLARE_API_TOKEN) {
      try {
        const cf = this._getCloudflare();
        const st = cf.getConfigStatus();
        if (!st.useMock && cf.config && cf.config.apiToken) {
          runtimeCfToken = String(cf.config.apiToken);
        }
      } catch (e) {}
    }
    const effectivePolicies = (this.wildcardPolicies || []).map((wp) => {
      const prov = String(wp.provider || 'cloudflare').toLowerCase();
      if (prov === 'cloudflare' && runtimeCfToken && (!wp.tokenEnv || wp.tokenEnv === 'CF_API_TOKEN')) {
        return { ...wp, apiToken: runtimeCfToken };
      }
      return wp;
    });

    return {
      askEndpoint: this.askEndpoint(),
      wildcardPolicies: effectivePolicies,
      acmeEmail: this.acmeEmail,
      customCertFiles
    };
  }

  async reconcileTlsOnly() {
    return this._caddy.reconcileTls(this._buildTlsOptions());
  }

  // ---------------------------------------------------------------------
  // Orquestación de Túnel Cloudflare (CGNAT / Zero-Open-Ports)
  // ---------------------------------------------------------------------

  /**
   * Configura y persiste el modo de publicación por Cloudflare Tunnel (`cloudflared`)
   * en `ingress.json` (sin guardar nunca el `tunnelToken`).
   *
   * @param {{
   *   enabled?: boolean,
   *   tunnelId?: string | null,
   *   mode?: 'per_hostname' | 'all_to_caddy',
   *   containerName?: string,
   *   caddyUpstream?: string
   * }} opts
   */
  configureCloudflareTunnel({ enabled, tunnelId, mode, containerName, caddyUpstream } = {}) {
    const cf = this._getCloudflare();
    const next = { ...this.tunnelConfig };
    if (enabled !== undefined) next.enabled = Boolean(enabled);
    if (tunnelId !== undefined) {
      if (tunnelId === null || tunnelId === '') {
        next.tunnelId = null;
      } else {
        const cleanId = String(tunnelId).trim();
        cf.assertCfId ? cf.assertCfId(cleanId, 'Tunnel ID') : null;
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(cleanId)) throw new Error(`Tunnel ID inválido: ${cleanId}`);
        next.tunnelId = cleanId;
      }
    }
    if (mode !== undefined) {
      if (mode !== 'per_hostname' && mode !== 'all_to_caddy') {
        throw new Error(`Modo de túnel inválido: ${mode} (usa per_hostname o all_to_caddy)`);
      }
      next.mode = mode;
    }
    if (containerName !== undefined) {
      const cleanName = String(containerName || 'culkibo-cloudflared').trim();
      if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(cleanName)) {
        throw new Error(`Nombre de contenedor cloudflared inválido: ${cleanName}`);
      }
      next.containerName = cleanName;
    }
    if (caddyUpstream !== undefined) {
      const cleanUp = cf.validateTunnelServiceUrl
        ? cf.validateTunnelServiceUrl(caddyUpstream)
        : String(caddyUpstream).trim();
      next.caddyUpstream = cleanUp;
    }
    if (next.enabled && !next.tunnelId) {
      throw new Error('Activar Cloudflare Tunnel requiere indicar tunnelId');
    }
    this.tunnelConfig = next;
    this._saveConfig();
    return { ...this.tunnelConfig };
  }

  /** Estado completo de Cloudflare Tunnel: configuración persistida + estado del conector Docker + reglas remotas. */
  async getTunnelStatus() {
    const cf = this._getCloudflare();
    const connector = typeof cf.getCloudflaredStatus === 'function'
      ? await cf.getCloudflaredStatus({ containerName: this.tunnelConfig.containerName }).catch(() => null)
      : null;
    /** @type {any} */
    let remoteConfig = null;
    if (this.tunnelConfig.tunnelId && typeof cf.getTunnelConfig === 'function') {
      const res = await cf.getTunnelConfig(this.tunnelConfig.tunnelId).catch(() => null);
      if (res && res.success) remoteConfig = res.config;
    }
    return {
      config: { ...this.tunnelConfig },
      connector,
      remoteIngress: remoteConfig?.ingress || []
    };
  }

  /**
   * Sincroniza las reglas remotas del Cloudflare Tunnel con los dominios activos de Culkibo:
   * - `all_to_caddy`: publica TODOS los dominios activos (y `panelDomain`) hacia Caddy local sin abrir puertos 80/443.
   * - `per_hostname`: publica cada dominio con `routingMode === 'cloudflare_tunnel'` hacia su upstream real.
   *
   * @param {{ tunnelId?: string | null, mode?: 'per_hostname' | 'all_to_caddy' | null, zoneId?: string | null }} [opts]
   */
  async syncTunnelIngress({ tunnelId = null, mode = null, zoneId = null } = {}) {
    const cf = this._getCloudflare();
    const activeTunnelId = tunnelId || this.tunnelConfig.tunnelId;
    if (!activeTunnelId) {
      return { synced: false, error: 'No hay ningún tunnelId configurado para sincronizar' };
    }
    const activeMode = mode || this.tunnelConfig.mode || 'per_hostname';
    const domains = (this._domains.domains || []).filter((d) => d && d.status !== 'disabled');

    if (activeMode === 'all_to_caddy') {
      const hosts = Array.from(new Set([
        ...domains.map((d) => d.hostname),
        ...(this.panelDomain ? [this.panelDomain] : [])
      ])).filter((h) => h && h !== 'localhost');

      if (hosts.length === 0) {
        const res = await cf.syncTunnelRoutes(activeTunnelId, []);
        this.tunnelConfig.lastSyncedAt = new Date().toISOString();
        this._saveConfig();
        return { synced: Boolean(res.success), mode: activeMode, tunnelId: activeTunnelId, routesCount: 0, ingress: res.ingress || [] };
      }

      const res = await cf.configureAllResourcesTunnel({
        tunnelId: activeTunnelId,
        zoneId,
        hostnames: hosts,
        caddyUpstream: this.tunnelConfig.caddyUpstream || 'http://127.0.0.1:80'
      });
      if (res.success) {
        this.tunnelConfig.lastSyncedAt = new Date().toISOString();
        this._saveConfig();
      }
      return {
        synced: Boolean(res.success),
        mode: activeMode,
        tunnelId: activeTunnelId,
        routesCount: hosts.length,
        hostnames: hosts,
        ingress: res.ingress || [],
        dns: res.dns || [],
        ...(res.error ? { error: res.error } : {})
      };
    }

    // Modo per_hostname: sincronizar dominios con routingMode === 'cloudflare_tunnel'
    const state = this.buildDesiredState();
    /** @type {Map<string, string>} */
    const upstreamByHost = new Map();
    for (const s of state.specs) {
      if (Array.isArray(s.hostnames) && Array.isArray(s.upstreams) && s.upstreams[0]) {
        for (const h of s.hostnames) upstreamByHost.set(String(h).toLowerCase(), s.upstreams[0]);
      }
    }

    const tunnelDomains = domains.filter((d) =>
      d.routingMode === 'cloudflare_tunnel' &&
      (!d.tunnelId || d.tunnelId === activeTunnelId)
    );
    const rules = tunnelDomains.map((d) => {
      const up = upstreamByHost.get(String(d.hostname).toLowerCase()) || this._hostDial(Number(d.targetPort) || 3001);
      const service = /^https?:\/\//i.test(up) ? up : `http://${up}`;
      return {
        hostname: d.hostname,
        service,
        originRequest: {
          httpHostHeader: d.hostname.replace(/^\*\./, ''),
          connectTimeout: 30
        }
      };
    });

    const syncRes = await cf.syncTunnelRoutes(activeTunnelId, rules);
    if (syncRes.success) {
      this.tunnelConfig.lastSyncedAt = new Date().toISOString();
      this._saveConfig();
    }
    return {
      synced: Boolean(syncRes.success),
      mode: activeMode,
      tunnelId: activeTunnelId,
      routesCount: rules.length,
      ingress: syncRes.ingress || [],
      ...(syncRes.error ? { error: syncRes.error } : {})
    };
  }

  async publishViaTunnel({ tunnelId = null, zoneId = null, hostname, serviceUrl, path: routePath = null, originRequest = null }) {
    const cf = this._getCloudflare();
    const activeTunnelId = tunnelId || this.tunnelConfig.tunnelId;
    if (!activeTunnelId) throw new Error('Indica tunnelId o configura un túnel predeterminado primero');
    return cf.routeHostnameToTunnel({
      tunnelId: activeTunnelId,
      zoneId,
      hostname,
      serviceUrl,
      path: routePath,
      originRequest
    });
  }

  async unpublishFromTunnel({ tunnelId = null, zoneId = null, hostname, path: routePath = null, removeDns = true }) {
    const cf = this._getCloudflare();
    const activeTunnelId = tunnelId || this.tunnelConfig.tunnelId;
    if (!activeTunnelId) throw new Error('Indica tunnelId o configura un túnel predeterminado primero');
    return cf.unrouteHostnameFromTunnel({
      tunnelId: activeTunnelId,
      zoneId,
      hostname,
      path: routePath,
      removeDns
    });
  }

  /**
   * Autorización centralizada para `/api/ingress/ask` (TLS bajo demanda).
   * Por seguridad anti-DoS (Caddy #6611), solo aprueba hosts exactos configurados,
   * panelDomain, acompañantes canónicos www/ápex, previews activas y ápex wildcard:
   * NUNCA aprueba subdominios arbitrarios `<random>.dominio` para emisión HTTP-01
   * (los comodines se cubren con su certificado DNS-01 automatizado en `certificates.automate`).
   */
  isHostnameAuthorizedForTls(rawHost) {
    const host = String(rawHost || '').trim().toLowerCase().split(':')[0].replace(/\.+$/, '');
    if (!host) return false;
    if (this.panelDomain && host === this.panelDomain.replace(/\.+$/, '')) return true;
    // Comprobación exacta de dominios no-comodín activos
    for (const d of (this._domains.domains || [])) {
      if (!d || d.status === 'disabled' || d.isWildcard) continue;
      const dh = String(d.hostname || '').trim().toLowerCase().replace(/\.+$/, '');
      if (dh === host) return true;
      if (d.canonicalRedirect === 'www_to_apex' && !dh.startsWith('www.') && host === `www.${dh}`) return true;
      if (d.canonicalRedirect === 'apex_to_www' && dh.startsWith('www.') && host === dh.slice(4)) return true;
    }
    // Autorizar previews activas de Pull Requests
    for (const pr of this.previewRoutes.values()) {
      if (pr && String(pr.hostname || '').toLowerCase().replace(/\.+$/, '') === host) return true;
    }
    // Autorizar el ápex de políticas wildcard persistidas si includeApex está activo
    for (const wp of this.wildcardPolicies) {
      if (!wp || wp.enabled === false) continue;
      if (wp.includeApex !== false && host === String(wp.rootDomain || '').toLowerCase().replace(/\.+$/, '')) return true;
    }
    return false;
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
    if (this.publishedIds.has(this._caddy.routeId(projectId))) return true;
    const project = projectManager.getById(projectId);
    const hostnames = project && Array.isArray(project.domains) ? project.domains : [];
    return (this._domains.domains || []).some(d => d.projectId === projectId || hostnames.includes(d.hostname));
  }

  /**
   * Endpoint que Caddy consulta antes de emitir un certificado.
   *
   * Es configurable porque Caddy puede estar en un contenedor, donde
   * `127.0.0.1` es el propio contenedor y no el daemon. En ese caso hay que
   * apuntar a `host.docker.internal` o a la IP del host.
   */
  askEndpoint() {
    if (process.env.CULKIBO_ASK_ENDPOINT) return process.env.CULKIBO_ASK_ENDPOINT;
    const host = this._caddy.isContainerized ? 'host.docker.internal' : '127.0.0.1';
    return `http://${host}:${this.daemonPort}/api/ingress/ask`;
  }

  _hostDial(port) {
    const host = this._caddy.isContainerized ? 'host.docker.internal' : '127.0.0.1';
    return `${host}:${port}`;
  }

  // ---------------------------------------------------------------------
  // Estado deseado
  // ---------------------------------------------------------------------

  /** El proyecto al que pertenece un dominio, o null si no está vinculado (O(1)). */
  projectForDomain(domain, projectsByHost) {
    if (domain.projectId) {
      const byId = projectManager.getById(domain.projectId);
      if (byId) return byId;
    }
    return projectsByHost ? (projectsByHost.get(domain.hostname) || null) : null;
  }

  /**
   * Destino real de un proyecto, o null si no hay ninguno.
   */
  upstreamForProject(project) {
    if (!project) return null;
    const dm = getDeployManager();
    const prod = dm && dm.store && dm.store[project.id] && dm.store[project.id].current;
    // P1-7: solo usar el despliegue de producción cuando está realmente activo (no detenido).
    if (prod && prod.upstream && prod.status !== 'detenido' && prod.status !== 'stopped') return prod.upstream;
    const lr = containerOrchestrator._localRunner;
    const livePort = lr && lr.isRunning(project.id) ? lr.getPort(project.id) : null;
    const port = livePort || (project.localRunning ? project.localPort : null);
    if (!port) return null;
    return this._hostDial(port);
  }

  /** Extrae todas las opciones de política de borde configuradas en un dominio. */
  _extractDomainEdgeOpts(domain) {
    return {
      securityHeaders: domain.securityHeaders !== false,
      hstsPreload: Boolean(domain.hstsPreload),
      hstsMaxAge: domain.hstsMaxAge ?? null,
      permissionsPolicy: domain.permissionsPolicy || null,
      csp: domain.csp || null,
      framePolicy: domain.framePolicy || null,
      customHeaders: domain.customHeaders || null,
      basicAuth: domain.basicAuth || null,
      forwardAuth: domain.forwardAuth || null,
      cors: domain.cors || null,
      pathRoutes: Array.isArray(domain.pathRoutes) && domain.pathRoutes.length > 0 ? domain.pathRoutes : null,
      pathRedirects: Array.isArray(domain.pathRedirects) && domain.pathRedirects.length > 0 ? domain.pathRedirects : null,
      protocol: domain.protocol || 'http',
      streaming: Boolean(domain.streaming),
      flushInterval: domain.flushInterval ?? null,
      streamCloseDelayMs: domain.streamCloseDelayMs ?? null,
      responseHeaderTimeoutMs: domain.responseHeaderTimeoutMs ?? null,
      ipAllowlist: domain.ipAllowlist || null,
      maxBodySizeMb: domain.maxBodySizeMb || null,
      rateLimit: domain.rateLimit || null
    };
  }

  podRouteFor(domain, traffic) {
    const port = Number(domain.targetPort) || (domain.targetPod === 'citadel' ? CITADEL_PORT : FORGE_PORT);
    const isPodPort = port === FORGE_PORT || port === CITADEL_PORT;
    const edgeOpts = this._extractDomainEdgeOpts(domain);

    if (isPodPort && traffic.forge > 0 && traffic.citadel > 0) {
      return {
        projectId: domain.id,
        hostnames: [domain.hostname],
        upstreams: [this._hostDial(FORGE_PORT), this._hostDial(CITADEL_PORT)],
        weights: [traffic.forge, traffic.citadel],
        ...edgeOpts,
        kind: 'pod',
        label: `Reparto ${traffic.forge}/${traffic.citadel} entre Desarrollo y Producción`
      };
    }

    return {
      projectId: domain.id,
      hostnames: [domain.hostname],
      upstreams: [this._hostDial(port)],
      ...edgeOpts,
      kind: domain.targetPod === 'service' ? 'service' : 'pod',
      label: domain.targetPod === 'service'
        ? (domain.serviceName || 'Servicio')
        : (domain.targetPod === 'citadel' ? 'Producción' : 'Desarrollo')
    };
  }

  /** Emite ruta auxiliar de redirección canónica 301 (`www` ↔ apex) cuando el dominio la activa. */
  _appendCanonicalRedirectSpec(domain, specs) {
    if (!domain || domain.isWildcard || domain.status === 'disabled') return;
    if (domain.canonicalRedirect === 'www_to_apex' && !domain.hostname.startsWith('www.')) {
      specs.push({
        projectId: `redir_${domain.id}`,
        hostnames: [`www.${domain.hostname}`],
        kind: 'redirect',
        redirectTo: domain.hostname,
        redirectStatus: 301,
        label: `Redirección www.${domain.hostname} → ${domain.hostname}`
      });
    } else if (domain.canonicalRedirect === 'apex_to_www' && domain.hostname.startsWith('www.')) {
      const apex = domain.hostname.slice(4);
      if (apex) {
        specs.push({
          projectId: `redir_${domain.id}`,
          hostnames: [apex],
          kind: 'redirect',
          redirectTo: domain.hostname,
          redirectStatus: 301,
          label: `Redirección ${apex} → ${domain.hostname}`
        });
      }
    }
  }

  buildDesiredState() {
    const projects = projectManager.getAll();
    const domains = this._domains.domains || [];
    const traffic = containerOrchestrator.trafficAllocation || { forge: 0, citadel: 100 };

    // Índice O(P+D) para evitar búsquedas O(D×P)
    /** @type {Map<string, any>} */
    const projectsByHost = new Map();
    for (const p of projects) {
      if (Array.isArray(p.domains)) {
        for (const h of p.domains) {
          if (typeof h === 'string' && !projectsByHost.has(h.toLowerCase())) {
            projectsByHost.set(h.toLowerCase(), p);
          }
        }
      }
    }

    const specs = [];
    const skipped = [];
    const grouped = new Map();
    const disabledHosts = new Set();

    // Consultar catálogo solo si algún dominio referencia `serviceId` (evita cargar catalogManager en frío)
    /** @type {any} */
    let catalogMod = null;
    const hasServiceDomains = domains.some((d) => d && d.serviceId);
    if (hasServiceDomains) {
      try { catalogMod = require('./catalogManager'); } catch (e) {}
    }

    for (const domain of domains) {
      if (domain.status === 'disabled') {
        disabledHosts.add(domain.hostname);
        skipped.push({ hostnames: [domain.hostname], reason: 'El dominio está deshabilitado' });
        continue;
      }

      // P0: omitir dominios cuyo servicio del catálogo está detenido o con error
      if (domain.serviceId && catalogMod && typeof catalogMod.get === 'function') {
        const inst = catalogMod.get(domain.serviceId);
        if (inst && (inst.status === 'stopped' || inst.status === 'error' || inst.status === 'failed')) {
          skipped.push({
            hostnames: [domain.hostname],
            serviceId: domain.serviceId,
            reason: `El servicio «${inst.name || domain.serviceName || domain.serviceId}» está detenido`
          });
          continue;
        }
      }

      const project = this.projectForDomain(domain, projectsByHost);
      if (project) {
        if (!grouped.has(project.id)) grouped.set(project.id, { project, domains: [] });
        grouped.get(project.id).domains.push(domain);
        continue;
      }

      specs.push(this.podRouteFor(domain, traffic));
      this._appendCanonicalRedirectSpec(domain, specs);
    }

    const includedProjectIds = new Set();
    for (const entry of grouped.values()) {
      const project = entry.project;
      const hostnames = entry.domains.map(d => d.hostname);

      // Modo mantenimiento atómico (<10 ms): responde 503 elegante sin parar el contenedor
      if (project.maintenanceMode === true) {
        includedProjectIds.add(project.id);
        specs.push({
          projectId: project.id,
          hostnames,
          kind: 'maintenance',
          label: `${project.name} (mantenimiento)`
        });
        for (const d of entry.domains) this._appendCanonicalRedirectSpec(d, specs);
        continue;
      }

      const upstream = this.upstreamForProject(project);
      if (!upstream) {
        skipped.push({
          hostnames,
          projectId: project.id,
          reason: `El proyecto «${project.name}» no está en ejecución: no hay ningún destino real al que enrutar`
        });
        continue;
      }
      includedProjectIds.add(project.id);

      // Agrupar por (isWildcard, firma completa de política de borde): así un dominio exacto jamás
      // hereda prioridad wildcard y cada dominio puede tener ForwardAuth/CORS/gRPC/paths/BasicAuth/IP Allowlist propios.
      /** @type {Map<string, { domains: any[], isWildcard: boolean, sample: any }>} */
      const policyBuckets = new Map();
      for (const d of entry.domains) {
        const isW = Boolean(d.isWildcard || String(d.hostname).startsWith('*.'));
        const edge = this._extractDomainEdgeOpts(d);
        const sig = JSON.stringify([isW, edge]);
        if (!policyBuckets.has(sig)) policyBuckets.set(sig, { domains: [], isWildcard: isW, sample: d });
        const bucketObj = policyBuckets.get(sig);
        if (bucketObj) bucketObj.domains.push(d);
      }

      const bucketList = Array.from(policyBuckets.values());
      bucketList.forEach((bucket, idx) => {
        const edge = this._extractDomainEdgeOpts(bucket.sample);
        specs.push({
          projectId: idx === 0 ? project.id : `${project.id}_p${idx}`,
          ownerProjectId: project.id,
          hostnames: bucket.domains.map((d) => d.hostname),
          upstreams: [upstream],
          ...edge,
          kind: 'project',
          label: project.name
        });
      });
      for (const d of entry.domains) this._appendCanonicalRedirectSpec(d, specs);
    }

    const dm = getDeployManager();
    if (dm && dm.store) {
      for (const [projectId, state] of Object.entries(dm.store)) {
        if (includedProjectIds.has(projectId)) continue;
        const cur = state && state.current;
        if (cur && cur.upstream && cur.status !== 'detenido' && cur.status !== 'stopped' && Array.isArray(cur.hostnames) && cur.hostnames.length > 0) {
          const activeHosts = cur.hostnames.filter((h) => !disabledHosts.has(String(h).toLowerCase()));
          if (activeHosts.length > 0) {
            specs.push({
              projectId,
              hostnames: activeHosts,
              upstreams: [cur.upstream],
              securityHeaders: true,
              kind: 'production',
              label: cur.projectName || projectId
            });
          }
        }
      }
    }

    // Rutas activas de Pull Request Preview Deployments
    for (const [prKey, pr] of this.previewRoutes.entries()) {
      if (pr && pr.hostname && pr.upstream) {
        specs.push({
          projectId: `pr_${prKey}`,
          hostnames: [pr.hostname],
          upstreams: [pr.upstream],
          securityHeaders: true,
          kind: 'preview',
          label: `Preview PR #${pr.prNumber}`
        });
      }
    }

    // Ruta opcional del propio panel de Culkibo (Acceso Remoto con HTTPS).
    if (this.panelDomain) {
      const alreadyOwned = specs.some((s) => Array.isArray(s.hostnames) && s.hostnames.includes(this.panelDomain));
      if (!alreadyOwned) {
        const panelUpstream = process.env.CULKIBO_PANEL_UPSTREAM || this._hostDial(this.daemonPort);
        specs.push({
          projectId: 'culkibo_panel',
          hostnames: [this.panelDomain],
          upstreams: [panelUpstream],
          kind: 'panel',
          label: 'Panel Culkibo'
        });
      }
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
    const server = await this._caddy.get('/config/apps/http/servers/culkibo');
    if (server && typeof server === 'object' && !Array.isArray(server)) {
      if (!Array.isArray(server.routes)) {
        // PUT crea la clave; si otro proceso la ha creado entretanto, el error
        // es inofensivo y la siguiente escritura funciona igual.
        await this._caddy.write('PUT', '/config/apps/http/servers/culkibo/routes', []).catch(() => {});
      }
      this.serverReadyAt = Date.now();
      return { ready: true, created: false };
    }

    const full = await this._caddy.get('/config/');
    // P0-3: si el Caddy actual escucha Admin en 0.0.0.0:2019 (modo puente Docker), conservarlo siempre
    const existingAdminListen = full && full.admin && typeof full.admin.listen === 'string' ? full.admin.listen : '';
    const detectedContainerized = this._caddy.isContainerized || existingAdminListen.startsWith('0.0.0.0:');
    if (detectedContainerized) this._caddy.isContainerized = true;

    const hasApps = Boolean(full && full.apps && Object.keys(full.apps).length > 0);
    const tlsOpts = this._buildTlsOptions();
    const baseOpts = {
      askEndpoint: tlsOpts.askEndpoint,
      httpPort: this.httpPort,
      httpsPort: this.httpsPort,
      wildcardPolicies: tlsOpts.wildcardPolicies,
      acmeEmail: tlsOpts.acmeEmail,
      customCertFiles: tlsOpts.customCertFiles,
      containerized: detectedContainerized
    };
    const base = this._caddy.buildBaseConfig(baseOpts);

    if (!hasApps) {
      try {
        await this._caddy.loadBaseConfig(baseOpts);
      } catch (err) {
        // Si falló por falta de algún módulo DNS-01 (`dns.providers.*`), cargar base sin wildcards DNS-01 y avisar
        const provMatch = String(err.message || '').match(/dns\.providers\.([a-z0-9_-]+)/i);
        if ((provMatch || /module not registered/i.test(String(err.message || ''))) && baseOpts.wildcardPolicies.length > 0) {
          await this._caddy.loadBaseConfig({ ...baseOpts, wildcardPolicies: [] });
          this.log('WARN', `Caddy arrancado sin políticas wildcard porque falta el módulo ${provMatch ? provMatch[0] : 'dns.providers.*'}.`);
        } else {
          throw err;
        }
      }
      this.serverReadyAt = Date.now();
      return { ready: true, created: true, mode: 'base' };
    }

    if (!full.apps.http) {
      await this._caddy.write('PUT', '/config/apps/http', base.apps.http);
    } else if (!full.apps.http.servers) {
      await this._caddy.write('PUT', '/config/apps/http/servers', base.apps.http.servers);
    } else {
      await this._caddy.write('PUT', '/config/apps/http/servers/culkibo', base.apps.http.servers.culkibo);
    }
    this._caddy._appliedRouteJson.clear();

    /** @type {string | null} */
    let note = null;
    if (!full.apps.tls) {
      this._hasForeignTls = false;
      await this.reconcileTlsOnly();
    } else {
      this._hasForeignTls = true;
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
    const detection = await this._caddy.detect();
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
      routeId: this._caddy.routeId(projectId),
      reason,
      message: reason
    };
  }

  /** Da de alta o refresca la ruta de un proyecto (incluyendo mantenimiento y múltiples políticas); la retira si ya no procede. */
  async syncProject(projectId) {
    if (!this.mayHaveRoute(projectId)) {
      return this.nothingToDo(projectId, 'El proyecto no tiene ningún dominio vinculado');
    }

    return this.guard(async () => {
      const state = this.buildDesiredState();
      const projectSpecs = state.specs.filter(
        (s) => (s.projectId === projectId || s.ownerProjectId === projectId) &&
          (s.kind === 'project' || s.kind === 'maintenance' || s.kind === 'production')
      );

      if (projectSpecs.length === 0) {
        const removal = await this._caddy.removeRoute(projectId);
        this.publishedIds.delete(removal.id);
        const match = state.skipped.find(s => s.projectId === projectId);
        const reason = match ? match.reason : 'El proyecto no tiene ningún dominio vinculado';
        if (removal.removed) this.log('INFO', `Ruta retirada de ${projectId}: ${reason}`);
        return { applied: true, action: removal.removed ? 'removed' : 'noop', routeId: removal.id, reason };
      }

      if (projectSpecs.length > 1) {
        // Múltiples políticas por dominio en el mismo proyecto: reconciliar atómicamente para mantener orden
        const rec = await this._caddy.reconcile(state.specs);
        this.publishedIds = new Set(rec.applied);
        return {
          applied: true,
          action: 'updated',
          routeId: this._caddy.routeId(projectId),
          hostnames: projectSpecs.flatMap((s) => s.hostnames),
          upstreams: projectSpecs[0].upstreams || []
        };
      }

      const spec = projectSpecs[0];
      const result = await this._caddy.upsertRoute(spec);
      this.publishedIds.add(result.id);
      this.log('SUCCESS', `${result.created ? 'Alta' : 'Actualización'} de ${spec.hostnames.join(', ')} → ${(spec.upstreams || ['mantenimiento 503']).join(', ')}`);
      return {
        applied: true,
        action: result.created ? 'created' : 'updated',
        routeId: result.id,
        hostnames: spec.hostnames,
        upstreams: spec.upstreams || []
      };
    });
  }

  /** Retira la ruta de un proyecto. Idempotente. */
  async removeProject(projectId) {
    if (!this.mayHaveRoute(projectId)) {
      return this.nothingToDo(projectId, 'No había ninguna ruta publicada para este proyecto');
    }

    return this.guard(async () => {
      const removal = await this._caddy.removeRoute(projectId);
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
      const result = await this._caddy.reconcile(state.specs);
      /** @type {any} */
      let tlsResult = null;
      // Sincronizar siempre apps.tls (salvo Caddy con TLS ajeno) para reflejar cambios de acmeEmail o borrado del último PEM
      if (!this._hasForeignTls) {
        try {
          tlsResult = await this.reconcileTlsOnly();
        } catch (tlsErr) {
          tlsResult = { applied: false, error: tlsErr.message };
          try {
            require('./telemetryService').captureOperationFailure({
              operation: 'ingress_reconcile',
              stage: 'tls',
              message: tlsErr.message
            });
          } catch (e) {}
        }
      }
      this.publishedIds = new Set(result.applied);
      this.lastReconcile = {
        at: new Date().toISOString(),
        applied: result.applied.length,
        removed: result.removed.length,
        skipped: state.skipped.length
      };
      this.log('INFO', `Reconciliación: ${result.applied.length} ruta(s) aplicadas, ${result.removed.length} retirada(s), ${state.skipped.length} dominio(s) sin destino`);
      return { applied: true, routes: result.applied, removed: result.removed, skipped: state.skipped, tls: tlsResult };
    });
  }

  /**
   * Reconciliación de arranque.
   *
   * Es el punto que impide la deriva silenciosa tras un reinicio: Caddy puede
   * haber perdido su configuración, o haber sido editado por fuera, y sin esto
   * nuestra idea del mundo y la suya se separan sin que nadie lo note.
   */
  /** @param {{ port?: number }} [opts] */
  async bootstrap({ port } = {}) {
    if (port) this.daemonPort = Number(port);

    const detection = await this._caddy.detect({ force: true });
    if (!detection.available) {
      const message = `Sin plano de datos: ${detection.reason}. Culkibo funciona igual, pero ningún dominio se sirve desde aquí hasta que haya un Caddy accesible.`;
      console.warn(`[Edge:Ingress] ${message}`);
      this.log('WARN', message);
      return { available: false, applied: false, reason: detection.reason, message };
    }

    // Sondear capacidades del binario Caddy al arrancar para activar caddy-ratelimit / dns-* desde el primer reconcile
    await this._caddy.probeCapabilities().catch(() => {});

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
    const race = (p) => {
      /** @type {ReturnType<typeof setTimeout> | null} */
      let t = null;
      return Promise.race([
        p,
        new Promise((_, reject) => {
          t = setTimeout(() => reject(new Error('Tiempo de espera agotado en la resolución DNS')), timeoutMs);
          if (t.unref) t.unref();
        })
      ]).finally(() => { if (t) clearTimeout(t); });
    };

    const dns = getDns();
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

  async probeTls(hostname, { timeoutMs = 3000, port = null, fresh = false } = {}) {
    const raw = String(hostname || '').trim().toLowerCase();
    const isWildcard = raw.startsWith('*.');
    const root = raw.replace(/^\*\./, '');
    // P1-2: para comodín (`*.empresa.com`), sondeamos un subdominio sintético en vez del ápex
    const target = isWildcard ? `culkibo-probe.${root}` : root;
    const effectivePort = Number(port) || this.httpsPort || 443;
    const base = { hostname: raw, probed: target, wildcard: isWildcard };

    if (!root) return { ...base, reachable: false, error: 'Hostname vacío' };

    const cacheKey = `${isWildcard ? 'wc:' : ''}${target}:${effectivePort}`;
    if (!fresh) {
      const cached = this._tlsCache.get(cacheKey);
      const ttl = cached && cached.negative ? 15000 : 30000;
      if (cached && (Date.now() - cached.at) < ttl) {
        return { ...cached.result, hostname: raw, wildcard: isWildcard, cached: true };
      }
    }

    const startedResolve = Date.now();
    const resolved = await this.resolveAddress(target, timeoutMs);
    if (!resolved.address) {
      const failRes = {
        ...base,
        handshakeMs: Date.now() - startedResolve,
        reachable: false,
        error: humanizeTlsError(resolved.error)
      };
      if (this._tlsCache.size > 128) this._tlsCache.clear();
      this._tlsCache.set(cacheKey, { at: Date.now(), result: failRes, negative: true });
      return failRes;
    }

    // Protección SSRF: bloquear sondeos TLS a IPs privadas/metadatos salvo dominios registrados, panel o loopback estricto.
    const isRegistered = Boolean(
      this._domains.getByHostname(raw) ||
      this._domains.getByHostname(root) ||
      (this.panelDomain && (raw === this.panelDomain || root === this.panelDomain))
    );
    const isStrictLoopback = resolved.address === '127.0.0.1' || resolved.address === '::1';
    if (isMetadataIp(resolved.address) || (isPrivateIp(resolved.address) && !isRegistered && !isStrictLoopback)) {
      return { ...base, address: resolved.address, reachable: false, error: 'Dirección IP privada/interna bloqueada por protección SSRF' };
    }

    const tls = getTls();
    const probeResult = await new Promise((resolve) => {
      const startedAt = Date.now();
      /** @type {any} */
      let socket = null;
      let settled = false;

      const finish = (value) => {
        if (settled) return;
        settled = true;
        try { if (socket) socket.destroy(); } catch (e) {}
        resolve({ ...base, address: resolved.address, handshakeMs: Date.now() - startedAt, ...value });
      };

      try {
        const s = tls.connect({
          host: resolved.address,
          port: effectivePort,
          servername: target,
          rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1']
        }, () => {
          const cert = s.getPeerCertificate(false) || {};
          if (!cert.valid_to) {
            return finish({ reachable: true, error: 'El servidor no presentó ningún certificado' });
          }
          const notAfter = new Date(cert.valid_to);
          const notBefore = new Date(cert.valid_from);
          const hasNotAfter = !Number.isNaN(notAfter.getTime());
          const sans = cert.subjectaltname ? cert.subjectaltname.split(', ').map(x => x.replace(/^DNS:/, '').toLowerCase()) : [];
          const coversWildcard = isWildcard ? sans.includes(`*.${root}`) : undefined;
          const issuerName = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null;
          const issuerCN = (cert.issuer && cert.issuer.CN) || null;
          const isCloudflareOriginCa = /cloudflare origin/i.test(`${issuerName || ''} ${issuerCN || ''}`);
          finish({
            reachable: true,
            issuer: issuerName,
            issuerCN,
            isCloudflareOriginCa,
            subject: (cert.subject && cert.subject.CN) || null,
            sans,
            ...(isWildcard ? { coversWildcard } : {}),
            notBefore: Number.isNaN(notBefore.getTime()) ? null : notBefore.toISOString(),
            notAfter: hasNotAfter ? notAfter.toISOString() : null,
            daysRemaining: hasNotAfter ? Math.floor((notAfter.getTime() - Date.now()) / 86400000) : null,
            expired: hasNotAfter ? notAfter.getTime() <= Date.now() : null,
            trusted: s.authorized === true || isCloudflareOriginCa,
            trustError: s.authorized
              ? null
              : isCloudflareOriginCa
                ? 'Certificado Cloudflare Origin CA (válido con Proxy naranja de Cloudflare activado)'
                : (s.authorizationError ? humanizeTlsError(String(s.authorizationError)) : null),
            protocol: typeof s.getProtocol === 'function' ? s.getProtocol() : null,
            alpn: s.alpnProtocol || null
          });
        });
        socket = s;

        s.setTimeout(timeoutMs, () => finish({ reachable: false, error: humanizeTlsError(`Sin respuesta TLS en ${timeoutMs} ms`) }));
        s.on('error', (err) => finish({ reachable: false, error: humanizeTlsError(err.message) }));
      } catch (err) {
        finish({ reachable: false, error: humanizeTlsError(err.message) });
      }
    });

    if (this._tlsCache.size > 128) this._tlsCache.clear();
    this._tlsCache.set(cacheKey, { at: Date.now(), result: probeResult, negative: !probeResult.reachable });
    return probeResult;
  }

  /**
   * Diagnóstico integral de un dominio en 4 capas (DNS, Caddy/Ruta, TLS/Flexible-SSL y Upstream)
   * con veredicto y pasos accionables en castellano llano.
   */
  async diagnoseDomain(domainOrId, { expectedIp = null } = {}) {
    const dom = typeof domainOrId === 'string'
      ? (this._domains.getById(domainOrId) || this._domains.getByHostname(domainOrId))
      : domainOrId;
    const hostname = dom ? dom.hostname : String(domainOrId || '').trim().toLowerCase();
    if (!hostname) throw new Error('Indica un dominio para diagnosticar');

    const [dnsInfo, tlsInfo, caps, ingressStatus] = await Promise.all([
      this._domains.verifyDns(hostname, { expectedIp }),
      this.probeTls(hostname, { timeoutMs: 3500, fresh: true }),
      this._caddy.probeCapabilities({ force: false }),
      this.status({ probe: false, force: false })
    ]);

    const route = (ingressStatus.routes || []).find((r) => Array.isArray(r.hosts) && r.hosts.includes(hostname)) || null;
    const desired = (ingressStatus.desired || []).find((r) => Array.isArray(r.hosts) && r.hosts.includes(hostname)) || null;
    const skipped = (ingressStatus.skipped || []).find((s) => Array.isArray(s.hostnames) && s.hostnames.includes(hostname)) || null;

    // Comprobar si el upstream está realmente escuchando TCP
    /** @type {boolean | null} */
    let upstreamReachable = null;
    const targetUpstream = (route && route.upstreams && route.upstreams[0]) || (desired && desired.upstreams && desired.upstreams[0]) || null;
    if (targetUpstream && targetUpstream.includes(':')) {
      const [uHost, uPortStr] = targetUpstream.split(':');
      const uPort = Number(uPortStr);
      if (uPort > 0 && uPort <= 65535) {
        const net = getNet();
        upstreamReachable = await new Promise((resolve) => {
          const sock = net.connect({ host: uHost, port: uPort, timeout: 1500 }, () => {
            sock.destroy();
            resolve(true);
          });
          sock.on('error', () => { sock.destroy(); resolve(false); });
          sock.on('timeout', () => { sock.destroy(); resolve(false); });
        });
      }
    }

    /** @type {Array<{ id: string, title: string, status: 'ok' | 'warn' | 'fail', detail: string }>} */
    const checks = [];
    checks.push({
      id: 'dns',
      title: 'Resolución DNS',
      status: !dnsInfo.hasDnsRecords ? 'fail' : (dnsInfo.diagnostics.some((d) => d.level === 'error') ? 'fail' : (dnsInfo.diagnostics.some((d) => d.level === 'warn') ? 'warn' : 'ok')),
      detail: dnsInfo.diagnostics.map((d) => d.message).join(' ') || `Resuelve a ${(dnsInfo.resolvedIps || []).join(', ')}`
    });

    checks.push({
      id: 'caddy_route',
      title: 'Ruta en Caddy',
      status: !ingressStatus.available ? 'fail' : (route ? 'ok' : (skipped ? 'warn' : 'fail')),
      detail: !ingressStatus.available
        ? `Caddy no está activo (${ingressStatus.reason || 'sin conexión'}).`
        : route
          ? `Ruta publicada hacia ${route.upstreams.join(', ') || 'redirección/mantenimiento'}.`
          : skipped
            ? skipped.reason
            : 'La ruta aún no está publicada en Caddy. Pulsa «Reconciliar ahora».'
    });

    if (hostname.startsWith('*.')) {
      const root = hostname.slice(2);
      const policy = this.wildcardPolicies.find((p) => p.rootDomain === root && p.enabled !== false) || null;
      const providerId = String(policy?.provider || 'cloudflare').toLowerCase();
      const installed = Array.isArray(caps.installedDnsProviders) ? caps.installedDnsProviders : [];
      const hasProviderPlugin = installed.length > 0
        ? installed.includes(providerId)
        : (providerId === 'cloudflare' ? caps.hasCloudflareDnsPlugin : null);
      checks.push({
        id: 'wildcard_dns01',
        title: 'Certificado Wildcard (DNS-01)',
        status: hasProviderPlugin === false ? 'fail' : (policy ? 'ok' : 'warn'),
        detail: hasProviderPlugin === false
          ? `Tu binario de Caddy no incluye dns.providers.${providerId}. Compila con xcaddy o usa subdominios individuales con TLS bajo demanda.`
          : policy
            ? `Política DNS-01 (${providerId}) configurada para *.${root}.`
            : `Falta activar la política DNS-01 para *.${root} en el gestor Wildcard.`
      });
    }

    if (caps.http3) {
      checks.push({
        id: 'http3',
        title: 'HTTP/3 (QUIC)',
        status: caps.http3.supported ? 'ok' : 'warn',
        detail: caps.http3.supported
          ? `HTTP/3 QUIC activo (${(caps.http3.protocols || []).join(', ')}).`
          : (caps.http3.reason || 'HTTP/3 no está verificado en la configuración actual de Caddy.')
      });
    }

    const natOrFirewallBlocked = Boolean(
      !tlsInfo.reachable &&
      ingressStatus.available &&
      route &&
      upstreamReachable !== false &&
      dnsInfo.hasDnsRecords &&
      /tiempo de espera|443 no responde|bloqueado/i.test(String(tlsInfo.error || ''))
    );

    checks.push({
      id: 'tls',
      title: 'Certificado HTTPS (TLS)',
      status: tlsInfo.reachable && tlsInfo.trusted && !tlsInfo.expired
        ? (hostname.startsWith('*.') && tlsInfo.coversWildcard === false ? 'warn' : 'ok')
        : (tlsInfo.reachable ? 'warn' : 'fail'),
      detail: tlsInfo.reachable && tlsInfo.trusted && !tlsInfo.expired
        ? `Válido (${tlsInfo.isCloudflareOriginCa ? 'Cloudflare Origin CA' : (tlsInfo.issuer || 'CA verificada')}, ${tlsInfo.daysRemaining ?? '?'} días restantes${hostname.startsWith('*.') && tlsInfo.coversWildcard === false ? ' — aviso: el certificado servido no incluye SAN comodín' : ''}).`
        : natOrFirewallBlocked
          ? 'Tu servidor parece estar detrás de NAT/CGNAT o con los puertos 80/443 cerrados (Caddy y tu app sí están sanos en local). Usa un Túnel de Cloudflare (sin abrir puertos) o abre 80/443 en tu router/VPS.'
          : (tlsInfo.trustError || tlsInfo.error || 'Certificado aún pendiente de emisión.')
    });

    if (targetUpstream) {
      checks.push({
        id: 'upstream',
        title: 'Aplicación de destino',
        status: upstreamReachable ? 'ok' : 'fail',
        detail: upstreamReachable
          ? `El destino ${targetUpstream} está escuchando y acepta conexiones.`
          : `El destino ${targetUpstream} no acepta conexiones todavía (inicia o despliega el proyecto).`
      });
    } else {
      checks.push({
        id: 'upstream',
        title: 'Aplicación de destino',
        status: 'warn',
        detail: 'Aún no hay ningún contenedor o proceso local asignado a este dominio. Inicia el proyecto en local o despliégalo a producción.'
      });
    }

    const overall = checks.some((c) => c.status === 'fail') ? 'fail' : (checks.some((c) => c.status === 'warn') ? 'warn' : 'ok');
    return {
      hostname,
      overall,
      checks,
      dns: dnsInfo,
      tls: tlsInfo,
      route,
      upstreamReachable,
      capabilities: caps,
      checkedAt: new Date().toISOString()
    };
  }

  /**
   * Estado honesto del ingress: qué hay realmente en Caddy, en qué difiere de
   * lo que Culkibo cree (incluyendo deriva de contenido), y qué certificado sirve cada dominio.
   */
  async status({ probe = true, force = false, probeTimeoutMs = 3000 } = {}) {
    const detection = await this._caddy.detect({ force });
    const state = this.buildDesiredState();
    const desiredIds = state.specs.map(s => this._caddy.routeId(s.projectId));

    let liveRoutes = [];
    let routesError = null;
    if (detection.available) {
      try {
        liveRoutes = await this._caddy.listRoutes();
      } catch (err) {
        routesError = err.message;
        this.serverReadyAt = 0;
      }
    } else {
      this.serverReadyAt = 0;
    }

    const liveMap = new Map(liveRoutes.map((r) => [r['@id'], r]));
    const liveIds = Array.from(liveMap.keys());
    const desiredIdSet = new Set(desiredIds);
    const liveIdSet = new Set(liveIds);
    if (detection.available && !routesError) this.publishedIds = new Set(liveIds);

    /** @type {string[]} */
    const modified = [];
    for (const s of state.specs) {
      const id = this._caddy.routeId(s.projectId);
      const live = liveMap.get(id);
      if (!live) continue;
      const liveHosts = JSON.stringify(((live.match && live.match[0] && live.match[0].host) || []).slice().sort());
      const desHosts = JSON.stringify((s.hostnames || []).slice().sort());
      const proxyH = this._caddy.extractProxyHandler(live);
      const liveUps = JSON.stringify(((proxyH && proxyH.upstreams) || []).map((u) => u.dial));
      const desUps = JSON.stringify(s.upstreams || []);
      if (liveHosts !== desHosts || (s.kind !== 'redirect' && s.kind !== 'maintenance' && liveUps !== desUps)) {
        modified.push(id);
      }
    }

    const drift = {
      missing: desiredIds.filter(id => !liveIdSet.has(id)),
      unexpected: liveIds.filter(id => !desiredIdSet.has(id)),
      modified
    };

    // Excluir dominios deshabilitados para no malgastar slots de MAX_TLS_PROBES
    const hostSet = new Set((this._domains.domains || []).filter(d => d && d.status !== 'disabled').map(d => d.hostname));
    if (this.panelDomain) hostSet.add(this.panelDomain);
    const hostnames = Array.from(hostSet).slice(0, MAX_TLS_PROBES);
    const [tlsProbes, http3] = await Promise.all([
      probe && hostnames.length
        ? Promise.all(hostnames.map(h => this.probeTls(h, { timeoutMs: probeTimeoutMs })))
        : Promise.resolve([]),
      detection.available && typeof this._caddy.probeHttp3 === 'function'
        ? this._caddy.probeHttp3({ checkDockerUdp: false }).catch(() => null)
        : Promise.resolve(null)
    ]);

    return {
      dataPlane: 'caddy',
      available: detection.available,
      adminUrl: detection.adminUrl,
      version: detection.version,
      reason: detection.reason,
      panelDomain: this.panelDomain,
      acmeEmail: this.acmeEmail,
      wildcardPolicies: this.listWildcardPolicies(),
      dnsProviders: this.listSupportedDnsProviders(),
      tunnel: { ...this.tunnelConfig },
      http3,
      message: detection.available
        ? 'Caddy responde en su API de administración. El tráfico de los dominios lo sirve Caddy, no el daemon.'
        : `Ingress no disponible: ${detection.reason}. Culkibo sigue funcionando, pero ningún dominio se sirve desde aquí.`,
      routesManaged: liveRoutes.length,
      routesError,
      routes: liveRoutes.map(r => {
        const proxyH = this._caddy.extractProxyHandler(r);
        return {
          id: r['@id'],
          hosts: (r.match && r.match[0] && r.match[0].host) || [],
          upstreams: ((proxyH && proxyH.upstreams) || []).map(u => u.dial),
          weights: (proxyH && proxyH.load_balancing
            && proxyH.load_balancing.selection_policy
            && proxyH.load_balancing.selection_policy.weights) || null
        };
      }),
      desired: state.specs.map(s => ({
        id: this._caddy.routeId(s.projectId),
        kind: s.kind,
        label: s.label,
        hosts: s.hostnames,
        upstreams: s.upstreams || [],
        weights: s.weights || null
      })),
      skipped: state.skipped,
      drift,
      inSync: detection.available && !routesError && drift.missing.length === 0 && drift.unexpected.length === 0 && drift.modified.length === 0,
      lastReconcile: this.lastReconcile,
      lastTlsAudit: this.lastTlsAudit,
      tlsProbed: Boolean(probe),
      tls: tlsProbes,
      checkedAt: new Date().toISOString()
    };
  }

  /**
   * Watchdog automático de caducidad e integridad TLS (<14 días, caducado o no confiable/SAN incorrecto):
   * audita certificados PEM en disco (Origin CA / corporativos) y dominios activos en vivo,
   * deduplicando por hostname entre disco y vivo, y enviando alertas 1 vez/24h vía notificationService.
   */
  async checkCertificateExpiry({ warnDays = 14, probeLive = true } = {}) {
    const sslManager = this._getSsl();
    const now = Date.now();
    const DAY_MS = 24 * 3600 * 1000;
    /** @type {Map<string, { hostname: string, source: string, daysRemaining: number | null, expiresAt: string | null, issuer: string | null }>} */
    const expiredMap = new Map();
    /** @type {Map<string, { hostname: string, source: string, daysRemaining: number | null, expiresAt: string | null, issuer: string | null }>} */
    const expiringMap = new Map();
    /** @type {Map<string, { hostname: string, source: string, issuer: string | null, reason: string }>} */
    const untrustedMap = new Map();

    // 1. Certificados PEM propios en disco (no se renuevan solos)
    for (const c of (sslManager.listCertificates() || [])) {
      if (c.managedBy !== 'on_disk') continue;
      const key = String(c.domain || '').trim().toLowerCase();
      if (!key) continue;
      if (c.isExpired) {
        expiredMap.set(key, { hostname: c.domain, source: 'on_disk', daysRemaining: c.daysRemaining ?? 0, expiresAt: c.expiresAt || null, issuer: c.issuer || null });
        expiringMap.delete(key);
      } else if (c.daysRemaining != null && c.daysRemaining <= warnDays) {
        if (!expiredMap.has(key)) {
          expiringMap.set(key, { hostname: c.domain, source: 'on_disk', daysRemaining: c.daysRemaining, expiresAt: c.expiresAt || null, issuer: c.issuer || null });
        }
      }
    }

    // 2. Dominios activos en vivo (lotes de 4 para no saturar el event loop)
    if (probeLive) {
      const det = await this._caddy.detect();
      if (det && det.available) {
        const targets = Array.from(new Set([
          ...(this._domains.domains || []).filter((d) => d && d.status !== 'disabled').map((d) => d.hostname),
          ...(this.panelDomain ? [this.panelDomain] : [])
        ]));

        for (let i = 0; i < targets.length; i += 4) {
          const batch = targets.slice(i, i + 4);
          const results = await Promise.all(batch.map((h) => this.probeTls(h, { timeoutMs: 3500, fresh: true })));
          for (const r of results) {
            if (!r || !r.reachable) continue;
            const key = String(r.hostname || '').trim().toLowerCase();
            if (!key) continue;
            if (r.expired) {
              expiredMap.set(key, { hostname: r.hostname, source: 'live', daysRemaining: r.daysRemaining ?? 0, expiresAt: r.notAfter || null, issuer: r.issuer || null });
              expiringMap.delete(key);
            } else if (r.daysRemaining != null && r.daysRemaining <= warnDays) {
              if (!expiredMap.has(key)) {
                expiringMap.set(key, { hostname: r.hostname, source: 'live', daysRemaining: r.daysRemaining, expiresAt: r.notAfter || null, issuer: r.issuer || null });
              }
            }
            if (r.trusted === false && !r.expired) {
              untrustedMap.set(key, {
                hostname: r.hostname,
                source: 'live',
                issuer: r.issuer || null,
                reason: r.trustError || r.error || 'Certificado no confiable o SAN no coincide con el dominio'
              });
            }
          }
        }
      }
    }

    const expired = Array.from(expiredMap.values());
    const expiring = Array.from(expiringMap.values());
    const untrusted = Array.from(untrustedMap.values());

    // Notificar con deduplicación 24h por (hostname, tipo)
    /** @type {any} */
    let ns = this._customNotifier || null;
    if (!ns) {
      try { ns = require('./notificationService'); } catch (e) {}
    }
    if (ns && typeof ns.notify === 'function') {
      for (const item of [...expired, ...expiring]) {
        const isExp = expired.includes(item);
        const dedupKey = `${String(item.hostname).toLowerCase()}:expiry`;
        const lastAlert = this._tlsAlertSentAt.get(dedupKey) || 0;
        if (now - lastAlert < DAY_MS) continue;
        this._tlsAlertSentAt.set(dedupKey, now);
        ns.notify({
          event: 'tls_expiring',
          level: isExp || (item.daysRemaining != null && item.daysRemaining <= 3) ? 'error' : 'warning',
          title: isExp ? `Certificado TLS caducado: ${item.hostname}` : `Certificado TLS próximo a caducar: ${item.hostname}`,
          message: isExp
            ? `El certificado de ${item.hostname} (${item.source === 'on_disk' ? 'PEM en disco' : 'en vivo'}) ha caducado. Renuévalo desde Dominios.`
            : `El certificado de ${item.hostname} caduca en ${item.daysRemaining} día(s) (${item.expiresAt ? item.expiresAt.slice(0, 10) : 'próximamente'}).`
        }).catch(() => {});
      }
      for (const bad of untrusted) {
        const dedupKey = `${String(bad.hostname).toLowerCase()}:untrusted`;
        const lastAlert = this._tlsAlertSentAt.get(dedupKey) || 0;
        if (now - lastAlert < DAY_MS) continue;
        this._tlsAlertSentAt.set(dedupKey, now);
        ns.notify({
          event: 'tls_expiring',
          level: 'error',
          title: `Certificado TLS no confiable: ${bad.hostname}`,
          message: `El certificado servido en vivo por ${bad.hostname} falló la validación TLS: ${bad.reason}.`
        }).catch(() => {});
      }
    }

    this.lastTlsAudit = {
      checkedAt: new Date(now).toISOString(),
      warnDays,
      expired,
      expiring,
      untrusted
    };
    return this.lastTlsAudit;
  }
}

const ingressManagerInstance = Object.assign(new IngressManager(), { IngressManager });
module.exports = ingressManagerInstance;
