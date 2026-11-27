import { useSyncExternalStore } from 'react';

export type Locale = 'en' | 'es';

const LOCALE_STORAGE_KEY = 'culkibo_locale';

const listeners = new Set<() => void>();

function detectInitialLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  try {
    const params = new URLSearchParams(window.location.search);
    const qLang = params.get('lang')?.toLowerCase();
    if (qLang === 'en' || qLang === 'es') {
      window.localStorage.setItem(LOCALE_STORAGE_KEY, qLang);
      return qLang;
    }
  } catch {
    // ignore URL/storage restrictions
  }
  try {
    const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (saved === 'en' || saved === 'es') return saved;
  } catch {
    // ignore
  }
  const navLang = typeof navigator !== 'undefined' ? (navigator.language || '').toLowerCase() : '';
  return navLang.startsWith('es') ? 'es' : 'en';
}

let currentLocale: Locale = detectInitialLocale();

function applyLocaleToDom(locale: Locale): void {
  if (typeof document !== 'undefined') {
    document.documentElement.lang = locale;
  }
}

applyLocaleToDom(currentLocale);

export function getLocale(): Locale {
  return currentLocale;
}

export function setLocale(next: Locale): void {
  if (next !== 'en' && next !== 'es') return;
  if (currentLocale === next) return;
  currentLocale = next;
  applyLocaleToDom(next);
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, next);
  } catch {
    // ignore
  }
  for (const fn of listeners) fn();
}

export function toggleLocale(): Locale {
  const next: Locale = currentLocale === 'en' ? 'es' : 'en';
  setLocale(next);
  return next;
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

const MESSAGES = {
  en: {
    // Nav & Header
    'nav.projects': 'Projects',
    'nav.catalog': 'Catalog',
    'nav.domains': 'Domains',
    'nav.ai': 'AI Agents',
    'nav.aiShort': 'AI',
    'nav.fleet': 'Fleet',
    'nav.metrics': 'Metrics',
    'nav.uptime': 'Uptime',
    'nav.import': 'Import',
    'nav.logs': 'Live Logs',
    'nav.settings': 'Settings',
    'header.new': 'New',
    'header.searchAria': 'Open quick search and command palette',
    'header.searchTitle': 'Quick search',
    'header.settingsTitle': 'Settings & security (g s)',
    'header.daemonOnline': 'Control plane online',
    'header.daemonOnlineShort': 'Online',
    'header.reconnecting': 'Reconnecting',
    'header.reconnectingFull': 'Reconnecting WebSocket to server…',
    'header.openLogsHint': 'Click to open live logs',
    'header.newDeployGit': 'Deploy Git repository',
    'header.newDeployGitDesc': 'GitHub, GitLab, Git URL or local folder',
    'header.newImport': 'Import from Coolify or Compose',
    'header.newImportDesc': 'Coolify v4, Docker Compose, Vercel, Railway',
    'header.newCatalog': '1-Click Catalog (140+ apps)',
    'header.newCatalogDesc': 'n8n, Langfuse, Dify, WordPress, PostgreSQL…',
    'header.newWordpress': 'Zero-downtime WordPress migration',
    'header.newWordpressDesc': 'Analyze your current site and clone with SSL',
    'header.newDomain': 'Connect HTTPS domain',
    'header.newDomainDesc': 'Caddy, Multi-DNS-01 wildcard or CGNAT tunnel',
    'header.drawerWorkspace': 'Workspace',
    'header.drawerInfra': 'Infrastructure',
    'header.drawerOps': 'Operations & Security',
    'header.drawerSettings': 'Settings, 2FA & Audit',
    'header.drawerSearch': 'Search projects, 140+ apps…',
    'header.backProjects': '← Projects',
    'header.themeLight': 'Switch to Light mode',
    'header.themeDark': 'Switch to Dark mode',
    'header.langToggle': 'Switch language (EN / ES)',

    // App shell
    'app.checkingAuth': 'Checking access…',
    'app.offlineTitle': 'Could not connect to Culkibo',
    'app.offlineDesc': 'The control plane server is not responding right now. Check that the service is running and retry.',
    'app.retry': 'Retry connection',
    'app.shortcuts': 'Shortcuts (?)',
    'app.closeNotice': 'Dismiss notice',

    // Onboarding
    'onb.ready': 'Environment ready for production',
    'onb.title': 'Quick start (<2 min)',
    'onb.step1Title': 'Engine & HTTPS',
    'onb.step1Done': 'Docker and Caddy active{ip}.',
    'onb.step1Todo': 'Start Caddy to enable automatic TLS & HTTP/3 with zero config.',
    'onb.step2Title': 'Deploy your first app',
    'onb.step2Done': '{count} active {unit} running on your server.',
    'onb.step2Todo': 'Deploy from Git, migrate Coolify v4, or install from 140+ catalog apps.',
    'onb.step3Title': 'Connect your AI Agent',
    'onb.step3Done': 'Agent connected to control plane with 109+ MCP tools.',
    'onb.step3Todo': 'Connect Claude Code, Antigravity, or Cursor in 1 click (~81% fewer tokens).',
    'onb.step4Title': 'HTTPS & 2FA Security',
    'onb.step4Done': '{count} HTTPS {unit} connected.',
    'onb.step4Todo': 'Publish your domain with auto-SSL and harden access with TOTP 2FA.',
    'onb.activateCaddy': 'Start Caddy',
    'onb.git': 'Git',
    'onb.coolify': 'Coolify',
    'onb.apps140': '140+ Apps',
    'onb.domain': 'Domain',
    'onb.security2fa': '2FA & Audit',
    'onb.resourceSingular': 'resource',
    'onb.resourcePlural': 'resources',
    'onb.domainSingular': 'domain',
    'onb.domainPlural': 'domains',

    // ProjectList
    'projects.title': 'Projects',
    'projects.loading': 'Loading workspace…',
    'projects.emptySubtitle': 'Deploy from Git, migrate Coolify in 1 click, or install 140+ apps with automatic HTTPS.',
    'projects.importBtn': 'Import or migrate',
    'projects.newBtn': 'New project',
    'projects.searchPlaceholder': 'Search project, repository or domain…',
    'projects.filterAll': 'All',
    'projects.filterActive': 'Active',
    'projects.filterLocal': 'Local',
    'projects.filterStopped': 'Stopped',
    'projects.sortRecent': 'Most recent',
    'projects.sortName': 'Name (A–Z)',
    'projects.sortDomains': 'Most domains',
    'projects.sortStatus': 'Status',
    'projects.statusMaintenance': 'Maintenance',
    'projects.statusLive': 'In production',
    'projects.statusLocal': 'Local',
    'projects.statusHibernated': 'Hibernated',
    'projects.statusStopped': 'Stopped',
    'projects.statusReady': 'Ready',
    'projects.localProject': 'Local project',
    'projects.connectDomain': 'Connect HTTPS domain',
    'projects.notDeployed': 'Not deployed yet',
    'projects.deploy': 'Deploy',
    'projects.deploying': 'Deploying…',
    'projects.stop': 'Stop',
    'projects.stopping': 'Stopping…',
    'projects.open': 'Open',
    'projects.tableProject': 'Project',
    'projects.tableStatus': 'Status',
    'projects.tableRuntime': 'Runtime',
    'projects.tableDomain': 'Domain',
    'projects.tableActions': 'Actions',
    'projects.noDomain': 'No domain',
    'projects.heroPill': 'Zero-Shell · <60 MB RAM · Automatic HTTPS',
    'projects.heroTitle': 'Launch your first app in 30 seconds',
    'projects.heroDesc': 'Migrate existing infrastructure painlessly, deploy a Git repo with <10ms Live Sync, or launch curated 1-click stacks.',
    'projects.pathCoolifyTitle': 'Import from Coolify',
    'projects.pathCoolifyDesc': '1-click migration of apps, databases, magic vars, and automatic Traefik → Caddy translation.',
    'projects.pathCoolifyCta': 'Open Coolify migrator',
    'projects.pathGitTitle': 'Deploy Git repository',
    'projects.pathGitDesc': 'Connect GitHub, GitLab, or a local folder. SmartPack stack detection, BuildKit & native SSL.',
    'projects.pathGitCta': 'Create new project',
    'projects.pathCatalogTitle': '1-Click Catalog (140+ Apps)',
    'projects.pathCatalogDesc': 'WordPress, n8n, Langfuse, Dify, Authentik, Ghost, PostgreSQL… pinned images, zero docker.sock.',
    'projects.pathCatalogCta': 'Browse catalog',
    'projects.heroWpLink': 'Zero-downtime WordPress migration',
    'projects.heroAiLink': 'Connect Claude Code / Antigravity MCP',
    'projects.noMatchQuery': 'No projects match “{query}”',
    'projects.noMatchFilter': 'No projects in this filter',
    'projects.resetFilters': 'Reset filters',

    // CommandPalette
    'cmd.placeholder': 'Search projects, 140+ catalog apps, Coolify, MCP, 2FA, theme…',
    'cmd.groupCurrent': 'Current project',
    'cmd.groupQuick': 'Quick actions',
    'cmd.groupProjects': 'Projects',
    'cmd.groupCatalog': 'Catalog (140+ apps)',
    'cmd.groupNav': 'Navigation',
    'cmd.indexedApps': '{count} apps indexed',
    'cmd.emptyTitle': 'No matches for “{query}”',
    'cmd.emptyHint': 'Try “coolify”, “mcp”, “2fa”, “http3”, “dark”, “n8n”, “langfuse” or a project name.',
    'cmd.footerNav': '↑↓ navigate',
    'cmd.footerOpen': '↵ open',
    'cmd.resultSingular': 'result',
    'cmd.resultPlural': 'results',
    'cmd.actNewProject': 'Create new project',
    'cmd.actNewProjectHint': 'GitHub, Git URL or local folder',
    'cmd.actCoolify': 'Migrate from Coolify',
    'cmd.actCoolifyHint': 'Apps, DBs, magic vars & Traefik → Caddy translation',
    'cmd.actMcp': 'Connect Claude Code / Antigravity MCP',
    'cmd.actMcpHint': 'Streamable HTTP 2026 · 109+ tools & MCP Apps',
    'cmd.actSecurity': 'Run Security Audit & 2FA',
    'cmd.actSecurityHint': 'TOTP 2FA, OIDC SSO, SHA-256 chain & Secret Scanner',
    'cmd.actEdge': 'Check Edge Multi-DNS-01 & HTTP/3',
    'cmd.actEdgeHint': 'QUIC UDP :443 & 7 wildcard DNS-01 providers',
    'cmd.actTheme': 'Toggle Dark / Light theme',
    'cmd.actThemeHint': 'Instant Railway/Linear obsidian dark mode',
    'cmd.actLang': 'Switch language (EN ↔ ES)',
    'cmd.actLangHint': 'Instant zero-reload interface translation',
    'cmd.actDomain': 'Connect an HTTPS domain',
    'cmd.actDomainHint': 'Proxy, DNS, Wildcard or CGNAT EdgeTunnel',

    // Settings
    'settings.title': 'Settings',
    'settings.subtitle': 'Remote access, enterprise security (2FA/OIDC/Audit), appearance, integrations, backups, and system.',
    'settings.tabRemote': 'Remote access',
    'settings.tabTeam': 'Team & RBAC',
    'settings.tabSecurity': 'Security',
    'settings.tabGitops': 'GitOps',
    'settings.tabIntegrations': 'Integrations',
    'settings.tabBackups': 'Backups & DR',
    'settings.tabNotifications': 'Notifications',
    'settings.tabSystem': 'System',
    'settings.appearanceTitle': 'Appearance & Language',
    'settings.appearanceDesc': 'Choose your interface theme and language. Saved locally with instant switching.',
    'settings.themeLabel': 'Theme',
    'settings.themeLight': 'Light',
    'settings.themeDark': 'Dark',
    'settings.themeSystem': 'System',
    'settings.langLabel': 'Language',
    'settings.sec2faTitle': 'Two-Factor Authentication (TOTP 2FA)',
    'settings.sec2faDesc': 'Protect the control plane with 6-digit TOTP codes and AES-256-GCM encrypted single-use recovery codes.',
    'settings.sec2faSetup': 'Setup 2FA',
    'settings.sec2faReconfig': 'Reconfigure 2FA',
    'settings.sec2faDisable': 'Disable 2FA',
    'settings.secOidcTitle': 'SSO Providers (OIDC / OAuth2 PKCE)',
    'settings.secOidcDesc': 'Native zero-dep JWKS verification (RS256/ES256/EdDSA), mandatory PKCE S256, and groups → RBAC role mapping.',
    'settings.secAuditTitle': 'Tamper-Evident Audit Log (SHA-256 Chain)',
    'settings.secAuditDesc': 'Every mutation chains its cryptographic hash to the previous entry (prevHash → entryHash) to detect tampering.',
    'settings.secAuditVerify': 'Verify Tamper-Proof Chain',
    'settings.secAuditVerifying': 'Verifying…',
    'settings.secScannerTitle': 'Pre-Deploy Secret Scanner',
    'settings.secScannerDesc': 'Detects AWS, Stripe, GitHub, OpenAI/Anthropic, PEM, JWT, DB URIs, and high Shannon entropy before deploying.',
    'settings.secScannerSample': 'Load safe test sample',
    'settings.secScannerRun': 'Scan for secret leaks',
    'settings.secScannerRunning': 'Scanning…',

    // ProjectDetail Fast Restart
    'pd.envTitle': 'Environment Variables',
    'pd.envDirty': 'Unsaved changes',
    'pd.envDesc': 'Secrets and runtime configuration injected into deployments.',
    'pd.envSave': 'Save variables',
    'pd.fastBannerTitle': 'Runtime env vars saved — apply without rebuilding?',
    'pd.fastBannerDesc': 'Fast Restart recreates the container with your new env vars in ~1.5s, skipping full Docker image rebuilds.',
    'pd.fastRestartBtn': 'Fast Restart (~1.5s, no rebuild)',
    'pd.fastRestarting': 'Restarting container…',
    'pd.fullDeployBtn': 'Full Deploy',
    'pd.fastRestartDone': 'Container restarted with updated env in {ms} (no rebuild)',

    // Spatial Topology
    'topo.title': 'Interactive Service Topology Canvas',
    'topo.subtitle': 'Pan & zoom live architecture flow: Domains & Monitors → Projects → Databases / Cache / Catalog → Fleet Servers.',
    'topo.refresh': 'Refresh map',
    'topo.fit': 'Reset',
    'topo.building': 'Building dependency map…',
    'topo.empty': 'Create your first project or database to visualize live network topology.',
    'topo.colEdge': 'Domains & Uptime',
    'topo.colProjects': 'Projects',
    'topo.colData': 'Databases & Services',
    'topo.colServers': 'Fleet Servers',
    'topo.inspectorTitle': 'Node Inspector',
    'topo.inspectorEmpty': 'Click any node on the canvas to inspect live health, metadata, and upstream/downstream links.',
    'topo.inbound': 'Inbound',
    'topo.outbound': 'Outbound',
    'topo.dragHint': 'Drag canvas to pan · Click node to inspect',
  },
  es: {
    // Nav & Header
    'nav.projects': 'Proyectos',
    'nav.catalog': 'Catálogo',
    'nav.domains': 'Dominios',
    'nav.ai': 'Agentes IA',
    'nav.aiShort': 'IA',
    'nav.fleet': 'Flota',
    'nav.metrics': 'Métricas',
    'nav.uptime': 'Uptime',
    'nav.import': 'Importar',
    'nav.logs': 'Registros en directo',
    'nav.settings': 'Ajustes',
    'header.new': 'Nuevo',
    'header.searchAria': 'Abrir búsqueda y paleta de comandos',
    'header.searchTitle': 'Búsqueda rápida',
    'header.settingsTitle': 'Ajustes y seguridad (g s)',
    'header.daemonOnline': 'Plano de control en línea',
    'header.daemonOnlineShort': 'En línea',
    'header.reconnecting': 'Reconectando',
    'header.reconnectingFull': 'Reconectando WebSocket con el servidor…',
    'header.openLogsHint': 'Clic para abrir registros en directo',
    'header.newDeployGit': 'Desplegar repositorio Git',
    'header.newDeployGitDesc': 'GitHub, GitLab, URL Git o carpeta local',
    'header.newImport': 'Importar desde Coolify o Compose',
    'header.newImportDesc': 'Coolify v4, Docker Compose, Vercel, Railway',
    'header.newCatalog': 'Catálogo 1-Clic (140+ apps)',
    'header.newCatalogDesc': 'n8n, Langfuse, Dify, WordPress, PostgreSQL…',
    'header.newWordpress': 'Migrar WordPress sin cortes',
    'header.newWordpressDesc': 'Analiza tu web actual y clónala con SSL',
    'header.newDomain': 'Conectar dominio HTTPS',
    'header.newDomainDesc': 'Caddy, Multi-DNS-01 wildcard o túnel CGNAT',
    'header.drawerWorkspace': 'Espacio de trabajo',
    'header.drawerInfra': 'Infraestructura',
    'header.drawerOps': 'Operación y Seguridad',
    'header.drawerSettings': 'Ajustes, 2FA y Auditoría',
    'header.drawerSearch': 'Buscar proyectos, 140+ apps…',
    'header.backProjects': '← Proyectos',
    'header.themeLight': 'Cambiar a modo claro',
    'header.themeDark': 'Cambiar a modo oscuro',
    'header.langToggle': 'Cambiar idioma (ES / EN)',

    // App shell
    'app.checkingAuth': 'Comprobando acceso…',
    'app.offlineTitle': 'No se pudo conectar con Culkibo',
    'app.offlineDesc': 'El servidor del plano de control no responde en este momento. Comprueba que el servicio esté activo y vuelve a intentarlo.',
    'app.retry': 'Reintentar conexión',
    'app.shortcuts': 'Atajos (?)',
    'app.closeNotice': 'Cerrar aviso',

    // Onboarding
    'onb.ready': 'Entorno listo para producción',
    'onb.title': 'Arranque rápido (<2 min)',
    'onb.step1Title': 'Motor y HTTPS',
    'onb.step1Done': 'Docker y Caddy activos{ip}.',
    'onb.step1Todo': 'Activa Caddy para emitir TLS automático y HTTP/3 sin configurar nada.',
    'onb.step2Title': 'Despliega tu primera app',
    'onb.step2Done': '{count} {unit} en tu servidor.',
    'onb.step2Todo': 'Despliega desde Git, migra Coolify v4 o instala del catálogo (140+ apps).',
    'onb.step3Title': 'Conecta tu Agente IA',
    'onb.step3Done': 'Agente conectado al plano de control con 109+ herramientas.',
    'onb.step3Todo': 'Conecta Claude Code, Antigravity o Cursor en 1 clic (~81% menos tokens).',
    'onb.step4Title': 'HTTPS y Seguridad 2FA',
    'onb.step4Done': '{count} {unit} HTTPS conectados.',
    'onb.step4Todo': 'Publica tu dominio con SSL automático y protege tu cuenta con TOTP 2FA.',
    'onb.activateCaddy': 'Activar Caddy',
    'onb.git': 'Git',
    'onb.coolify': 'Coolify',
    'onb.apps140': '140+ Apps',
    'onb.domain': 'Dominio',
    'onb.security2fa': '2FA y Auditoría',
    'onb.resourceSingular': 'recurso activo',
    'onb.resourcePlural': 'recursos activos',
    'onb.domainSingular': 'dominio',
    'onb.domainPlural': 'dominios',

    // ProjectList
    'projects.title': 'Proyectos',
    'projects.loading': 'Cargando espacio de trabajo…',
    'projects.emptySubtitle': 'Despliega desde Git, migra Coolify en 1 clic o instala 140+ apps con HTTPS automático.',
    'projects.importBtn': 'Importar o migrar',
    'projects.newBtn': 'Nuevo proyecto',
    'projects.searchPlaceholder': 'Buscar proyecto, repositorio o dominio…',
    'projects.filterAll': 'Todos',
    'projects.filterActive': 'Activos',
    'projects.filterLocal': 'Local',
    'projects.filterStopped': 'Detenidos',
    'projects.sortRecent': 'Más recientes',
    'projects.sortName': 'Nombre (A–Z)',
    'projects.sortDomains': 'Más dominios',
    'projects.sortStatus': 'Estado',
    'projects.statusMaintenance': 'Mantenimiento',
    'projects.statusLive': 'En producción',
    'projects.statusLocal': 'Local',
    'projects.statusHibernated': 'Hibernado',
    'projects.statusStopped': 'Detenido',
    'projects.statusReady': 'Listo',
    'projects.localProject': 'Proyecto local',
    'projects.connectDomain': 'Conectar dominio HTTPS',
    'projects.notDeployed': 'Sin desplegar todavía',
    'projects.deploy': 'Desplegar',
    'projects.deploying': 'Desplegando…',
    'projects.stop': 'Detener',
    'projects.stopping': 'Parando…',
    'projects.open': 'Abrir',
    'projects.tableProject': 'Proyecto',
    'projects.tableStatus': 'Estado',
    'projects.tableRuntime': 'Runtime',
    'projects.tableDomain': 'Dominio',
    'projects.tableActions': 'Acciones',
    'projects.noDomain': 'Sin dominio',
    'projects.heroPill': 'Zero-Shell · <60 MB RAM · HTTPS Automático',
    'projects.heroTitle': 'Elige cómo empezar en 30 segundos',
    'projects.heroDesc': 'Migra tu infraestructura actual sin dolor, despliega un repositorio Git con Live Sync o instala un stack del catálogo curado.',
    'projects.pathCoolifyTitle': 'Importar desde Coolify',
    'projects.pathCoolifyDesc': 'Migración en 1 clic de apps, bases de datos y variables mágicas con traducción automática Traefik → Caddy.',
    'projects.pathCoolifyCta': 'Abrir migrador Coolify',
    'projects.pathGitTitle': 'Desplegar repositorio Git',
    'projects.pathGitDesc': 'Conecta GitHub, GitLab o carpeta local. Detección SmartPack, build BuildKit y SSL nativo.',
    'projects.pathGitCta': 'Crear nuevo proyecto',
    'projects.pathCatalogTitle': 'Catálogo 1-Clic (140+ Apps)',
    'projects.pathCatalogDesc': 'WordPress, n8n, Langfuse, Dify, Authentik, Ghost, PostgreSQL… imágenes pineadas sin docker.sock.',
    'projects.pathCatalogCta': 'Explorar catálogo',
    'projects.heroWpLink': 'Migrar WordPress sin cortes',
    'projects.heroAiLink': 'Conectar Claude Code / Antigravity MCP',
    'projects.noMatchQuery': 'No hay proyectos que coincidan con «{query}»',
    'projects.noMatchFilter': 'No hay proyectos en este filtro',
    'projects.resetFilters': 'Restablecer filtros',

    // CommandPalette
    'cmd.placeholder': 'Buscar proyectos, 140+ apps del catálogo, Coolify, MCP, 2FA, tema…',
    'cmd.groupCurrent': 'Proyecto actual',
    'cmd.groupQuick': 'Acciones rápidas',
    'cmd.groupProjects': 'Proyectos',
    'cmd.groupCatalog': 'Catálogo (140+ apps)',
    'cmd.groupNav': 'Navegación',
    'cmd.indexedApps': '{count} apps indexadas',
    'cmd.emptyTitle': 'Sin coincidencias para «{query}»',
    'cmd.emptyHint': 'Prueba con «coolify», «mcp», «2fa», «http3», «oscuro», «n8n», «langfuse» o un proyecto.',
    'cmd.footerNav': '↑↓ navegar',
    'cmd.footerOpen': '↵ abrir',
    'cmd.resultSingular': 'resultado',
    'cmd.resultPlural': 'resultados',
    'cmd.actNewProject': 'Crear nuevo proyecto',
    'cmd.actNewProjectHint': 'GitHub, URL Git o carpeta local',
    'cmd.actCoolify': 'Migrar desde Coolify',
    'cmd.actCoolifyHint': 'Apps, BD, magic vars y traducción Traefik → Caddy',
    'cmd.actMcp': 'Conectar Claude Code / Antigravity MCP',
    'cmd.actMcpHint': 'Streamable HTTP 2026 · 109+ herramientas y MCP Apps',
    'cmd.actSecurity': 'Ejecutar auditoría de seguridad y 2FA',
    'cmd.actSecurityHint': 'TOTP 2FA, OIDC SSO, cadena SHA-256 y Secret Scanner',
    'cmd.actEdge': 'Comprobar Edge Multi-DNS-01 y HTTP/3',
    'cmd.actEdgeHint': 'QUIC UDP :443 y 7 proveedores wildcard DNS-01',
    'cmd.actTheme': 'Alternar modo oscuro / claro',
    'cmd.actThemeHint': 'Modo oscuro obsidian estilo Railway/Linear',
    'cmd.actLang': 'Cambiar idioma (ES ↔ EN)',
    'cmd.actLangHint': 'Traducción instantánea sin recargar la página',
    'cmd.actDomain': 'Conectar un dominio HTTPS',
    'cmd.actDomainHint': 'Proxy, DNS, Wildcard o Túnel CGNAT EdgeTunnel',

    // Settings
    'settings.title': 'Ajustes',
    'settings.subtitle': 'Acceso remoto, seguridad enterprise (2FA/OIDC/Auditoría), apariencia, integraciones, backups y sistema.',
    'settings.tabRemote': 'Acceso remoto',
    'settings.tabTeam': 'Equipo y RBAC',
    'settings.tabSecurity': 'Seguridad',
    'settings.tabGitops': 'GitOps',
    'settings.tabIntegrations': 'Integraciones',
    'settings.tabBackups': 'Backups y DR',
    'settings.tabNotifications': 'Notificaciones',
    'settings.tabSystem': 'Sistema',
    'settings.appearanceTitle': 'Apariencia e Idioma',
    'settings.appearanceDesc': 'Elige el tema visual y el idioma de la interfaz. Se guarda localmente con cambio instantáneo.',
    'settings.themeLabel': 'Tema',
    'settings.themeLight': 'Claro',
    'settings.themeDark': 'Oscuro',
    'settings.themeSystem': 'Sistema',
    'settings.langLabel': 'Idioma',
    'settings.sec2faTitle': 'Autenticación en dos pasos (TOTP 2FA)',
    'settings.sec2faDesc': 'Protege el plano de control con códigos TOTP de 6 dígitos y códigos de recuperación de un solo uso cifrados con AES-256-GCM.',
    'settings.sec2faSetup': 'Configurar 2FA',
    'settings.sec2faReconfig': 'Reconfigurar 2FA',
    'settings.sec2faDisable': 'Desactivar 2FA',
    'settings.secOidcTitle': 'Proveedores SSO (OIDC / OAuth2 PKCE)',
    'settings.secOidcDesc': 'Verificación criptográfica JWKS nativa (RS256/ES256/EdDSA), PKCE S256 obligatorio y mapeo groups → RBAC.',
    'settings.secAuditTitle': 'Registro de auditoría encadenado (SHA-256)',
    'settings.secAuditDesc': 'Cada mutación enlaza su huella criptográfica con la entrada anterior (prevHash → entryHash) para detectar manipulaciones.',
    'settings.secAuditVerify': 'Verificar cadena a prueba de manipulaciones',
    'settings.secAuditVerifying': 'Verificando…',
    'settings.secScannerTitle': 'Escáner de fugas de secretos (Pre-Despliegue)',
    'settings.secScannerDesc': 'Detecta claves AWS, Stripe, GitHub, OpenAI/Anthropic, PEM, JWT, URIs de BD y alta entropía Shannon antes de publicar.',
    'settings.secScannerSample': 'Cargar muestra de prueba',
    'settings.secScannerRun': 'Escanear fugas de secretos',
    'settings.secScannerRunning': 'Escaneando…',

    // ProjectDetail Fast Restart
    'pd.envTitle': 'Variables de entorno',
    'pd.envDirty': 'Cambios sin guardar',
    'pd.envDesc': 'Secretos y configuración inyectados en el entorno de ejecución y despliegue.',
    'pd.envSave': 'Guardar variables',
    'pd.fastBannerTitle': 'Variables guardadas — ¿aplicar sin reconstruir?',
    'pd.fastBannerDesc': 'Fast Restart recrea el contenedor con las nuevas variables en ~1.5s, evitando reconstruir toda la imagen Docker.',
    'pd.fastRestartBtn': 'Fast Restart (~1.5s, sin rebuild)',
    'pd.fastRestarting': 'Reiniciando contenedor…',
    'pd.fullDeployBtn': 'Despliegue completo',
    'pd.fastRestartDone': 'Contenedor reiniciado con nuevas variables en {ms} (sin rebuild)',

    // Spatial Topology
    'topo.title': 'Lienzo espacial de topología y dependencias',
    'topo.subtitle': 'Arrastra y haz zoom sobre el flujo vivo: Dominios/Monitores → Proyectos → Bases de datos / Caché / Catálogo → Servidores.',
    'topo.refresh': 'Actualizar mapa',
    'topo.fit': 'Centrar',
    'topo.building': 'Construyendo mapa de dependencias…',
    'topo.empty': 'Crea tu primer proyecto o base de datos para visualizar su topología de red.',
    'topo.colEdge': 'Dominios y Uptime',
    'topo.colProjects': 'Proyectos',
    'topo.colData': 'Datos y Servicios',
    'topo.colServers': 'Servidores',
    'topo.inspectorTitle': 'Inspector de nodo',
    'topo.inspectorEmpty': 'Haz clic en cualquier nodo del lienzo para inspeccionar su salud, metadatos y enlaces.',
    'topo.inbound': 'Entrantes',
    'topo.outbound': 'Salientes',
    'topo.dragHint': 'Arrastra para mover · Clic en nodo para inspeccionar',
  },
} as const;

export type TranslationKey = keyof typeof MESSAGES.en;

export function translate(
  locale: Locale,
  key: TranslationKey,
  vars?: Record<string, string | number>
): string {
  const dict = MESSAGES[locale] || MESSAGES.en;
  let text: string = dict[key] ?? MESSAGES.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
    }
  }
  return text;
}

export function useI18n() {
  const locale = useSyncExternalStore(subscribe, getLocale, () => 'en' as Locale);
  const t = (key: TranslationKey, vars?: Record<string, string | number>) =>
    translate(locale, key, vars);
  return { locale, setLocale, toggleLocale, t };
}
