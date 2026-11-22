const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { atomicWriteJsonSync } = require('./ssrfGuard');

const CONFIG_FILE = path.join(__dirname, '..', '..', 'data', 'github.json');
const GH_SEGMENT_RE = /^[A-Za-z0-9_.-]{1,100}$/;

function assertGhSegment(value, label) {
  const s = String(value || '').trim();
  if (!GH_SEGMENT_RE.test(s) || s === '.' || s === '..') {
    throw new Error(`${label} de GitHub inválido`);
  }
  return encodeURIComponent(s);
}

/**
 * Ventana durante la cual una entrega repetida se considera la misma entrega.
 *
 * GitHub reintenta una entrega que no conteste 2xx a tiempo, y el botón
 * «Redeliver» del panel de webhooks reenvía el MISMO payload. Diez minutos
 * cubren de sobra ambos casos sin bloquear un redespliegue deliberado del mismo
 * commit (para eso está el botón «Desplegar», que no pasa por aquí).
 */
const DELIVERY_TTL_MS = 10 * 60 * 1000;
const DELIVERY_MAX_ENTRIES = 500;

class GithubService {
  constructor() {
    this.apiBase = 'https://api.github.com';
    this.configFile = CONFIG_FILE;
    this.ensureDataDir();
    this.config = this.loadConfig();

    /**
     * Registro de entregas ya atendidas: clave -> marca de tiempo.
     *
     * En memoria a propósito. Persistirlo protegería contra un reinicio del
     * daemon justo entre dos reintentos de GitHub, que es una ventana de
     * segundos; a cambio habría que escribir en disco en cada push y podar el
     * fichero. El coste de un duplicado tras un reinicio es una build de más,
     * no una corrupción: el despliegue es idempotente por construcción (imagen
     * nueva, salud, conmutación).
     */
    this.deliveries = new Map();

    // Mock data for tests and offline/demo environments
    this.mockUser = {
      login: 'pablo-developer',
      id: 9812401,
      name: 'Pablo Developer',
      avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4',
      html_url: 'https://github.com/pablo-developer',
      bio: 'Arquitecto Cloud & AI Developer',
      public_repos: 12,
      total_private_repos: 6,
      followers: 45,
      following: 28
    };

    this.mockRepos = [
      {
        id: 101,
        name: 'culkibo-frontend',
        full_name: 'pablo-developer/culkibo-frontend',
        owner: { login: 'pablo-developer', avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4' },
        description: 'Dashboard en tiempo real con React, Tailwind CSS y Vite',
        private: false,
        html_url: 'https://github.com/pablo-developer/culkibo-frontend',
        clone_url: 'https://github.com/pablo-developer/culkibo-frontend.git',
        default_branch: 'main',
        language: 'TypeScript',
        stars: 34,
        forks: 5,
        updated_at: '2026-09-11T18:30:00Z'
      },
      {
        id: 102,
        name: 'ai-voice-agent',
        full_name: 'pablo-developer/ai-voice-agent',
        owner: { login: 'pablo-developer', avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4' },
        description: 'Agente de voz autónomo con FastAPI y WebSockets de baja latencia',
        private: false,
        html_url: 'https://github.com/pablo-developer/ai-voice-agent',
        clone_url: 'https://github.com/pablo-developer/ai-voice-agent.git',
        default_branch: 'main',
        language: 'Python',
        stars: 88,
        forks: 14,
        updated_at: '2026-09-12T05:15:00Z'
      },
      {
        id: 103,
        name: 'nextjs-saas-starter',
        full_name: 'pablo-developer/nextjs-saas-starter',
        owner: { login: 'pablo-developer', avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4' },
        description: 'Plantilla de aplicación SaaS con autenticación y base de datos',
        private: true,
        html_url: 'https://github.com/pablo-developer/nextjs-saas-starter',
        clone_url: 'https://github.com/pablo-developer/nextjs-saas-starter.git',
        default_branch: 'main',
        language: 'TypeScript',
        stars: 19,
        forks: 2,
        updated_at: '2026-09-10T12:00:00Z'
      },
      {
        id: 104,
        name: 'docker-edge-proxy',
        full_name: 'pablo-developer/docker-edge-proxy',
        owner: { login: 'pablo-developer', avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4' },
        description: 'Proxy inverso ultrarrápido empaquetado en Dockerfile multietapa',
        private: true,
        html_url: 'https://github.com/pablo-developer/docker-edge-proxy',
        clone_url: 'https://github.com/pablo-developer/docker-edge-proxy.git',
        default_branch: 'master',
        language: 'Dockerfile',
        stars: 7,
        forks: 0,
        updated_at: '2026-09-08T09:20:00Z'
      },
      {
        id: 105,
        name: 'api-express-microservice',
        full_name: 'pablo-developer/api-express-microservice',
        owner: { login: 'pablo-developer', avatar_url: 'https://avatars.githubusercontent.com/u/9812401?v=4' },
        description: 'Microservicio RESTful en Node.js con Express y SQLite',
        private: false,
        html_url: 'https://github.com/pablo-developer/api-express-microservice',
        clone_url: 'https://github.com/pablo-developer/api-express-microservice.git',
        default_branch: 'main',
        language: 'JavaScript',
        stars: 12,
        forks: 1,
        updated_at: '2026-09-07T14:45:00Z'
      }
    ];

    this.mockBranches = {
      default: [
        { name: 'main', commitSha: 'a1b2c3d', protected: true },
        { name: 'dev', commitSha: 'e4f5a6b', protected: false },
        { name: 'staging', commitSha: '7c8d9e0', protected: false }
      ]
    };
  }

  // -------------------------------------------------------------------------
  // Idempotencia de webhooks
  // -------------------------------------------------------------------------

  /** Elimina del registro las entregas que ya han caducado. */
  pruneDeliveries(now = Date.now()) {
    for (const [key, at] of this.deliveries) {
      if (now - at > DELIVERY_TTL_MS) this.deliveries.delete(key);
    }
    // Tope duro: un atacante con la firma correcta (o un repositorio muy
    // activo) no puede hacer crecer el mapa sin límite.
    while (this.deliveries.size > DELIVERY_MAX_ENTRIES) {
      const oldest = this.deliveries.keys().next().value;
      if (oldest === undefined) break;
      this.deliveries.delete(oldest);
    }
  }

  /**
   * Reclama una entrega de webhook. Devuelve `{ fresh: true }` la primera vez y
   * `{ fresh: false, reason }` en cualquier reentrega dentro de la ventana.
   *
   * Se comprueban DOS claves porque GitHub reentrega de dos formas distintas:
   *
   *   - un reintento automático repite la cabecera `X-GitHub-Delivery`;
   *   - el botón «Redeliver» del panel genera un GUID nuevo con el mismo
   *     payload, así que el GUID no basta y hay que mirar también el commit.
   *
   * Sin esto, dos entregas del mismo push arrancan dos builds del mismo commit
   * a la vez: la segunda encuentra el bloqueo del proyecto, falla, y el
   * historial se llena de despliegues «fallidos» que nunca lo fueron.
   *
   * @param {string} projectId
   * @param {{deliveryId?: string | null, commitSha?: string | null}} identity
   */
  claimDelivery(projectId, { deliveryId = null, commitSha = null } = {}) {
    const now = Date.now();
    this.pruneDeliveries(now);

    /** @type {string[]} */
    const keys = [];
    if (deliveryId) keys.push(`${projectId}:entrega:${String(deliveryId).slice(0, 100)}`);
    if (commitSha) keys.push(`${projectId}:commit:${String(commitSha).toLowerCase().slice(0, 40)}`);

    // Sin ninguna de las dos no hay forma de identificar la entrega: se deja
    // pasar, porque bloquear por defecto sería peor que una build repetida.
    if (keys.length === 0) return { fresh: true, reason: null };

    for (const key of keys) {
      const seenAt = this.deliveries.get(key);
      if (seenAt !== undefined && now - seenAt <= DELIVERY_TTL_MS) {
        const seconds = Math.round((now - seenAt) / 1000);
        return {
          fresh: false,
          reason: `Entrega duplicada: este push ya se atendió hace ${seconds} s`
        };
      }
    }

    for (const key of keys) this.deliveries.set(key, now);
    return { fresh: true, reason: null };
  }

  /** Olvida lo registrado para un proyecto. Lo usan las pruebas y el borrado. */
  forgetDeliveries(projectId = null) {
    if (!projectId) {
      this.deliveries.clear();
      return;
    }
    for (const key of [...this.deliveries.keys()]) {
      if (key.startsWith(`${projectId}:`)) this.deliveries.delete(key);
    }
  }

  ensureDataDir() {
    const dir = path.dirname(this.configFile);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  loadConfig() {
    try {
      if (fs.existsSync(this.configFile)) {
        const raw = fs.readFileSync(this.configFile, 'utf8');
        return JSON.parse(raw);
      }
    } catch (err) {
      console.error('Error cargando configuración de GitHub:', err.message);
    }
    return { token: null, user: null, connectedAt: null };
  }

  saveConfig(data) {
    this.ensureDataDir();
    atomicWriteJsonSync(this.configFile, data, 0o600);
    this.config = data;
    return this.config;
  }

  isMockToken(token) {
    if (!token) return false;
    const t = token.trim();
    return (
      t.startsWith('mock_') ||
      t.startsWith('test_') ||
      t.startsWith('ghp_mock') ||
      t === 'valid_github_pat_token' ||
      t === 'test-token'
    );
  }

  async verifyToken(token) {
    if (!token || typeof token !== 'string' || token.trim().length === 0) {
      throw new Error('El token de GitHub es obligatorio');
    }

    const cleanToken = token.trim();

    if (this.isMockToken(cleanToken)) {
      return { ...this.mockUser };
    }

    try {
      const res = await axios.get(`${this.apiBase}/user`, {
        headers: {
          Authorization: `Bearer ${cleanToken}`,
          'User-Agent': 'Culkibo-Cloud/1.0.0',
          Accept: 'application/vnd.github.v3+json'
        },
        timeout: 8000
      });

      return {
        login: res.data.login,
        id: res.data.id,
        name: res.data.name || res.data.login,
        avatar_url: res.data.avatar_url,
        html_url: res.data.html_url,
        bio: res.data.bio || '',
        public_repos: res.data.public_repos || 0,
        total_private_repos: res.data.total_private_repos || 0,
        followers: res.data.followers || 0,
        following: res.data.following || 0
      };
    } catch (err) {
      const status = err.response?.status;
      if (status === 401) {
        throw new Error('Token de GitHub inválido o caducado (401 Unauthorized)');
      }
      if (status === 403) {
        throw new Error('Token sin permisos suficientes o límite de peticiones alcanzado (403 Forbidden)');
      }
      throw new Error(`Error al verificar token con GitHub: ${err.response?.data?.message || err.message}`);
    }
  }

  async connect(token) {
    const user = await this.verifyToken(token);
    const configData = {
      token: token.trim(),
      user,
      connectedAt: new Date().toISOString()
    };
    this.saveConfig(configData);
    return { success: true, user };
  }

  async disconnect() {
    const configData = { token: null, user: null, connectedAt: null };
    if (fs.existsSync(this.configFile)) {
      try {
        fs.unlinkSync(this.configFile);
      } catch (e) {
        this.saveConfig(configData);
      }
    }
    this.config = configData;
    return { success: true };
  }

  getStatus() {
    const isConnected = Boolean(this.config && this.config.token && this.config.user);
    /** @type {string | null} */
    let tokenMasked = null;
    if (isConnected && this.config.token) {
      const t = this.config.token;
      if (t.length > 8) {
        tokenMasked = `${t.substring(0, 4)}••••${t.substring(t.length - 4)}`;
      } else {
        tokenMasked = '••••••••';
      }
    }
    return {
      connected: isConnected,
      user: isConnected ? this.config.user : null,
      tokenMasked,
      connectedAt: this.config?.connectedAt || null
    };
  }

  getHeaders() {
    if (!this.config || !this.config.token) {
      throw new Error('Cuenta de GitHub no conectada. Conecta tu token primero.');
    }
    return {
      Authorization: `Bearer ${this.config.token}`,
      'User-Agent': 'Culkibo-Cloud/1.0.0',
      Accept: 'application/vnd.github.v3+json'
    };
  }

  async getRepositories({ page = 1, perPage = 30, search = '', sort = 'updated' } = {}) {
    if (!this.config || !this.config.token) {
      throw new Error('Cuenta de GitHub no conectada. Conecta tu token primero.');
    }

    if (this.isMockToken(this.config.token)) {
      let filtered = [...this.mockRepos];
      if (search) {
        const q = search.toLowerCase().trim();
        filtered = filtered.filter(r =>
          r.name.toLowerCase().includes(q) ||
          r.full_name.toLowerCase().includes(q) ||
          (r.description && r.description.toLowerCase().includes(q)) ||
          (r.language && r.language.toLowerCase().includes(q))
        );
      }
      const pageNum = parseInt(String(page), 10) || 1;
      const limit = parseInt(String(perPage), 10) || 30;
      const startIdx = (pageNum - 1) * limit;
      const paged = filtered.slice(startIdx, startIdx + limit);
      return {
        repos: paged,
        total: filtered.length,
        page: pageNum,
        perPage: limit
      };
    }

    const pageNum = parseInt(String(page), 10) || 1;
    const limit = parseInt(String(perPage), 10) || 30;

    // If searching on real GitHub, try Search API across all user's repos
    if (search && this.config.user?.login) {
      try {
        const q = `${search.trim()} user:${this.config.user.login} fork:true`;
        const searchRes = await axios.get(`${this.apiBase}/search/repositories`, {
          headers: this.getHeaders(),
          params: {
            q,
            sort: sort === 'updated' ? 'updated' : 'stars',
            order: 'desc',
            page: pageNum,
            per_page: limit
          },
          timeout: 10000
        });

        const mapped = (searchRes.data.items || []).map(r => ({
          id: r.id,
          name: r.name,
          full_name: r.full_name,
          owner: {
            login: r.owner?.login || '',
            avatar_url: r.owner?.avatar_url || ''
          },
          description: r.description || '',
          private: Boolean(r.private),
          html_url: r.html_url,
          clone_url: r.clone_url,
          default_branch: r.default_branch || 'main',
          language: r.language || 'Code',
          stars: r.stargazers_count || 0,
          forks: r.forks_count || 0,
          updated_at: r.updated_at
        }));

        return {
          repos: mapped,
          total: searchRes.data.total_count || mapped.length,
          page: pageNum,
          perPage: limit
        };
      } catch (searchErr) {
        // Fallback to user/repos if search API is rate limited or unavailable
      }
    }

    try {
      const res = await axios.get(`${this.apiBase}/user/repos`, {
        headers: this.getHeaders(),
        params: {
          page: pageNum,
          per_page: limit,
          sort,
          affiliation: 'owner,collaborator,organization_member'
        },
        timeout: 10000
      });

      let mapped = res.data.map(r => ({
        id: r.id,
        name: r.name,
        full_name: r.full_name,
        owner: {
          login: r.owner?.login || '',
          avatar_url: r.owner?.avatar_url || ''
        },
        description: r.description || '',
        private: Boolean(r.private),
        html_url: r.html_url,
        clone_url: r.clone_url,
        default_branch: r.default_branch || 'main',
        language: r.language || 'Code',
        stars: r.stargazers_count || 0,
        forks: r.forks_count || 0,
        updated_at: r.updated_at
      }));

      if (search) {
        const q = search.toLowerCase().trim();
        mapped = mapped.filter(r =>
          r.name.toLowerCase().includes(q) ||
          r.full_name.toLowerCase().includes(q) ||
          (r.description && r.description.toLowerCase().includes(q)) ||
          (r.language && r.language.toLowerCase().includes(q))
        );
      }

      return {
        repos: mapped,
        total: mapped.length,
        page: pageNum,
        perPage: limit
      };
    } catch (err) {
      throw new Error(`Error obteniendo repositorios de GitHub: ${err.response?.data?.message || err.message}`);
    }
  }

  async getBranches(owner, repo) {
    if (!this.config || !this.config.token) {
      throw new Error('Cuenta de GitHub no conectada. Conecta tu token primero.');
    }

    if (this.isMockToken(this.config.token)) {
      return this.mockBranches[repo] || this.mockBranches.default;
    }

    try {
      const safeOwner = assertGhSegment(owner, 'Propietario');
      const safeRepo = assertGhSegment(repo, 'Repositorio');
      const res = await axios.get(`${this.apiBase}/repos/${safeOwner}/${safeRepo}/branches`, {
        headers: this.getHeaders(),
        params: { per_page: 100 },
        timeout: 10000
      });

      return res.data.map(b => ({
        name: b.name,
        commitSha: b.commit?.sha || '',
        protected: Boolean(b.protected)
      }));
    } catch (err) {
      throw new Error(`Error obteniendo ramas de ${owner}/${repo}: ${err.response?.data?.message || err.message}`);
    }
  }

  async autoDetectRepo(owner, repo, branch = 'main') {
    if (!this.config || !this.config.token) {
      throw new Error('Cuenta de GitHub no conectada. Conecta tu token primero.');
    }

    // Mock detection logic
    if (this.isMockToken(this.config.token)) {
      const lower = `${owner}/${repo}`.toLowerCase();
      if (lower.includes('compose')) {
        return {
          detected: true,
          framework: 'Docker Compose',
          language: 'Docker Compose',
          buildCommand: 'docker compose build',
          startCommand: 'docker compose up -d',
          port: 8080,
          icon: '🐳',
          baseDirectory: '/',
          watchPaths: ['docker-compose.yml', 'compose.yaml'],
          envVars: {},
          confidence: 'high'
        };
      }
      if (lower.includes('astro')) {
        return {
          detected: true,
          framework: 'Astro',
          language: 'TypeScript',
          buildCommand: 'npm run build',
          startCommand: 'npm run preview',
          port: 4321,
          icon: '🚀',
          baseDirectory: '/',
          watchPaths: ['src/**', 'public/**'],
          envVars: { NODE_ENV: 'production' },
          confidence: 'high'
        };
      }
      if (lower.includes('svelte')) {
        return {
          detected: true,
          framework: 'SvelteKit',
          language: 'TypeScript',
          buildCommand: 'npm run build',
          startCommand: 'npm run preview',
          port: 5173,
          icon: '🔥',
          baseDirectory: '/',
          watchPaths: ['src/**', 'static/**'],
          envVars: { NODE_ENV: 'production' },
          confidence: 'high'
        };
      }
      if (lower.includes('rust') || lower.includes('cargo')) {
        return {
          detected: true,
          framework: 'Rust',
          language: 'Rust',
          buildCommand: 'cargo build --release',
          startCommand: './target/release/app',
          port: 8080,
          icon: '🦀',
          baseDirectory: '/',
          watchPaths: ['src/**', 'Cargo.toml'],
          envVars: {},
          confidence: 'high'
        };
      }
      if (lower.includes('frontend') || lower.includes('react') || lower.includes('vite')) {
        return {
          detected: true,
          framework: 'React (Vite)',
          language: 'TypeScript',
          buildCommand: 'npm run build',
          startCommand: 'npm run preview',
          port: 5173,
          icon: '⚡',
          baseDirectory: '/',
          watchPaths: ['src/**', 'public/**'],
          envVars: { NODE_ENV: 'production' },
          confidence: 'high'
        };
      }
      if (lower.includes('django')) {
        return {
          detected: true,
          framework: 'Python Django',
          language: 'Python',
          buildCommand: 'pip install -r requirements.txt',
          startCommand: 'python manage.py runserver 0.0.0.0:8000',
          port: 8000,
          icon: '🐍',
          baseDirectory: '/',
          watchPaths: ['**/*.py'],
          envVars: { PYTHONUNBUFFERED: '1' },
          confidence: 'high'
        };
      }
      if (lower.includes('voice') || lower.includes('ai') || lower.includes('fastapi') || lower.includes('python')) {
        return {
          detected: true,
          framework: 'Python FastAPI',
          language: 'Python',
          buildCommand: 'pip install -r requirements.txt',
          startCommand: 'uvicorn main:app --host 0.0.0.0 --port 8000',
          port: 8000,
          icon: '🔥',
          baseDirectory: '/',
          watchPaths: ['app/**', '*.py'],
          envVars: { PYTHONUNBUFFERED: '1' },
          confidence: 'high'
        };
      }
      if (lower.includes('next') || lower.includes('saas')) {
        return {
          detected: true,
          framework: 'Next.js',
          language: 'TypeScript',
          buildCommand: 'npm run build',
          startCommand: 'npm start',
          port: 3000,
          icon: '▲',
          baseDirectory: '/',
          watchPaths: ['app/**', 'components/**', 'pages/**'],
          envVars: { NODE_ENV: 'production' },
          confidence: 'high'
        };
      }
      if (lower.includes('docker') || lower.includes('proxy')) {
        return {
          detected: true,
          framework: 'Dockerfile',
          language: 'Docker',
          buildCommand: 'docker build -t app .',
          startCommand: 'docker run -p 8080:8080 app',
          port: 8080,
          icon: '🐳',
          baseDirectory: '/',
          watchPaths: ['Dockerfile', 'nginx.conf'],
          envVars: {},
          confidence: 'high'
        };
      }
      return {
        detected: true,
        framework: 'Node.js (Express)',
        language: 'JavaScript',
        buildCommand: 'npm run build',
        startCommand: 'node index.js',
        port: 3000,
        icon: '🚀',
        baseDirectory: '/',
        watchPaths: ['src/**', 'server/**', '*.js'],
        envVars: { NODE_ENV: 'production', PORT: '3000' },
        confidence: 'high'
      };
    }

    try {
      const safeOwner = assertGhSegment(owner, 'Propietario');
      const safeRepo = assertGhSegment(repo, 'Repositorio');
      // 1. Check root directory contents
      const contentsRes = await axios.get(`${this.apiBase}/repos/${safeOwner}/${safeRepo}/contents`, {
        headers: this.getHeaders(),
        params: { ref: branch },
        timeout: 10000
      });

      const fileNames = contentsRes.data.map(f => f.name.toLowerCase());

      // 2. Check for Docker Compose
      if (fileNames.includes('docker-compose.yml') || fileNames.includes('docker-compose.yaml') || fileNames.includes('compose.yaml') || fileNames.includes('compose.yml')) {
        return {
          detected: true,
          framework: 'Docker Compose',
          language: 'Docker Compose',
          buildCommand: 'docker compose build',
          startCommand: 'docker compose up -d',
          port: 8080,
          icon: '🐳',
          baseDirectory: '/',
          watchPaths: ['docker-compose.yml', 'compose.yaml', 'src/**'],
          envVars: {},
          confidence: 'high'
        };
      }

      // 3. Check for package.json
      if (fileNames.includes('package.json')) {
        try {
          const pkgRes = await axios.get(`${this.apiBase}/repos/${safeOwner}/${safeRepo}/contents/package.json`, {
            headers: this.getHeaders(),
            params: { ref: branch },
            timeout: 10000
          });

          const rawContent = Buffer.from(pkgRes.data.content, 'base64').toString('utf8');
          const pkg = JSON.parse(rawContent);
          const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
          const scripts = pkg.scripts || {};

          // Next.js
          if (deps['next']) {
            return {
              detected: true,
              framework: 'Next.js',
              language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'next build',
              startCommand: scripts['start'] ? 'npm start' : 'next start',
              port: 3000,
              icon: '▲',
              baseDirectory: '/',
              watchPaths: ['app/**', 'pages/**', 'components/**'],
              envVars: { NODE_ENV: 'production' },
              confidence: 'high'
            };
          }

          // Astro
          if (deps['astro']) {
            return {
              detected: true,
              framework: 'Astro',
              language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'astro build',
              startCommand: scripts['preview'] ? 'npm run preview' : (scripts['dev'] ? 'npm run dev' : 'npm start'),
              port: 4321,
              icon: '🚀',
              baseDirectory: '/',
              watchPaths: ['src/**', 'public/**'],
              envVars: { NODE_ENV: 'production' },
              confidence: 'high'
            };
          }

          // Svelte / SvelteKit
          if (deps['svelte'] || deps['@sveltejs/kit']) {
            return {
              detected: true,
              framework: 'SvelteKit',
              language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'npm run build',
              startCommand: scripts['preview'] ? 'npm run preview' : (scripts['dev'] ? 'npm run dev' : 'node build'),
              port: 5173,
              icon: '🔥',
              baseDirectory: '/',
              watchPaths: ['src/**', 'static/**'],
              envVars: { NODE_ENV: 'production' },
              confidence: 'high'
            };
          }

          // NestJS
          if (deps['@nestjs/core']) {
            return {
              detected: true,
              framework: 'NestJS',
              language: 'TypeScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'npm run build',
              startCommand: scripts['start:prod'] ? 'npm run start:prod' : 'npm start',
              port: 3000,
              icon: '🦁',
              baseDirectory: '/',
              watchPaths: ['src/**', '*.ts'],
              envVars: { NODE_ENV: 'production', PORT: '3000' },
              confidence: 'high'
            };
          }

          // Vite / React
          if (deps['vite'] || deps['react']) {
            return {
              detected: true,
              framework: deps['vite'] ? 'React (Vite)' : 'React App',
              language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'npm run build',
              startCommand: scripts['preview'] ? 'npm run preview' : (scripts['dev'] ? 'npm run dev' : 'npm start'),
              port: deps['vite'] ? 5173 : 3000,
              icon: '⚡',
              baseDirectory: '/',
              watchPaths: ['src/**', 'public/**'],
              envVars: { NODE_ENV: 'production' },
              confidence: 'high'
            };
          }

          // Vue / Nuxt
          if (deps['nuxt'] || deps['vue']) {
            return {
              detected: true,
              framework: deps['nuxt'] ? 'Nuxt' : 'Vue.js',
              language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
              buildCommand: scripts['build'] ? 'npm run build' : 'npm run build',
              startCommand: scripts['start'] ? 'npm start' : (scripts['dev'] ? 'npm run dev' : 'npm start'),
              port: 3000,
              icon: '💚',
              baseDirectory: '/',
              watchPaths: ['src/**', 'pages/**', 'components/**'],
              envVars: { NODE_ENV: 'production' },
              confidence: 'high'
            };
          }

          // Express / Generic Node
          return {
            detected: true,
            framework: deps['express'] ? 'Node.js (Express)' : 'Node.js',
            language: deps['typescript'] ? 'TypeScript' : 'JavaScript',
            buildCommand: scripts['build'] ? 'npm run build' : '',
            startCommand: scripts['start'] ? 'npm start' : (scripts['dev'] ? 'npm run dev' : 'node index.js'),
            port: 3000,
            icon: '🚀',
            baseDirectory: '/',
            watchPaths: ['src/**', '*.js', '*.ts'],
            envVars: { NODE_ENV: 'production', PORT: '3000' },
            confidence: 'high'
          };
        } catch (e) {
          // fallback to generic node
          return {
            detected: true,
            framework: 'Node.js',
            language: 'JavaScript',
            buildCommand: 'npm run build',
            startCommand: 'npm start',
            port: 3000,
            icon: '🚀',
            baseDirectory: '/',
            watchPaths: ['src/**'],
            confidence: 'medium'
          };
        }
      }

      // 4. Check for Dockerfile
      if (fileNames.includes('dockerfile')) {
        return {
          detected: true,
          framework: 'Dockerfile',
          language: 'Docker',
          buildCommand: 'docker build -t app .',
          startCommand: 'docker run -p 8080:8080 app',
          port: 8080,
          icon: '🐳',
          baseDirectory: '/',
          watchPaths: ['Dockerfile', 'src/**'],
          envVars: {},
          confidence: 'high'
        };
      }

      // 5. Check for Python
      if (fileNames.includes('requirements.txt') || fileNames.includes('pyproject.toml') || fileNames.includes('pipfile')) {
        let isFastApi = fileNames.includes('main.py');
        let isDjango = fileNames.includes('manage.py');
        let isFlask = fileNames.includes('app.py');

        if (isDjango) {
          return {
            detected: true,
            framework: 'Python Django',
            language: 'Python',
            buildCommand: 'pip install -r requirements.txt',
            startCommand: 'python manage.py runserver 0.0.0.0:8000',
            port: 8000,
            icon: '🐍',
            baseDirectory: '/',
            watchPaths: ['**/*.py'],
            envVars: { PYTHONUNBUFFERED: '1' },
            confidence: 'high'
          };
        }

        if (isFlask) {
          return {
            detected: true,
            framework: 'Python Flask',
            language: 'Python',
            buildCommand: 'pip install -r requirements.txt',
            startCommand: 'flask run --host=0.0.0.0 --port=5000',
            port: 5000,
            icon: '🐍',
            baseDirectory: '/',
            watchPaths: ['**/*.py'],
            envVars: { PYTHONUNBUFFERED: '1' },
            confidence: 'high'
          };
        }

        return {
          detected: true,
          framework: isFastApi ? 'Python FastAPI' : 'Python',
          language: 'Python',
          buildCommand: 'pip install -r requirements.txt',
          startCommand: isFastApi ? 'uvicorn main:app --host 0.0.0.0 --port 8000' : 'python app.py',
          port: 8000,
          icon: '🐍',
          baseDirectory: '/',
          watchPaths: ['**/*.py'],
          envVars: { PYTHONUNBUFFERED: '1' },
          confidence: 'high'
        };
      }

      // 6. Check for Rust (Cargo.toml)
      if (fileNames.includes('cargo.toml')) {
        return {
          detected: true,
          framework: 'Rust',
          language: 'Rust',
          buildCommand: 'cargo build --release',
          startCommand: './target/release/app',
          port: 8080,
          icon: '🦀',
          baseDirectory: '/',
          watchPaths: ['src/**', 'Cargo.toml'],
          envVars: {},
          confidence: 'high'
        };
      }

      // 7. Check for Go
      if (fileNames.includes('go.mod')) {
        return {
          detected: true,
          framework: 'Go',
          language: 'Go',
          buildCommand: 'go build -o app',
          startCommand: './app',
          port: 8080,
          icon: '🔷',
          baseDirectory: '/',
          watchPaths: ['**/*.go'],
          confidence: 'high'
        };
      }

      // 8. Check for Static HTML
      if (fileNames.includes('index.html')) {
        return {
          detected: true,
          framework: 'HTML Estático',
          language: 'HTML/CSS/JS',
          buildCommand: '',
          startCommand: 'npx serve -s .',
          port: 3000,
          icon: '🌐',
          baseDirectory: '/',
          watchPaths: ['**/*.html', '**/*.css', '**/*.js'],
          confidence: 'high'
        };
      }

      // Generic fallback
      return {
        detected: true,
        framework: 'General',
        language: 'Desconocido',
        buildCommand: '',
        startCommand: '',
        port: 8080,
        icon: '📦',
        baseDirectory: '/',
        watchPaths: ['**/*'],
        confidence: 'low'
      };
    } catch (err) {
      throw new Error(`Error en autodetección del repositorio ${owner}/${repo}: ${err.response?.data?.message || err.message}`);
    }
  }
}

module.exports = new GithubService();
