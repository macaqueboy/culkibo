const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const Project = require('../models/Project');
const containerOrchestrator = require('./containerOrchestrator');

class ProjectManager extends EventEmitter {
  constructor() {
    super();
    this.dataPath = path.join(__dirname, '..', '..', 'data', 'projects.json');
    this.projects = new Map();
    this.savingPromise = null;
    this.pendingSave = false;
    this._lastBackupAt = 0;
    /** @type {Promise<void> | null} */
    this._inFlightFlush = null;
    /** @type {Promise<void> | null} */
    this._queuedFlush = null;
    /** @type {Promise<void> | null} */
    this._batchingFlush = null;
    /** @type {Buffer | null} */
    this._serializedAll = null;
    this._version = 1;
    /** @type {Map<string, { str: string, buf: Buffer, etag: string }>} */
    this._projectJsonCache = new Map();
    this.ensureDataDir();
    this.loadProjects();
  }

  ensureDataDir() {
    const dir = path.dirname(this.dataPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  readProjectsFile(filePath) {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) throw new Error(`${path.basename(filePath)} está vacío`);
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error(`${path.basename(filePath)} no contiene un array`);
    return parsed;
  }

  /**
   * Borra los temporales que deja un flush interrumpido.
   *
   * `flushToDisk()` escribe en `projects.json.<marca>.tmp` y luego renombra. Si
   * el proceso muere entre ambos pasos, el temporal se queda ahí para siempre.
   * Uno no molesta; cientos, tras meses de reinicios, sí.
   */
  cleanStaleTempFiles() {
    try {
      const dir = path.dirname(this.dataPath);
      const base = path.basename(this.dataPath);
      let removed = 0;
      for (const file of fs.readdirSync(dir)) {
        if (file.startsWith(`${base}.`) && file.endsWith('.tmp')) {
          try { fs.unlinkSync(path.join(dir, file)); removed++; } catch (e) {}
        }
      }
      if (removed > 0) {
        console.log(`[ProjectManager] Eliminados ${removed} temporales huérfanos de un guardado interrumpido`);
      }
    } catch (e) {}
  }

  loadProjects() {
    this.cleanStaleTempFiles();
    if (fs.existsSync(this.dataPath)) {
      /** @type {any[] | null} */
      let data = null;
      try {
        data = this.readProjectsFile(this.dataPath);
      } catch (err) {
        console.error('Error loading projects:', err.message);
        // Fall back to the last known-good snapshot written by flushToDisk().
        const backupPath = `${this.dataPath}.bak`;
        if (fs.existsSync(backupPath)) {
          try {
            data = this.readProjectsFile(backupPath);
            console.warn(`[ProjectManager] Restaurados ${data.length} proyectos desde ${path.basename(backupPath)}`);
          } catch (backupErr) {
            console.error('Error loading backup projects:', backupErr.message);
          }
        }
      }

      if (data) {
        data.forEach(p => {
          // Boot sanitation: no project may come back claiming a live process.
          // The OS killed every child when the previous daemon exited.
          p.localRunning = false;
          this.projects.set(p.id, new Project(p));
        });
      }
    } else {
      // Default demo project
      const demo = new Project({
        name: 'Mi Primera App',
        description: 'Proyecto de demostración generado automáticamente.',
        icon: '🚀'
      });
      this.projects.set(demo.id, demo);
      this.saveProjects();
    }
  }

  /** @param {string | null} [changedId] */
  invalidateCache(changedId = null) {
    this._serializedAll = null;
    this._version++;
    if (changedId) this._projectJsonCache.delete(changedId);
    else this._projectJsonCache.clear();
  }

  /** @param {string | null} [changedId] */
  saveProjects(changedId = null) {
    this.invalidateCache(changedId);
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
    }
    this.saveDebounceTimer = setTimeout(async () => {
      this.saveDebounceTimer = null;
      await this.flushToDisk(changedId);
    }, 15);
    if (this.saveDebounceTimer.unref) {
      this.saveDebounceTimer.unref();
    }
  }

  /**
   * Garantiza que el estado actual llega a disco, y devuelve una promesa que
   * resuelve cuando lo ha hecho.
   *
   * La versión anterior hacía `if (this.isFlushing) { this.pendingFlush = true;
   * return; }`: si ya había una escritura en vuelo, la segunda llamada volvía
   * inmediatamente sin haber escrito nada. El llamante creía que el estado
   * estaba persistido cuando aún no lo estaba, y como `stop()` lanza el flush
   * sin esperarlo, una lectura inmediata de projects.json podía devolver el
   * estado anterior. Se manifestaba como un test intermitente, que es la peor
   * forma de manifestarse: parece mala suerte, no un fallo.
   *
   * Ahora las escrituras se encadenan. Cada llamada obtiene la promesa de una
   * escritura que ocurre DESPUÉS de ella, así que esperarla siempre significa
   * "mi cambio está en disco".
   */
  /** @param {string | null} [changedId] */
  flushToDisk(changedId = null) {
    this.invalidateCache(changedId);
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
      this.saveDebounceTimer = null;
    }

    // Group Commit (fase 1): agrupa en el mismo turno del bucle de eventos
    // (`setImmediate`, sin el tick de 15.6 ms de Windows) todas las mutaciones
    // concurrentes en UNA sola escritura atómica a disco.
    if (!this._inFlightFlush) {
      if (!this._batchingFlush) {
        this._batchingFlush = new Promise((resolve) => {
          setImmediate(() => {
            this._batchingFlush = null;
            const p = this.writeSnapshot().finally(() => {
              if (this._inFlightFlush === p) this._inFlightFlush = null;
            });
            this._inFlightFlush = p;
            this.flushChain = p;
            resolve(p);
          });
        });
        this.flushChain = this._batchingFlush;
      }
      return this._batchingFlush;
    }

    // Group Commit (fase 2): ya hay una escritura en curso que pudo capturar
    // `this.projects` antes de esta mutación. Todos los llamantes concurrentes
    // que lleguen durante esta escritura comparten UNA única escritura posterior.
    if (!this._queuedFlush) {
      const next = this._inFlightFlush
        .catch(() => {})
        .then(() => {
          this._queuedFlush = null;
          const p = this.writeSnapshot().finally(() => {
            if (this._inFlightFlush === p) this._inFlightFlush = null;
          });
          this._inFlightFlush = p;
          return p;
        });
      this._queuedFlush = next;
      this.flushChain = next;
    }

    return this._queuedFlush;
  }

  /** Escritura atómica de una instantánea. La llama solo `flushToDisk()`. */
  async writeSnapshot() {
    /** @type {string | null} */
    let tempPath = null;
    try {
      // Reutilizar la caché JSON incremental en lugar de volver a ejecutar
      // `JSON.stringify(data, null, 2)` en el bucle de eventos bajo ráfagas.
      const buf = this.getAllSerialized();
      if (!buf || buf.length < 2) {
        throw new Error('Serialización de proyectos vacía; se aborta la escritura');
      }

      tempPath = `${this.dataPath}.${Date.now()}_${Math.random().toString(36).slice(2)}.tmp`;
      await fs.promises.writeFile(tempPath, buf, { mode: 0o600 });

      // Verify exact byte count landed on disk without re-parsing hundreds of KB on the event loop.
      const st = await fs.promises.stat(tempPath);
      if (st.size !== buf.length) {
        throw new Error(`El archivo temporal no coincide en tamaño (${st.size} != ${buf.length})`);
      }

      // On Windows, rename() throws EPERM/EBUSY while another handle (an editor,
      // an antivirus scan, a concurrent reader) holds the destination open. That
      // is transient, so retry before resorting to copyFile — which truncates the
      // destination first and is the one path that can leave a 0-byte file.
      let renamed = false;
      /** @type {any} */
      let lastErr = null;
      for (let attempt = 0; attempt < 5 && !renamed; attempt++) {
        try {
          await fs.promises.rename(tempPath, this.dataPath);
          renamed = true;
        } catch (renameErr) {
          lastErr = renameErr;
          await new Promise(r => setTimeout(r, 20 * (attempt + 1)));
        }
      }

      if (!renamed) {
        console.warn('[ProjectManager] rename() falló tras 5 intentos, usando copyFile:', lastErr && lastErr.message);
        await fs.promises.copyFile(tempPath, this.dataPath);
        try { await fs.promises.unlink(tempPath); } catch(e) {}
      }
      try { await fs.promises.chmod(this.dataPath, 0o600); } catch (e) {}
      tempPath = null;

      // Refresh the .bak recovery snapshot in the background (throttled) so
      // concurrent HTTP writes never stall waiting on a duplicate disk copy.
      const now = Date.now();
      if (now - this._lastBackupAt > 5000) {
        this._lastBackupAt = now;
        try {
          await fs.promises.copyFile(this.dataPath, `${this.dataPath}.bak`);
          await fs.promises.chmod(`${this.dataPath}.bak`, 0o600).catch(() => {});
        } catch (e) {}
      }
    } catch (err) {
      console.error('Error flushing projects to disk:', err);
      if (tempPath) {
        try { await fs.promises.unlink(tempPath); } catch (e) {}
      }
    }
  }

  getAll() {
    return Array.from(this.projects.values());
  }

  /**
   * Buffer JSON pre-serializado de `getAll()`, invalidado en cada mutación.
   * Evita repetir `JSON.stringify` de cientos de KB bajo lecturas concurrentes.
   * @returns {Buffer}
   */
  getAllSerialized() {
    if (!this._serializedAll) {
      /** @type {string[]} */
      const parts = [];
      for (const [id, proj] of this.projects.entries()) {
        let entry = this._projectJsonCache.get(id);
        if (entry === undefined) {
          const str = JSON.stringify(proj);
          const buf = Buffer.from(str, 'utf8');
          entry = { str, buf, etag: `W/"p-${id}-${this._version}-${buf.length}"` };
          this._projectJsonCache.set(id, entry);
        }
        parts.push(entry.str);
      }
      this._serializedAll = Buffer.from(`[${parts.join(',')}]`, 'utf8');
    }
    return this._serializedAll;
  }

  getAllEtag() {
    const buf = this.getAllSerialized();
    return `W/"pa-${this._version}-${buf.length}"`;
  }

  getById(id) {
    return this.projects.get(id);
  }

  /**
   * Entrada JSON pre-serializada `{ str, buf, etag }` por proyecto (O(1) en lecturas repetidas).
   * @param {string} id
   * @returns {{ str: string, buf: Buffer, etag: string } | null}
   */
  getByIdSerializedEntry(id) {
    const proj = this.projects.get(id);
    if (!proj) return null;
    let cached = this._projectJsonCache.get(id);
    if (cached === undefined) {
      const str = JSON.stringify(proj);
      const buf = Buffer.from(str, 'utf8');
      cached = { str, buf, etag: `W/"p-${id}-${this._version}-${buf.length}"` };
      this._projectJsonCache.set(id, cached);
    }
    return cached;
  }

  /**
   * Serialización JSON en caché por proyecto (O(1) en lecturas repetidas).
   * @param {string} id
   * @returns {string | null}
   */
  getByIdSerialized(id) {
    const entry = this.getByIdSerializedEntry(id);
    return entry ? entry.str : null;
  }

  /**
   * @param {any} data
   * @param {string | null} [id]
   */
  validateProjectData(data, id = null) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Invalid project payload');
    }
    const effectiveId = id !== null && id !== undefined ? id : data.id;
    if (effectiveId !== undefined && effectiveId !== null && effectiveId !== '') {
      const idStr = String(effectiveId);
      if (!/^[a-zA-Z0-9_-]{1,80}$/.test(idStr)) {
        throw new Error('Invalid project ID (path traversal detected)');
      }
    }
    if (data.name !== undefined && data.name !== null) {
      // Keep Unicode intact; strip only control characters and angle brackets
      // in one fast regex pass instead of allocating per-char arrays.
      data.name = String(data.name)
        .replace(/[\x00-\x1f\x7f<>]/g, '')
        .slice(0, 120)
        .trim();
    }
    if (data.baseDirectory !== undefined && data.baseDirectory !== null && data.baseDirectory !== '') {
      const baseDir = String(data.baseDirectory).trim();
      if (baseDir.includes('\0') || baseDir.split(/[\\/]+/).includes('..')) {
        throw new Error('Invalid baseDirectory (path traversal detected)');
      }
    }
    if (data.watchPaths && Array.isArray(data.watchPaths)) {
      data.watchPaths.forEach(p => {
        if (typeof p !== 'string' || p.includes('../') || p.includes('..\\') || p.includes(';') || p.includes('\0')) {
          throw new Error('Invalid watch path detected');
        }
      });
    }
    if (data.startCommand !== undefined && data.startCommand !== null) {
      if (typeof data.startCommand !== 'string' || /[;\0\r\n]/.test(data.startCommand)) {
        throw new Error('Invalid start command');
      }
    }
    if (data.buildCommand !== undefined && data.buildCommand !== null) {
      if (typeof data.buildCommand !== 'string' || /[;\0\r\n]/.test(data.buildCommand)) {
        throw new Error('Invalid build command');
      }
    }
    if (data.localPath !== undefined && data.localPath !== null && String(data.localPath).trim() !== '') {
      const lp = String(data.localPath).trim();
      if (/[\0\r\n]/.test(lp) || lp.length > 512) {
        throw new Error('Invalid localPath');
      }
      const resolved = path.resolve(lp);
      const parsedRoot = path.parse(resolved).root;
      if (resolved === parsedRoot) {
        throw new Error('No se permite vincular el directorio raíz del sistema');
      }
      // Bloquear data/ de Culkibo y directorios sensibles del SO (Coolify CVE-2026-34153)
      const dataDirAbs = path.resolve(path.dirname(this.dataPath));
      const relToData = path.relative(dataDirAbs, resolved);
      if (relToData === '' || (!relToData.startsWith('..') && !path.isAbsolute(relToData))) {
        throw new Error('No se permite vincular el directorio interno data/ de Culkibo como carpeta local');
      }
      const forbiddenPrefixes = ['/etc', '/proc', '/sys', '/root', '/var/run', '/run', 'c:\\windows\\system32'];
      const lowerRes = resolved.toLowerCase();
      if (forbiddenPrefixes.some((p) => lowerRes === p || lowerRes.startsWith(`${p}${path.sep}`) || lowerRes.startsWith(`${p}/`))) {
        throw new Error('No se permite vincular un directorio sensible del sistema como carpeta local');
      }
    }
    if (Array.isArray(data.domains) && data.domains.length > 0) {
      const normalized = Array.from(new Set(
        data.domains.map((d) => String(d || '').trim().toLowerCase().replace(/\.+$/, '')).filter(Boolean)
      ));
      for (const host of normalized) {
        for (const existing of this.projects.values()) {
          if (effectiveId && existing.id === effectiveId) continue;
          if (Array.isArray(existing.domains) && existing.domains.some((ed) => String(ed || '').trim().toLowerCase().replace(/\.+$/, '') === host)) {
            throw new Error(`El dominio "${host}" ya está asignado al proyecto "${existing.name}"`);
          }
        }
      }
      data.domains = normalized;
    }

    if (data.serverId !== undefined && data.serverId !== null && data.serverId !== '') {
      if (typeof data.serverId !== 'string') {
        throw new Error('Invalid serverId');
      }
      const sid = data.serverId.trim();
      if (!/^[a-z0-9_-]{1,64}$/.test(sid)) {
        throw new Error('Invalid serverId (expected /^[a-z0-9_-]{1,64}$/)');
      }
      data.serverId = sid;
    }

    if (data.teamId !== undefined && data.teamId !== null && data.teamId !== '') {
      if (typeof data.teamId !== 'string') {
        throw new Error('Invalid teamId');
      }
      const tid = data.teamId.trim();
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(tid)) {
        throw new Error('Invalid teamId');
      }
      data.teamId = tid;
    }

    if (data.smokeTests !== undefined && data.smokeTests !== null) {
      /** @type {any[]} */
      let checksList = [];
      if (Array.isArray(data.smokeTests)) {
        checksList = data.smokeTests;
      } else if (typeof data.smokeTests === 'object' && Array.isArray(data.smokeTests.checks)) {
        if (data.smokeTests.failPolicy !== undefined && !['abort', 'rollback', 'warn'].includes(data.smokeTests.failPolicy)) {
          throw new Error('Invalid smokeTests.failPolicy');
        }
        checksList = data.smokeTests.checks;
      } else {
        throw new Error('Invalid smokeTests payload');
      }
      if (checksList.length > 10) {
        throw new Error('smokeTests supports at most 10 checks');
      }
      const blockedHeaders = /^(host|connection|content-length|transfer-encoding|keep-alive|te|trailer|upgrade)$/i;
      const forbiddenJsonSegs = new Set(['__proto__', 'constructor', 'prototype']);
      for (const chk of checksList) {
        if (!chk || typeof chk !== 'object' || Array.isArray(chk)) {
          throw new Error('Invalid smokeTest check entry');
        }
        if (typeof chk.path !== 'string') {
          throw new Error('Invalid smokeTest path');
        }
        const p = chk.path.trim();
        if (!p.startsWith('/') || p.startsWith('//') || p.length > 512 || p.includes('..') || /[\s\r\n\0]/.test(p)) {
          throw new Error(`Invalid smokeTest path: ${p.slice(0, 60)}`);
        }
        if (chk.method !== undefined && !['GET', 'HEAD', 'POST'].includes(String(chk.method).toUpperCase())) {
          throw new Error(`Invalid smokeTest method: ${chk.method}`);
        }
        const stRaw = chk.expectStatus !== undefined ? chk.expectStatus : chk.expectedStatus;
        if (stRaw !== undefined && stRaw !== null) {
          const validNum = typeof stRaw === 'number' && Number.isInteger(stRaw) && stRaw >= 100 && stRaw <= 599;
          const validClass = typeof stRaw === 'string' && /^[1-5]xx$/i.test(stRaw.trim());
          const validArr = Array.isArray(stRaw) && stRaw.length > 0 && stRaw.length <= 10 &&
            stRaw.every((n) => typeof n === 'number' && Number.isInteger(n) && n >= 100 && n <= 599);
          if (!validNum && !validClass && !validArr) {
            throw new Error('Invalid smokeTest expectStatus');
          }
        }
        const containsRaw = chk.expectBodyContains !== undefined ? chk.expectBodyContains : chk.bodyContains;
        if (containsRaw !== undefined && containsRaw !== null) {
          if (typeof containsRaw !== 'string' || containsRaw.length > 256 || containsRaw.includes('\0')) {
            throw new Error('Invalid smokeTest expectBodyContains');
          }
        }
        if (chk.bodyNotContains !== undefined && chk.bodyNotContains !== null) {
          if (typeof chk.bodyNotContains !== 'string' || chk.bodyNotContains.length > 256 || chk.bodyNotContains.includes('\0')) {
            throw new Error('Invalid smokeTest bodyNotContains');
          }
        }
        if (chk.maxLatencyMs !== undefined && chk.maxLatencyMs !== null && chk.maxLatencyMs !== '') {
          const ml = Number(chk.maxLatencyMs);
          if (!Number.isFinite(ml) || ml < 1 || ml > 60000) {
            throw new Error('Invalid smokeTest maxLatencyMs (1..60000)');
          }
        }
        if (chk.timeoutMs !== undefined && chk.timeoutMs !== null) {
          const tm = Number(chk.timeoutMs);
          if (!Number.isFinite(tm) || tm < 50 || tm > 30000) {
            throw new Error('Invalid smokeTest timeoutMs (50..30000)');
          }
        }
        if (chk.retries !== undefined && chk.retries !== null) {
          const rt = Number(chk.retries);
          if (!Number.isInteger(rt) || rt < 0 || rt > 3) {
            throw new Error('Invalid smokeTest retries (0..3)');
          }
        }
        if (chk.headers !== undefined && chk.headers !== null) {
          if (typeof chk.headers !== 'object' || Array.isArray(chk.headers)) {
            throw new Error('Invalid smokeTest headers');
          }
          const entries = Object.entries(chk.headers);
          if (entries.length > 10) throw new Error('Too many smokeTest headers (max 10)');
          for (const [hk, hv] of entries) {
            if (!/^[A-Za-z0-9-]+$/.test(hk) || blockedHeaders.test(hk)) {
              throw new Error(`Disallowed smokeTest header: ${hk}`);
            }
            if (typeof hv !== 'string' || /[\r\n\0]/.test(hv) || hv.length > 512) {
              throw new Error(`Invalid smokeTest header value for ${hk}`);
            }
          }
        }
        if (chk.jsonPathEquals !== undefined && chk.jsonPathEquals !== null) {
          if (typeof chk.jsonPathEquals !== 'object' || Array.isArray(chk.jsonPathEquals) || typeof chk.jsonPathEquals.path !== 'string') {
            throw new Error('Invalid smokeTest jsonPathEquals');
          }
          const segs = chk.jsonPathEquals.path.trim().split('.').filter(Boolean);
          if (segs.length < 1 || segs.length > 5 || segs.some((s) => forbiddenJsonSegs.has(s) || !/^[A-Za-z0-9_-]{1,64}$/.test(s))) {
            throw new Error('Invalid smokeTest jsonPathEquals path');
          }
        }
      }
    }

    if (data.canary !== undefined && data.canary !== null) {
      if (typeof data.canary !== 'object' || Array.isArray(data.canary)) {
        throw new Error('Invalid canary configuration');
      }
      if (data.canary.weightPercent !== undefined && data.canary.weightPercent !== null) {
        const wp = Number(data.canary.weightPercent);
        if (!Number.isFinite(wp) || wp < 1 || wp > 99) {
          throw new Error('Invalid canary.weightPercent (1..99)');
        }
      }
      if (data.canary.observeSeconds !== undefined && data.canary.observeSeconds !== null) {
        const obs = Number(data.canary.observeSeconds);
        if (!Number.isFinite(obs) || obs <= 0 || obs > 3600) {
          throw new Error('Invalid canary.observeSeconds (0..3600]');
        }
      }
      if (data.canary.maxErrorRate !== undefined && data.canary.maxErrorRate !== null) {
        const mer = Number(data.canary.maxErrorRate);
        if (!Number.isFinite(mer) || mer < 0 || mer > 1) {
          throw new Error('Invalid canary.maxErrorRate (0..1)');
        }
      }
      if (data.canary.steps !== undefined && data.canary.steps !== null) {
        if (!Array.isArray(data.canary.steps) || data.canary.steps.length < 1 || data.canary.steps.length > 5) {
          throw new Error('Invalid canary.steps (1..5 ascending ints)');
        }
        let prevStep = 0;
        for (const s of data.canary.steps) {
          if (typeof s !== 'number' || !Number.isInteger(s) || s < 1 || s > 100 || s <= prevStep) {
            throw new Error('Invalid canary.steps (must be strictly ascending integers in 1..100)');
          }
          prevStep = s;
        }
      }
      if (data.canary.stepDurationMs !== undefined && data.canary.stepDurationMs !== null) {
        const sd = Number(data.canary.stepDurationMs);
        if (!Number.isFinite(sd) || sd < 10 || sd > 300000) {
          throw new Error('Invalid canary.stepDurationMs (10..300000)');
        }
      }
      if (data.canary.checksPerStep !== undefined && data.canary.checksPerStep !== null) {
        const cps = Number(data.canary.checksPerStep);
        if (!Number.isInteger(cps) || cps < 1 || cps > 10) {
          throw new Error('Invalid canary.checksPerStep (1..10)');
        }
      }
      if (data.canary.maxLatencyMs !== undefined && data.canary.maxLatencyMs !== null) {
        const ml = Number(data.canary.maxLatencyMs);
        if (!Number.isFinite(ml) || ml < 1 || ml > 60000) {
          throw new Error('Invalid canary.maxLatencyMs (1..60000)');
        }
      }
    }

    if (data.freezeWindows !== undefined && data.freezeWindows !== null) {
      if (!Array.isArray(data.freezeWindows)) {
        throw new Error('Invalid freezeWindows (expected array)');
      }
      if (data.freezeWindows.length > 16) {
        throw new Error('freezeWindows supports at most 16 entries');
      }
      const validDayNames = new Set(['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']);
      for (const fw of data.freezeWindows) {
        if (!fw || typeof fw !== 'object' || Array.isArray(fw)) {
          throw new Error('Invalid freezeWindow entry');
        }
        const tzRaw = fw.tz !== undefined ? fw.tz : (fw.timezone !== undefined ? fw.timezone : 'UTC');
        if (typeof tzRaw !== 'string' || !tzRaw.trim() || tzRaw.length > 64) {
          throw new Error('Invalid freezeWindow timezone');
        }
        try {
          new Intl.DateTimeFormat('en-US', { timeZone: tzRaw.trim() });
        } catch (e) {
          throw new Error(`Invalid IANA timezone in freezeWindow: ${tzRaw}`);
        }
        if (fw.reason !== undefined && fw.reason !== null) {
          if (typeof fw.reason !== 'string' || fw.reason.length > 200 || fw.reason.includes('\0')) {
            throw new Error('Invalid freezeWindow reason');
          }
        }
        const daysRaw = fw.days !== undefined ? fw.days : fw.daysOfWeek;
        if (daysRaw !== undefined && daysRaw !== null) {
          if (!Array.isArray(daysRaw) || daysRaw.length === 0 || daysRaw.length > 7) {
            throw new Error('Invalid freezeWindow days');
          }
          for (const d of daysRaw) {
            const okNum = typeof d === 'number' && Number.isInteger(d) && d >= 0 && d <= 6;
            const okStr = typeof d === 'string' && validDayNames.has(d.trim().toLowerCase().slice(0, 3));
            if (!okNum && !okStr) {
              throw new Error(`Invalid freezeWindow day: ${d}`);
            }
          }
        }
        if (fw.kind === 'once') {
          const s = Date.parse(String(fw.startAt || ''));
          const e = Date.parse(String(fw.endAt || ''));
          if (!Number.isFinite(s) || !Number.isFinite(e) || e <= s) {
            throw new Error('Invalid freezeWindow startAt/endAt');
          }
        } else if (fw.startHour !== undefined || fw.endHour !== undefined) {
          const sh = Number(fw.startHour);
          const eh = Number(fw.endHour);
          if (!Number.isInteger(sh) || sh < 0 || sh > 23 || !Number.isInteger(eh) || eh < 0 || eh > 24) {
            throw new Error('Invalid freezeWindow startHour/endHour (startHour 0..23, endHour 0..24)');
          }
        } else if (typeof fw.startTime === 'string' && typeof fw.endTime === 'string') {
          if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(fw.startTime.trim()) || !/^(([01]\d|2[0-3]):[0-5]\d|24:00)$/.test(fw.endTime.trim())) {
            throw new Error('Invalid freezeWindow startTime/endTime (expected HH:MM)');
          }
        } else {
          throw new Error('freezeWindow requires startHour/endHour, startTime/endTime, or kind:"once" with startAt/endAt');
        }
      }
    }
  }

  create(data) {
    const safeData = data && typeof data === 'object' ? { ...data } : {};
    this.validateProjectData(safeData);
    const project = new Project(safeData);
    this.projects.set(project.id, project);
    this.saveProjects(project.id);
    this.emit('project_created', project);
    return project;
  }

  /**
   * @param {string} id
   * @param {any} data
   * @param {{ allowTeamReassign?: boolean }} [options]
   */
  update(id, data, options = {}) {
    const safeData = data && typeof data === 'object' ? { ...data } : {};
    // Never let a caller overwrite immutable identity/audit/tenant fields via generic PUT.
    delete safeData.id;
    delete safeData.createdAt;
    if (!options || !options.allowTeamReassign) {
      delete safeData.teamId;
    }
    this.validateProjectData(safeData, id);
    const project = this.projects.get(id);
    if (!project) throw new Error('Project not found');
    
    const wasActive = project.status === 'active';
    const watchPathsChanged = wasActive && safeData.watchPaths !== undefined &&
      JSON.stringify(project.watchPaths || []) !== JSON.stringify(safeData.watchPaths || []);

    Object.assign(project, safeData, { id, updatedAt: new Date().toISOString() });
    const updatedProject = new Project(project);
    this.projects.set(id, updatedProject);
    this.saveProjects(id);

    if (watchPathsChanged) {
      const projectDir = path.join(process.env.CULKIBO_DATA_DIR || process.cwd(), 'projects', id);
      if (!fs.existsSync(projectDir)) {
        fs.mkdirSync(projectDir, { recursive: true });
      }
      containerOrchestrator.watchDirectory(projectDir, updatedProject.watchPaths || []);
    }

    this.emit('project_update', updatedProject);
    return updatedProject;
  }

  delete(id) {
    const project = this.projects.get(id);
    if (project && project.status === 'active') {
      const projectDir = path.join(process.env.CULKIBO_DATA_DIR || process.cwd(), 'projects', id);
      containerOrchestrator.stopWatching(projectDir);
    }
    const result = this.projects.delete(id);
    this.flushToDisk(id);
    this.emit('project_deleted', { id });
    return result;
  }

  activate(id) {
    const project = this.projects.get(id);
    if (!project) throw new Error('Project not found');

    project.status = 'active';
    project.updatedAt = new Date().toISOString();
    if (project.resources && Array.isArray(project.resources)) {
      project.resources.forEach(r => {
        r.status = 'active';
      });
    }
    this.projects.set(id, project);
    this.flushToDisk(id);

    this.emit('project_update', project);
    return project;
  }

  stop(id) {
    const project = this.projects.get(id);
    if (!project) throw new Error('Project not found');

    project.status = 'stopped';
    project.localRunning = false;
    project.updatedAt = new Date().toISOString();
    if (project.resources && Array.isArray(project.resources)) {
      project.resources.forEach(r => {
        r.status = 'stopped';
      });
    }
    this.projects.set(id, project);
    this.flushToDisk(id);

    const projectDir = path.join(process.env.CULKIBO_DATA_DIR || process.cwd(), 'projects', id);
    containerOrchestrator.stopWatching(projectDir);

    this.emit('project_update', project);
    return project;
  }

  hibernate(id) {
    const project = this.projects.get(id);
    if (!project) throw new Error('Project not found');

    project.status = 'hibernated';
    project.localRunning = false;
    project.updatedAt = new Date().toISOString();
    if (project.resources && Array.isArray(project.resources)) {
      project.resources.forEach(r => {
        r.status = 'hibernated';
      });
    }
    this.projects.set(id, project);
    this.flushToDisk(id);

    // Stop watcher for this specific project
    const projectDir = path.join(process.env.CULKIBO_DATA_DIR || process.cwd(), 'projects', id);
    containerOrchestrator.stopWatching(projectDir);

    this.emit('project_update', project);
    return project;
  }
}

module.exports = new ProjectManager();
