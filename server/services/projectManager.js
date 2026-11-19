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
    /** @type {Map<string, string>} */
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

    // Group Commit (fase 1): si no hay escritura activa, agrupa en el mismo
    // turno del bucle de eventos (2 ms) todas las mutaciones que llegan juntas
    // en una ráfaga concurrente en UNA sola escritura atómica a disco.
    if (!this._inFlightFlush) {
      if (!this._batchingFlush) {
        this._batchingFlush = new Promise((resolve) => {
          const t = setTimeout(() => {
            this._batchingFlush = null;
            const p = this.writeSnapshot().finally(() => {
              if (this._inFlightFlush === p) this._inFlightFlush = null;
            });
            this._inFlightFlush = p;
            this.flushChain = p;
            resolve(p);
          }, 2);
          if (t.unref) t.unref();
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
      await fs.promises.writeFile(tempPath, buf);

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
      tempPath = null;

      // Refresh the .bak recovery snapshot in the background (throttled) so
      // concurrent HTTP writes never stall waiting on a duplicate disk copy.
      const now = Date.now();
      if (now - this._lastBackupAt > 5000) {
        this._lastBackupAt = now;
        fs.promises.copyFile(this.dataPath, `${this.dataPath}.bak`).catch(() => {});
      }
    } catch (err) {
      console.error('Error flushing projects to disk:', err);
      if (tempPath) {
        try { await fs.promises.unlink(tempPath); } catch (e) {}
      }
    }
    // Sin `finally` con reentrada: la serialización la garantiza la cadena de
    // flushToDisk(). Volver a llamarse a sí misma desde aquí era lo que hacía
    // imposible saber cuándo había terminado de verdad una escritura.
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
          entry = JSON.stringify(proj);
          this._projectJsonCache.set(id, entry);
        }
        parts.push(entry);
      }
      this._serializedAll = Buffer.from(`[${parts.join(',')}]`, 'utf8');
    }
    return this._serializedAll;
  }

  getById(id) {
    return this.projects.get(id);
  }

  /**
   * @param {any} data
   * @param {string | null} [id]
   */
  validateProjectData(data, id = null) {
    if (id && (!/^[a-zA-Z0-9_-]+$/.test(id) || id.includes('../') || id.includes('..\\'))) {
      throw new Error('Invalid project ID (path traversal detected)');
    }
    if (data.name) {
      // Culkibo is a Spanish-first product: the previous ASCII allowlist silently
      // destroyed accents, ñ and emoji ("Aplicación Núcleo" -> "Aplicacin Ncleo")
      // on every single update, including the implicit update done by start-local.
      // Keep Unicode intact; strip only control characters and the angle brackets
      // that could break out of the HTML the local runner renders. Every consumer
      // that prints a name into markup escapes it as well.
      data.name = Array.from(String(data.name))
        .filter((ch) => {
          const code = ch.codePointAt(0) ?? 0;
          return code > 31 && code !== 127 && ch !== String.fromCharCode(60) && ch !== String.fromCharCode(62);
        })
        .join('')
        .slice(0, 120)
        .trim();
    }
    if (data.watchPaths && Array.isArray(data.watchPaths)) {
      data.watchPaths.forEach(p => {
        if (p.includes('../') || p.includes('..\\') || p.includes(';')) {
          throw new Error('Invalid watch path detected');
        }
      });
    }
    if (data.startCommand && data.startCommand.includes(';')) {
      throw new Error('Invalid start command');
    }
    if (data.buildCommand && data.buildCommand.includes(';')) {
      throw new Error('Invalid build command');
    }
  }

  create(data) {
    this.validateProjectData(data);
    const project = new Project(data);
    this.projects.set(project.id, project);
    this.saveProjects(project.id);
    this.emit('project_created', project);
    return project;
  }

  update(id, data) {
    this.validateProjectData(data, id);
    const project = this.projects.get(id);
    if (!project) throw new Error('Project not found');
    
    const wasActive = project.status === 'active';
    const oldWatchPaths = JSON.stringify(project.watchPaths || []);
    
    Object.assign(project, data, { updatedAt: new Date().toISOString() });
    const updatedProject = new Project(project);
    this.projects.set(id, updatedProject);
    this.saveProjects(id);

    const newWatchPaths = JSON.stringify(updatedProject.watchPaths || []);
    if (wasActive && newWatchPaths !== oldWatchPaths) {
      const projectDir = path.join(process.cwd(), 'projects', id);
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
      // Detener el watcher directamente sin hacer un flush intermedio de hibernación
      // que se sobrescribiría un microsegundo después al borrar el proyecto.
      const projectDir = path.join(process.cwd(), 'projects', id);
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
    this.flushToDisk();

    // Start watcher
    const projectDir = path.join(process.cwd(), 'projects', id);
    if (!fs.existsSync(projectDir)) {
      fs.mkdirSync(projectDir, { recursive: true });
    }
    containerOrchestrator.watchDirectory(projectDir, project.watchPaths || []);

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
    this.flushToDisk();

    // Stop watcher for this specific project
    const projectDir = path.join(process.cwd(), 'projects', id);
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
    this.flushToDisk();

    // Stop watcher for this specific project
    const projectDir = path.join(process.cwd(), 'projects', id);
    containerOrchestrator.stopWatching(projectDir);

    this.emit('project_update', project);
    return project;
  }
}

module.exports = new ProjectManager();
