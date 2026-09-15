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

  saveProjects() {
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
    }
    this.saveDebounceTimer = setTimeout(async () => {
      this.saveDebounceTimer = null;
      await this.flushToDisk();
    }, 15);
    if (this.saveDebounceTimer.unref) {
      this.saveDebounceTimer.unref();
    }
  }

  async flushToDisk() {
    if (this.saveDebounceTimer) {
      clearTimeout(this.saveDebounceTimer);
      this.saveDebounceTimer = null;
    }

    if (this.isFlushing) {
      this.pendingFlush = true;
      return;
    }
    this.isFlushing = true;

    let tempPath = null;
    try {
      const data = Array.from(this.projects.values());
      const serialized = JSON.stringify(data, null, 2);

      // Never let a serialisation glitch blank the store.
      if (!serialized || serialized.length < 2) {
        throw new Error('Serialización de proyectos vacía; se aborta la escritura');
      }

      tempPath = `${this.dataPath}.${Date.now()}_${Math.random().toString(36).slice(2)}.tmp`;
      await fs.promises.writeFile(tempPath, serialized, 'utf8');

      // Verify what actually landed on disk before it replaces the live file.
      const verify = await fs.promises.readFile(tempPath, 'utf8');
      if (verify.length !== Buffer.byteLength(serialized, 'utf8') && verify !== serialized) {
        throw new Error('El archivo temporal no coincide con los datos serializados');
      }
      JSON.parse(verify);

      // Keep the last known-good copy so a half-written replace is recoverable.
      if (fs.existsSync(this.dataPath)) {
        try { await fs.promises.copyFile(this.dataPath, `${this.dataPath}.bak`); } catch (e) {}
      }

      // On Windows, rename() throws EPERM/EBUSY while another handle (an editor,
      // an antivirus scan, a concurrent reader) holds the destination open. That
      // is transient, so retry before resorting to copyFile — which truncates the
      // destination first and is the one path that can leave a 0-byte file.
      let renamed = false;
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
    } catch (err) {
      console.error('Error flushing projects to disk:', err);
      if (tempPath) {
        try { await fs.promises.unlink(tempPath); } catch (e) {}
      }
    } finally {
      this.isFlushing = false;
      if (this.pendingFlush) {
        this.pendingFlush = false;
        await this.flushToDisk();
      }
    }
  }

  getAll() {
    return Array.from(this.projects.values());
  }

  getById(id) {
    return this.projects.get(id);
  }

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
    this.saveProjects();
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
    this.saveProjects();

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
      this.hibernate(id);
    }
    const result = this.projects.delete(id);
    this.saveProjects();
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
