const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const localRunner = require('./localRunner');

/**
 * De «la rama configurada del proyecto» a «un directorio en disco exactamente
 * en ese commit», diciendo qué commit era.
 *
 * ---------------------------------------------------------------------------
 * POR QUÉ EXISTE ESTE FICHERO
 * ---------------------------------------------------------------------------
 *
 * `deployManager` construía lo que hubiera en `projects/<id>`. Eso convierte un
 * despliegue en una lotería: el directorio puede venir de un clon de hace tres
 * semanas, de una prueba en local o de un `git checkout` a mano. Un despliegue
 * que no sabe qué commit está sirviendo no se puede auditar ni revertir con
 * criterio, y el historial del panel miente.
 *
 * Es un servicio aparte a propósito: `deployManager` no tiene por qué saber
 * cómo llegan las credenciales a git, y `localRunner` no tiene por qué saber
 * qué es un despliegue a producción. Esta es la costura entre ambos.
 *
 * ---------------------------------------------------------------------------
 * LAS TRES REGLAS QUE NO SE TOCAN
 * ---------------------------------------------------------------------------
 *
 * 1. NUNCA SE CONSTRUYE UNA CADENA DE SHELL. Todo va por
 *    `spawn('git', [argv], { shell: false })`.
 *
 * 2. EL TOKEN NO VIAJA EN LA URL NI EN ARGV. Se reutiliza
 *    `localRunner.gitAuthEnv()`, que lo entrega por `GIT_ASKPASS` en el entorno
 *    del hijo. Un token en la URL acaba en `ps`, en `.git/config`, en los
 *    mensajes de error de git y en cualquier log que repita el comando.
 *
 * 3. NOMBRES DE RAMA Y COMMITS VALIDADOS ANTES DE ARGV. Sin shell no hay
 *    inyección de comandos, pero git sí lee sus propias opciones: una rama
 *    llamada `--upload-pack=...` sería ejecución de código en el host aunque no
 *    haya intérprete de por medio.
 */

/** Límite generoso; git mismo admite más, pero nada legítimo lo necesita. */
const BRANCH_MAX = 200;

/**
 * Un nombre de rama que git acepta y que no puede confundirse con una opción
 * ni con una ruta relativa.
 */
function isValidBranch(value) {
  const branch = String(value == null ? '' : value).trim();
  if (!branch || branch.length > BRANCH_MAX) return false;
  if (branch.startsWith('-') || branch.startsWith('/') || branch.endsWith('/')) return false;
  if (branch.endsWith('.lock') || branch.endsWith('.')) return false;
  if (branch.includes('..') || branch.includes('//') || branch.includes('@{')) return false;
  return /^[A-Za-z0-9._/#+-]+$/.test(branch);
}

/** Un SHA abreviado o completo, en minúsculas y sin nada más. */
function isValidCommit(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{7,40}$/.test(value.trim());
}

/**
 * Lanza git con un array de argumentos y transmite su salida línea a línea.
 * No lanza nunca: devuelve el código y lo capturado, como `deployManager.runTool`.
 * Soporta cancelación cooperativa mediante `AbortSignal` (`SIGTERM` + escalada `SIGKILL`).
 *
 * @param {string[]} args
 * @param {{cwd?: string, env?: any, timeoutMs?: number, onLine?: ((line: string) => void) | null, signal?: AbortSignal | null}} [options]
 * @returns {Promise<{code: number, stdout: string, stderr: string, spawnError?: boolean, timedOut?: boolean, aborted?: boolean}>}
 */
function runGit(args, { cwd = undefined, env = undefined, timeoutMs = 120000, onLine = null, signal = null } = {}) {
  if (signal && signal.aborted) {
    return Promise.resolve({ code: -3, stdout: '', stderr: 'Operación cancelada', aborted: true });
  }
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('git', args, { cwd, env: env || process.env, shell: false, windowsHide: true });
    } catch (err) {
      return resolve({ code: -1, stdout: '', stderr: err.message, spawnError: true });
    }

    /** @type {string[]} */
    const stdout = [];
    /** @type {string[]} */
    const stderr = [];
    let buffered = '';

    const pump = (chunk, sink) => {
      const text = chunk.toString();
      sink.push(text);
      if (sink.length > 400) sink.shift();
      if (!onLine) return;
      // git escribe el progreso con \r, no con \n: partir solo por \n dejaría
      // una única línea kilométrica que crece hasta el final de la descarga.
      buffered += text;
      const lines = buffered.split(/[\r\n]+/);
      buffered = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) onLine(trimmed);
      }
    };

    child.stdout.on('data', (d) => pump(d, stdout));
    child.stderr.on('data', (d) => pump(d, stderr));

    let timedOut = false;
    let aborted = false;
    /** @type {ReturnType<typeof setTimeout> | null} */
    let killEscalation = null;

    const terminateChild = () => {
      try { child.kill('SIGTERM'); } catch (e) {}
      killEscalation = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch (e) {}
      }, 3000);
      if (killEscalation.unref) killEscalation.unref();
    };

    const onAbort = () => {
      aborted = true;
      terminateChild();
    };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    const timer = setTimeout(() => {
      timedOut = true;
      terminateChild();
    }, timeoutMs);
    if (timer.unref) timer.unref();

    const cleanupListeners = () => {
      clearTimeout(timer);
      if (killEscalation) clearTimeout(killEscalation);
      if (signal) signal.removeEventListener('abort', onAbort);
    };

    child.on('error', (err) => {
      cleanupListeners();
      resolve({ code: aborted ? -3 : -1, stdout: stdout.join(''), stderr: err.message, spawnError: true, aborted });
    });

    child.on('close', (code) => {
      cleanupListeners();
      if (onLine && buffered.trim()) onLine(buffered.trim());
      resolve({
        code: aborted ? -3 : (timedOut ? -2 : code),
        stdout: stdout.join(''),
        stderr: stderr.join(''),
        timedOut,
        aborted
      });
    });
  });
}

class RepoSync {
  /** Directorio de trabajo del proyecto en este host (confinado en projects/). */
  projectDir(project) {
    return localRunner.resolveProjectDir(project.id);
  }

  /**
   * Deja `projects/<id>` en el commit que toca y cuenta cuál es.
   *
   * Casos que cubre, que son justamente los que rompen un despliegue en
   * producción a las tres semanas de funcionar:
   *
   *   - el repositorio todavía no está clonado -> clon superficial de una rama;
   *   - el árbol de trabajo está sucio -> se descarta y se dice qué se descartó;
   *   - la rama configurada ha cambiado -> se trae y se conmuta, sin reclonar;
   *   - la URL del repositorio ha cambiado (o el token acaba de conectarse)
   *     -> se reescribe `origin` antes de hablar con el remoto;
   *   - se pide un commit concreto (rollback hacia delante, reintento de un
   *     despliegue viejo) -> se trae ese objeto suelto y, si el servidor no lo
   *     permite, se profundiza el clon en vez de fallar.
   *
   * @param {any} project
   * @param {{commit?: string | null, targetDir?: string | null, onLine?: ((line: string) => void) | null, timeoutMs?: number, signal?: AbortSignal | null}} [options]
   */
  async sync(project, { commit = null, targetDir = null, onLine = null, timeoutMs = 300000, signal = null } = {}) {
    let dir = this.projectDir(project);
    if (targetDir) {
      const projectsRoot = path.resolve(path.dirname(dir));
      const candidate = path.resolve(String(targetDir));
      const rel = path.relative(projectsRoot, candidate);
      if (!rel || rel === '.' || rel.startsWith('..') || path.isAbsolute(rel)) {
        return { ok: false, error: 'Directorio de destino fuera de projects/', dir: candidate, dirtyFiles: [] };
      }
      dir = candidate;
    }
    const emit = (message) => { if (onLine) onLine(localRunner.redactSecrets(message)); };
    const abortedResult = (dirtyFiles = []) => ({
      ok: false,
      aborted: true,
      error: 'Sincronización Git cancelada',
      dir,
      dirtyFiles
    });

    if (signal && signal.aborted) {
      return abortedResult();
    }

    /** Resultado vacío pero válido: el despliegue puede seguir. */
    const skipped = (reason) => ({
      ok: true,
      action: 'omitido',
      reason,
      dir,
      branch: project.gitBranch || null,
      commit: null,
      shortCommit: null,
      subject: null,
      author: null,
      previousCommit: null,
      dirtyFiles: []
    });

    const rawUrl = (project.gitRepo || '').trim();
    if (!rawUrl) {
      return skipped('El proyecto no tiene repositorio configurado: se construirá el código que ya está en disco');
    }

    const branch = (project.gitBranch || 'main').trim();
    if (!isValidBranch(branch)) {
      return { ok: false, error: `Nombre de rama no válido: «${branch}»`, dir, dirtyFiles: [] };
    }
    if (commit != null && commit !== '' && !isValidCommit(commit)) {
      return { ok: false, error: 'El identificador de commit solicitado no es un SHA válido', dir, dirtyFiles: [] };
    }
    const wanted = commit ? String(commit).trim().toLowerCase() : null;

    const cloneUrl = localRunner.normalizeGitUrl(rawUrl);
    if (!cloneUrl) {
      return { ok: false, error: `URL de repositorio Git no permitida o inválida: «${rawUrl}»`, dir, dirtyFiles: [] };
    }
    const display = localRunner.redactSecrets(rawUrl);
    const { env, cleanup } = localRunner.gitAuthEnv(cloneUrl);

    try {
      if (signal && signal.aborted) return abortedResult();
      fs.mkdirSync(path.dirname(dir), { recursive: true });

      const exists = fs.existsSync(dir);
      const isRepo = exists && fs.existsSync(path.join(dir, '.git'));

      // --- Caso 1: no hay repositorio ------------------------------------
      if (!isRepo) {
        if (exists && fs.readdirSync(dir).length > 0) {
          // Hay código que Culkibo no clonó. Borrarlo para hacer sitio a un
          // clon destruiría trabajo que puede no estar en ningún remoto, así
          // que se construye lo que hay y se dice claramente.
          return skipped(
            `${dir} tiene contenido pero no es un repositorio de git: se construirá tal cual está, sin sincronizar con ${display}`
          );
        }

        emit(`Clonando ${display} (rama ${branch}, clon superficial de 1 commit)...`);
        if (signal) {
          if (/^file:/i.test(String(cloneUrl)) && process.env.CULKIBO_ALLOW_LOCAL_GIT !== '1') {
            return { ok: false, error: 'URL de repositorio rechazada por política de seguridad', dir, dirtyFiles: [] };
          }
          const cloneRes = await this._cloneWithSignal(String(cloneUrl), dir, { branch, timeoutMs, env, onLine: emit, signal });
          if (cloneRes.aborted || signal.aborted) {
            try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
            return abortedResult();
          }
          if (!cloneRes.ok) {
            return { ok: false, error: cloneRes.error, dir, dirtyFiles: [] };
          }
        } else {
          try {
            await localRunner.gitClone(String(cloneUrl), dir, { timeout: timeoutMs, depth: 1, branch, onLine: emit });
          } catch (err) {
            return { ok: false, error: localRunner.redactSecrets(err.message), dir, dirtyFiles: [] };
          }
        }

        if (signal && signal.aborted) return abortedResult();

        if (wanted) {
          const deepened = await this.fetchCommit(dir, env, wanted, branch, timeoutMs, emit, signal);
          if (deepened.aborted || (signal && signal.aborted)) return abortedResult();
          if (!deepened.ok || !deepened.ref) return { ...deepened, dir, dirtyFiles: [] };
          const checkout = await runGit(['checkout', '-B', branch, deepened.ref], { cwd: dir, env, timeoutMs: 60000, onLine: emit, signal });
          if (checkout.aborted || (signal && signal.aborted)) return abortedResult();
          if (checkout.code !== 0) {
            return { ok: false, error: this.errorOf(checkout, `No se pudo situar el repositorio en ${wanted}`), dir, dirtyFiles: [] };
          }
        }

        const head = await this.readHead(dir, env, signal);
        if (signal && signal.aborted) return abortedResult();
        return { ok: true, action: 'clonado', reason: null, dir, branch, previousCommit: null, dirtyFiles: [], ...head };
      }

      // --- Caso 2: ya hay repositorio -------------------------------------
      // Lanzar rev-parse, remote get-url y status en paralelo ahorra 2 spawns secuenciales.
      const [before, currentRemote, status] = await Promise.all([
        runGit(['rev-parse', 'HEAD'], { cwd: dir, env, timeoutMs: 20000, signal }),
        runGit(['remote', 'get-url', 'origin'], { cwd: dir, env, timeoutMs: 20000, signal }),
        runGit(['status', '--porcelain'], { cwd: dir, env, timeoutMs: 60000, signal })
      ]);
      if (before.aborted || currentRemote.aborted || status.aborted || (signal && signal.aborted)) {
        return abortedResult();
      }
      const previousCommit = before.code === 0 ? (before.stdout || '').trim() : null;

      if (currentRemote.code !== 0) {
        const added = await runGit(['remote', 'add', 'origin', '--', String(cloneUrl)], { cwd: dir, env, timeoutMs: 20000, signal });
        if (added.aborted || (signal && signal.aborted)) return abortedResult();
      } else if ((currentRemote.stdout || '').trim() !== cloneUrl) {
        emit('El repositorio remoto configurado ha cambiado; se actualiza «origin».');
        const setUrl = await runGit(['remote', 'set-url', 'origin', '--', String(cloneUrl)], { cwd: dir, env, timeoutMs: 20000, signal });
        if (setUrl.aborted || (signal && signal.aborted)) return abortedResult();
        if (setUrl.code !== 0) {
          return { ok: false, error: this.errorOf(setUrl, 'No se pudo actualizar la URL del repositorio'), dir, dirtyFiles: [] };
        }
      }

      // Árbol sucio. Se descarta, pero se dice qué se descarta: perder cambios
      // en silencio es peor que perderlos.
      const dirtyFiles = (status.stdout || '')
        .split(/\r?\n/)
        .map(s => s.trim())
        .filter(Boolean)
        .slice(0, 50);

      if (dirtyFiles.length > 0) {
        const sample = dirtyFiles.slice(0, 5).join(', ');
        emit(`El árbol de trabajo tenía ${dirtyFiles.length} cambio(s) sin confirmar; se descartan: ${sample}${dirtyFiles.length > 5 ? ', ...' : ''}`);
        const reset = await runGit(['reset', '--hard'], { cwd: dir, env, timeoutMs: 120000, onLine: emit, signal });
        if (reset.aborted || (signal && signal.aborted)) return abortedResult(dirtyFiles);
        if (reset.code !== 0) {
          return { ok: false, error: this.errorOf(reset, 'No se pudo descartar los cambios locales'), dir, dirtyFiles };
        }
        // Sólo invocar `git clean -fd` cuando realmente hay ficheros sucios/sin rastrear.
        const clean = await runGit(
          ['clean', '-fd', '--exclude=node_modules', '--exclude=.culkibo'],
          { cwd: dir, env, timeoutMs: 120000, onLine: emit, signal }
        );
        if (clean.aborted || (signal && signal.aborted)) return abortedResult(dirtyFiles);
      }

      /** @type {string} */
      let ref;
      if (wanted) {
        const fetched = await this.fetchCommit(dir, env, wanted, branch, timeoutMs, emit, signal);
        if (fetched.aborted || (signal && signal.aborted)) return abortedResult(dirtyFiles);
        if (!fetched.ok || !fetched.ref) return { ...fetched, dir, dirtyFiles };
        ref = fetched.ref;
      } else {
        emit(`Trayendo refs/heads/${branch} desde origin...`);
        const fetch = await runGit(
          ['fetch', '--depth', '1', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`],
          { cwd: dir, env, timeoutMs, onLine: emit, signal }
        );
        if (fetch.aborted || (signal && signal.aborted)) return abortedResult(dirtyFiles);
        if (fetch.code !== 0) {
          return {
            ok: false,
            error: this.errorOf(fetch, `No se pudo traer la rama «${branch}» de ${display}`),
            dir,
            dirtyFiles
          };
        }
        ref = `refs/remotes/origin/${branch}`;
      }

      if (signal && signal.aborted) return abortedResult(dirtyFiles);

      // Limpiar bloqueos huérfanos `.git/*.lock` antiguos (>5 min) dejados por SIGKILL/OOM
      const gitDir = path.join(dir, '.git');
      for (const lockName of ['index.lock', 'shallow.lock', 'HEAD.lock']) {
        const lockFile = path.join(gitDir, lockName);
        try {
          if (fs.existsSync(lockFile) && (Date.now() - fs.statSync(lockFile).mtimeMs) > 5 * 60 * 1000) {
            fs.unlinkSync(lockFile);
          }
        } catch (e) {}
      }

      // `checkout -B` crea la rama si no existe y la reposiciona si existe: es
      // el mismo comando para «primera vez», «misma rama» y «rama cambiada».
      const checkout = await runGit(['checkout', '-B', branch, ref], { cwd: dir, env, timeoutMs: 120000, onLine: emit, signal });
      if (checkout.aborted || (signal && signal.aborted)) return abortedResult(dirtyFiles);
      if (checkout.code !== 0) {
        return { ok: false, error: this.errorOf(checkout, `No se pudo situar el repositorio en «${branch}»`), dir, dirtyFiles };
      }

      // Compactación perezosa de packs para evitar crecimiento infinito en clones repetidos (Kamal #1866)
      await runGit(['gc', '--auto', '--quiet'], { cwd: dir, env, timeoutMs: 30000, signal }).catch(() => {});
      if (signal && signal.aborted) return abortedResult(dirtyFiles);

      const head = await this.readHead(dir, env, signal);
      if (signal && signal.aborted) return abortedResult(dirtyFiles);
      const action = previousCommit && head.commit === previousCommit ? 'sin-cambios' : 'actualizado';
      return { ok: true, action, reason: null, dir, branch, previousCommit, dirtyFiles, ...head };
    } finally {
      cleanup();
    }
  }

  /**
   * Clon superficial abortable por `AbortSignal` (sin shell, con fallback anónimo si falla auth en repo público).
   * @param {string} cloneUrl
   * @param {string} targetDir
   * @param {{ branch: string, timeoutMs: number, env: any, onLine: (line: string) => void, signal: AbortSignal }} opts
   */
  async _cloneWithSignal(cloneUrl, targetDir, { branch, timeoutMs, env, onLine, signal }) {
    const args = ['clone', '--progress', '--depth', '1', '--single-branch', '--branch', branch, '--', cloneUrl, targetDir];
    const res = await runGit(args, { env, timeoutMs, onLine, signal });
    if (res.aborted || signal.aborted) {
      return { ok: false, aborted: true, error: 'Clonación Git cancelada' };
    }
    if (res.code === 0) return { ok: true };

    // Si falló autenticación con token de GitHub en repo público, reintentar sin token
    const errText = `${res.stderr || ''}\n${res.stdout || ''}`;
    const looksAuthFail = /invalid username or token|authentication failed|could not read username|403/i.test(errText);
    const anonUrl = String(cloneUrl).replace(/^https:\/\/x-access-token@github\.com\//i, 'https://github.com/');
    if (looksAuthFail && anonUrl !== cloneUrl) {
      try { fs.rmSync(targetDir, { recursive: true, force: true }); } catch (e) {}
      const anonEnv = {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_CONFIG_COUNT: '1',
        GIT_CONFIG_KEY_0: 'credential.helper',
        GIT_CONFIG_VALUE_0: ''
      };
      const retry = await runGit(
        ['clone', '--progress', '--depth', '1', '--single-branch', '--branch', branch, '--', anonUrl, targetDir],
        { env: anonEnv, timeoutMs, onLine, signal }
      );
      if (retry.aborted || signal.aborted) {
        return { ok: false, aborted: true, error: 'Clonación Git cancelada' };
      }
      if (retry.code === 0) return { ok: true };
      return { ok: false, error: this.errorOf(retry, 'No se pudo clonar el repositorio') };
    }
    return { ok: false, error: this.errorOf(res, 'No se pudo clonar el repositorio') };
  }

  /**
   * Trae un commit suelto.
   *
   * GitHub permite pedir un SHA concreto (`uploadpack.allowReachableSHA1InWant`),
   * pero no todos los servidores lo hacen. Si el remoto lo rechaza, en vez de
   * fallar se profundiza el clon —que es lento pero funciona en cualquier
   * servidor— y se busca el objeto ahí.
   *
   * @param {string} dir
   * @param {any} env
   * @param {string} wanted
   * @param {string} branch
   * @param {number} timeoutMs
   * @param {(line: string) => void} emit
   * @param {AbortSignal | null} [signal]
   */
  async fetchCommit(dir, env, wanted, branch, timeoutMs, emit, signal = null) {
    emit(`Trayendo el commit ${wanted.slice(0, 7)} desde origin...`);
    const direct = await runGit(['fetch', '--depth', '1', '--force', 'origin', wanted], { cwd: dir, env, timeoutMs, onLine: emit, signal });
    if (direct.aborted || (signal && signal.aborted)) return { ok: false, aborted: true, error: 'Sincronización Git cancelada' };
    if (direct.code === 0) return { ok: true, ref: 'FETCH_HEAD' };

    emit('El servidor no permite pedir un commit suelto; se recupera el historial completo de la rama.');
    const unshallow = await runGit(['fetch', '--unshallow', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`], {
      cwd: dir, env, timeoutMs, onLine: emit, signal
    });
    if (unshallow.aborted || (signal && signal.aborted)) return { ok: false, aborted: true, error: 'Sincronización Git cancelada' };
    if (unshallow.code !== 0) {
      // `--unshallow` falla si el clon ya era completo; en ese caso basta un
      // fetch normal.
      const plain = await runGit(['fetch', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`], {
        cwd: dir, env, timeoutMs, onLine: emit, signal
      });
      if (plain.aborted || (signal && signal.aborted)) return { ok: false, aborted: true, error: 'Sincronización Git cancelada' };
      if (plain.code !== 0) {
        return { ok: false, error: this.errorOf(plain, `No se pudo traer el historial de «${branch}»`) };
      }
    }

    const exists = await runGit(['cat-file', '-e', `${wanted}^{commit}`], { cwd: dir, env, timeoutMs: 30000, signal });
    if (exists.aborted || (signal && signal.aborted)) return { ok: false, aborted: true, error: 'Sincronización Git cancelada' };
    if (exists.code !== 0) {
      return { ok: false, error: `El commit ${wanted.slice(0, 7)} no existe en «${branch}» o no es alcanzable desde ella` };
    }
    return { ok: true, ref: wanted };
  }

  /**
   * Lee el commit en el que ha quedado el árbol de trabajo.
   * @param {string} dir
   * @param {any} env
   * @param {AbortSignal | null} [signal]
   */
  async readHead(dir, env, signal = null) {
    // \x1f (unit separator) no puede aparecer en un asunto de commit, a
    // diferencia de cualquier carácter imprimible que se nos ocurra usar.
    const res = await runGit(['log', '-1', '--pretty=format:%H%x1f%an%x1f%s%x1f%cI'], { cwd: dir, env, timeoutMs: 30000, signal });
    if (res.code !== 0) {
      return { commit: null, shortCommit: null, subject: null, author: null, committedAt: null };
    }
    const [commit, author, subject, committedAt] = (res.stdout || '').split('\x1f');
    const sha = (commit || '').trim();
    return {
      commit: sha || null,
      shortCommit: sha ? sha.slice(0, 7) : null,
      subject: (subject || '').trim().slice(0, 300) || null,
      author: (author || '').trim().slice(0, 120) || null,
      committedAt: (committedAt || '').trim() || null
    };
  }

  /** Mensaje de error legible y sin credenciales a partir de un resultado de git. */
  errorOf(result, fallback) {
    if (result.aborted) return `${fallback}: operación cancelada`;
    if (result.timedOut) return `${fallback}: se agotó el tiempo de espera`;
    if (result.spawnError) return `${fallback}: no se pudo ejecutar git (${result.stderr})`;
    const text = localRunner.redactSecrets((result.stderr || result.stdout || '').trim());
    return text ? `${fallback}: ${text.slice(0, 500)}` : `${fallback} (código ${result.code})`;
  }
}

const instance = /** @type {any} */ (new RepoSync());
instance.RepoSync = RepoSync;
instance.helpers = { isValidBranch, isValidCommit, runGit };

module.exports = instance;
