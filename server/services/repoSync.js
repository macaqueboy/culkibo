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
  return /^[A-Za-z0-9._/-]+$/.test(branch);
}

/** Un SHA abreviado o completo, en minúsculas y sin nada más. */
function isValidCommit(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{7,40}$/.test(value.trim());
}

/**
 * Lanza git con un array de argumentos y transmite su salida línea a línea.
 * No lanza nunca: devuelve el código y lo capturado, como `deployManager.runTool`.
 *
 * @param {string[]} args
 * @param {{cwd?: string, env?: any, timeoutMs?: number, onLine?: ((line: string) => void) | null}} [options]
 * @returns {Promise<{code: number, stdout: string, stderr: string, spawnError?: boolean, timedOut?: boolean}>}
 */
function runGit(args, { cwd = undefined, env = undefined, timeoutMs = 120000, onLine = null } = {}) {
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
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch (e) {}
    }, timeoutMs);
    if (timer.unref) timer.unref();

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout: stdout.join(''), stderr: err.message, spawnError: true });
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (onLine && buffered.trim()) onLine(buffered.trim());
      resolve({ code: timedOut ? -2 : code, stdout: stdout.join(''), stderr: stderr.join(''), timedOut });
    });
  });
}

class RepoSync {
  /** Directorio de trabajo del proyecto en este host. */
  projectDir(project) {
    return path.join(process.cwd(), 'projects', project.id);
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
   * @param {{commit?: string | null, onLine?: ((line: string) => void) | null, timeoutMs?: number}} [options]
   */
  async sync(project, { commit = null, onLine = null, timeoutMs = 300000 } = {}) {
    const dir = this.projectDir(project);
    const emit = (message) => { if (onLine) onLine(localRunner.redactSecrets(message)); };

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
    const display = localRunner.redactSecrets(rawUrl);
    const { env, cleanup } = localRunner.gitAuthEnv();

    try {
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
        try {
          await localRunner.gitClone(String(cloneUrl), dir, { timeout: timeoutMs, depth: 1, branch, onLine: emit });
        } catch (err) {
          return { ok: false, error: localRunner.redactSecrets(err.message), dir, dirtyFiles: [] };
        }

        if (wanted) {
          const deepened = await this.fetchCommit(dir, env, wanted, branch, timeoutMs, emit);
          if (!deepened.ok) return { ...deepened, dir, dirtyFiles: [] };
          const checkout = await runGit(['checkout', '-B', branch, deepened.ref], { cwd: dir, env, timeoutMs: 60000, onLine: emit });
          if (checkout.code !== 0) {
            return { ok: false, error: this.errorOf(checkout, `No se pudo situar el repositorio en ${wanted}`), dir, dirtyFiles: [] };
          }
        }

        const head = await this.readHead(dir, env);
        return { ok: true, action: 'clonado', reason: null, dir, branch, previousCommit: null, dirtyFiles: [], ...head };
      }

      // --- Caso 2: ya hay repositorio -------------------------------------
      const before = await runGit(['rev-parse', 'HEAD'], { cwd: dir, env, timeoutMs: 20000 });
      const previousCommit = before.code === 0 ? (before.stdout || '').trim() : null;

      // El remoto puede haber cambiado, y además `normalizeGitUrl` incorpora el
      // usuario `x-access-token` solo cuando hay token: si la cuenta de GitHub
      // se conectó DESPUÉS del clon, la URL guardada pediría contraseña por
      // terminal y, con GIT_TERMINAL_PROMPT=0, el fetch fallaría sin explicar
      // por qué.
      const currentRemote = await runGit(['remote', 'get-url', 'origin'], { cwd: dir, env, timeoutMs: 20000 });
      if (currentRemote.code !== 0) {
        await runGit(['remote', 'add', 'origin', '--', String(cloneUrl)], { cwd: dir, env, timeoutMs: 20000 });
      } else if ((currentRemote.stdout || '').trim() !== cloneUrl) {
        emit('El repositorio remoto configurado ha cambiado; se actualiza «origin».');
        const setUrl = await runGit(['remote', 'set-url', 'origin', '--', String(cloneUrl)], { cwd: dir, env, timeoutMs: 20000 });
        if (setUrl.code !== 0) {
          return { ok: false, error: this.errorOf(setUrl, 'No se pudo actualizar la URL del repositorio'), dir, dirtyFiles: [] };
        }
      }

      // Árbol sucio. Se descarta, pero se dice qué se descarta: perder cambios
      // en silencio es peor que perderlos.
      const status = await runGit(['status', '--porcelain'], { cwd: dir, env, timeoutMs: 60000 });
      const dirtyFiles = (status.stdout || '')
        .split(/\r?\n/)
        .map(s => s.trim())
        .filter(Boolean)
        .slice(0, 50);

      if (dirtyFiles.length > 0) {
        const sample = dirtyFiles.slice(0, 5).join(', ');
        emit(`El árbol de trabajo tenía ${dirtyFiles.length} cambio(s) sin confirmar; se descartan: ${sample}${dirtyFiles.length > 5 ? ', ...' : ''}`);
        const reset = await runGit(['reset', '--hard'], { cwd: dir, env, timeoutMs: 120000, onLine: emit });
        if (reset.code !== 0) {
          return { ok: false, error: this.errorOf(reset, 'No se pudo descartar los cambios locales'), dir, dirtyFiles };
        }
      }

      // `clean` sin `-x`: los ficheros ignorados (un .env local, por ejemplo)
      // sobreviven. `node_modules` y `.culkibo` se excluyen porque volver a
      // instalarlos en cada despliegue es tirar la caché a la basura, que es
      // exactamente cómo Coolify pasó de 1 a 4,5 minutos de build.
      await runGit(
        ['clean', '-fd', '--exclude=node_modules', '--exclude=.culkibo'],
        { cwd: dir, env, timeoutMs: 120000, onLine: emit }
      );

      /** @type {string} */
      let ref;
      if (wanted) {
        const fetched = await this.fetchCommit(dir, env, wanted, branch, timeoutMs, emit);
        if (!fetched.ok) return { ...fetched, dir, dirtyFiles };
        ref = fetched.ref;
      } else {
        emit(`Trayendo refs/heads/${branch} desde origin...`);
        const fetch = await runGit(
          ['fetch', '--depth', '1', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`],
          { cwd: dir, env, timeoutMs, onLine: emit }
        );
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

      // `checkout -B` crea la rama si no existe y la reposiciona si existe: es
      // el mismo comando para «primera vez», «misma rama» y «rama cambiada».
      const checkout = await runGit(['checkout', '-B', branch, ref], { cwd: dir, env, timeoutMs: 120000, onLine: emit });
      if (checkout.code !== 0) {
        return { ok: false, error: this.errorOf(checkout, `No se pudo situar el repositorio en «${branch}»`), dir, dirtyFiles };
      }

      const head = await this.readHead(dir, env);
      const action = previousCommit && head.commit === previousCommit ? 'sin-cambios' : 'actualizado';
      return { ok: true, action, reason: null, dir, branch, previousCommit, dirtyFiles, ...head };
    } finally {
      cleanup();
    }
  }

  /**
   * Trae un commit suelto.
   *
   * GitHub permite pedir un SHA concreto (`uploadpack.allowReachableSHA1InWant`),
   * pero no todos los servidores lo hacen. Si el remoto lo rechaza, en vez de
   * fallar se profundiza el clon —que es lento pero funciona en cualquier
   * servidor— y se busca el objeto ahí.
   */
  async fetchCommit(dir, env, wanted, branch, timeoutMs, emit) {
    emit(`Trayendo el commit ${wanted.slice(0, 7)} desde origin...`);
    const direct = await runGit(['fetch', '--depth', '1', '--force', 'origin', wanted], { cwd: dir, env, timeoutMs, onLine: emit });
    if (direct.code === 0) return { ok: true, ref: 'FETCH_HEAD' };

    emit('El servidor no permite pedir un commit suelto; se recupera el historial completo de la rama.');
    const unshallow = await runGit(['fetch', '--unshallow', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`], {
      cwd: dir, env, timeoutMs, onLine: emit
    });
    if (unshallow.code !== 0) {
      // `--unshallow` falla si el clon ya era completo; en ese caso basta un
      // fetch normal.
      const plain = await runGit(['fetch', '--force', 'origin', `+refs/heads/${branch}:refs/remotes/origin/${branch}`], {
        cwd: dir, env, timeoutMs, onLine: emit
      });
      if (plain.code !== 0) {
        return { ok: false, error: this.errorOf(plain, `No se pudo traer el historial de «${branch}»`) };
      }
    }

    const exists = await runGit(['cat-file', '-e', `${wanted}^{commit}`], { cwd: dir, env, timeoutMs: 30000 });
    if (exists.code !== 0) {
      return { ok: false, error: `El commit ${wanted.slice(0, 7)} no existe en «${branch}» o no es alcanzable desde ella` };
    }
    return { ok: true, ref: wanted };
  }

  /** Lee el commit en el que ha quedado el árbol de trabajo. */
  async readHead(dir, env) {
    // \x1f (unit separator) no puede aparecer en un asunto de commit, a
    // diferencia de cualquier carácter imprimible que se nos ocurra usar.
    const res = await runGit(['log', '-1', '--pretty=format:%H%x1f%an%x1f%s%x1f%cI'], { cwd: dir, env, timeoutMs: 30000 });
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
