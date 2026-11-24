/**
 * Tokenizador y validador seguro de comandos (cero shell, cero dependencias).
 *
 * Convierte cadenas o arrays de argumentos en un `argv: string[]` apto para
 * `spawn('docker', ['exec', ..., ...argv], { shell: false })`, rechazando
 * metacaracteres de shell, saltos de línea y caracteres de control.
 */

const FORBIDDEN_UNQUOTED_RE = /[;|&`<>]/;
const CMD_SUB_RE = /\$\(/;
const CONTROL_CHAR_RE = /[\0\r\n]/;
const SAFE_BIN_RE = /^[A-Za-z0-9._/@+-]+$/;
const SAFE_WORKDIR_RE = /^\/[A-Za-z0-9._/@+-]{0,200}$/;

/**
 * Parsea una cadena de comando o array en `string[]` sin invocar ningún shell.
 * @param {string | string[] | null | undefined} input
 * @param {{ maxArgs?: number, maxLength?: number }} [opts]
 * @returns {string[]}
 */
function parseSafeCommandArgv(input, { maxArgs = 64, maxLength = 1024 } = {}) {
  if (input == null) {
    throw new Error('Comando vacío');
  }

  /** @type {string[]} */
  let argv = [];

  if (Array.isArray(input)) {
    for (const part of input) {
      if (typeof part !== 'string') {
        throw new Error('Todos los argumentos del comando deben ser texto');
      }
      if (CONTROL_CHAR_RE.test(part)) {
        throw new Error('El comando contiene caracteres de control no permitidos');
      }
      if (part.length > maxLength) {
        throw new Error('Argumento de comando demasiado largo');
      }
      argv.push(part);
    }
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) throw new Error('Comando vacío');
    if (trimmed.length > maxLength) {
      throw new Error(`El comando supera el límite de ${maxLength} caracteres`);
    }
    if (CONTROL_CHAR_RE.test(trimmed)) {
      throw new Error('El comando no puede contener saltos de línea ni bytes nulos');
    }

    let current = '';
    /** @type {null | "'" | '"'} */
    let quote = null;
    let hasToken = false;

    for (let i = 0; i < trimmed.length; i++) {
      const ch = trimmed[i];
      if (quote) {
        if (ch === '\\' && quote === '"' && i + 1 < trimmed.length) {
          const next = trimmed[i + 1];
          if (next === '"' || next === '\\') {
            current += next;
            i++;
            continue;
          }
        }
        if (ch === quote) {
          quote = null;
          continue;
        }
        current += ch;
        continue;
      }

      if (ch === "'" || ch === '"') {
        quote = ch;
        hasToken = true;
        continue;
      }

      if (ch === '$' && trimmed[i + 1] === '(') {
        throw new Error('No se permiten sustituciones de shell "$(" en comandos');
      }
      if (FORBIDDEN_UNQUOTED_RE.test(ch)) {
        throw new Error(`Operador de shell no permitido ("${ch}"). Usa un comando directo sin pipes ni encadenamiento.`);
      }
      if (/\s/.test(ch)) {
        if (hasToken) {
          argv.push(current);
          current = '';
          hasToken = false;
        }
        continue;
      }
      current += ch;
      hasToken = true;
    }

    if (quote) {
      throw new Error('Comillas sin cerrar en el comando');
    }
    if (hasToken) {
      argv.push(current);
    }
  } else {
    throw new Error('Formato de comando inválido (debe ser string o string[])');
  }

  if (argv.length === 0) {
    throw new Error('Comando vacío');
  }
  if (argv.length > maxArgs) {
    throw new Error(`Demasiados argumentos (máximo ${maxArgs})`);
  }

  const bin = argv[0];
  if (!bin || bin.startsWith('-') || !SAFE_BIN_RE.test(bin)) {
    throw new Error(`Binario no válido al inicio del comando: "${String(bin).slice(0, 40)}"`);
  }
  if (CMD_SUB_RE.test(bin)) {
    throw new Error('Sustitución de comandos no permitida');
  }

  return argv;
}

/**
 * Valida un directorio de trabajo dentro de un contenedor Docker.
 * @param {string | null | undefined} workdir
 * @returns {string | null}
 */
function sanitizeWorkdir(workdir) {
  if (workdir == null || String(workdir).trim() === '') return null;
  const clean = String(workdir).trim();
  if (clean.includes('..') || CONTROL_CHAR_RE.test(clean) || !SAFE_WORKDIR_RE.test(clean)) {
    throw new Error(`Directorio de trabajo inválido: ${clean.slice(0, 60)}`);
  }
  return clean;
}

module.exports = {
  parseSafeCommandArgv,
  sanitizeWorkdir
};
