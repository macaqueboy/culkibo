const assert = require('assert');
const fs = require('fs');
const path = require('path');

/**
 * Prueba de regresión del compromiso público de Culkibo:
 *
 *   «Nunca se construyen comandos de shell. Los procesos se lanzan con spawn()
 *    y un array de argumentos; nunca concatenando cadenas.»
 *
 * Esa frase está en el README y es la diferencia entre una promesa y una
 * propiedad verificable. Esta suite la verifica: escanea TODO el código del
 * servidor, el CLI y los scripts buscando los patrones que reintroducen la
 * clase de fallo —21 avisos críticos en Coolify, 34 en Dokploy— y compara el
 * resultado con una lista de excepciones cerrada.
 *
 * La comparación es de IGUALDAD, no de inclusión, a propósito:
 *   - un hallazgo nuevo rompe la prueba (alguien reintrodujo el patrón);
 *   - una excepción que ya no aparece en el código también la rompe (la lista
 *     no puede pudrirse y acabar autorizando algo que nadie recuerda).
 *
 * Cada excepción lleva escrita la razón por la que es segura. Si no se puede
 * escribir la razón, no es una excepción: es un fallo.
 */

const ROOT = path.join(__dirname, '..');

/** Directorios y ficheros de código ejecutable del lado servidor. */
const SCAN_ROOTS = ['server', 'bin', 'scripts', 'bench', 'telemetry-collector'];

/** Sólo JavaScript. Los .sh y .ps1 SON shell; no se les aplica esta regla. */
const SCAN_EXT = new Set(['.js', '.cjs', '.mjs']);

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

/**
 * Los patrones prohibidos.
 *
 * `exec`/`execSync` están prohibidos en CUALQUIER forma, no sólo con plantilla:
 * ambos entregan su primer argumento a `cmd.exe` / `/bin/sh` entero. Que hoy el
 * argumento sea una constante no es una propiedad estable — basta con que
 * mañana alguien le interpole un nombre de proyecto.
 */
const RULES = [
  {
    id: 'exec-template',
    what: 'exec() con plantilla de cadena',
    // El lookbehind descarta métodos como `this.db.exec(\`SQL\`)` (SQLite) y `re.exec(...)`.
    re: /(?<![.\w$])exec\s*\(\s*`/
  },
  {
    id: 'execsync-template',
    what: 'execSync() con plantilla de cadena',
    re: /(?<![.\w$])execSync\s*\(\s*`/
  },
  {
    id: 'exec-literal',
    what: 'exec()/execSync() con cadena literal',
    re: /(?<![.\w$])(?:exec|execSync)\s*\(\s*['"]/
  },
  {
    id: 'exec-variable',
    what: 'exec()/execSync() con una variable',
    // El lookbehind descarta `regexp.exec(...)`, que no lanza nada.
    re: /(?<![.\w$])(?:exec|execSync)\s*\(\s*[A-Za-z_$][\w$]*\s*[,)]/
  },
  {
    id: 'cp-member-exec',
    what: 'child_process.exec()/execSync() directo o vía alias cp/childProcess',
    re: /(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\b(?:child_process|childProcess|cp))\s*\.\s*exec(?:Sync)?\s*\(/
  },
  {
    id: 'shell-true',
    what: 'shell: true',
    re: /\bshell\s*:\s*true\b/
  },
  {
    id: 'shell-interpreter',
    what: 'shell: "<intérprete>" (p. ej. shell: "/bin/sh")',
    re: /\bshell\s*:\s*['"`]/
  },
  {
    id: 'interpreter-spawn',
    what: 'se lanza un intérprete de comandos como programa',
    re: /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['"`](?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|sh|bash|zsh|\/bin\/(?:sh|bash))['"`]/
  }
];

/**
 * Excepciones autorizadas. Cada una tiene que decir POR QUÉ es segura.
 *
 * Regla de admisión: una excepción sólo es válida si ningún valor controlado
 * por el usuario puede llegar al intérprete, o si se valida antes de llegar.
 */
const ALLOWED = [
  {
    file: 'server/services/localRunner.js',
    rule: 'interpreter-spawn',
    contains: "spawn('cmd.exe', ['/c', bin, ...argv]",
    why: [
      'Windows no ofrece ninguna forma de lanzar npm / npx / vite sin cmd.exe:',
      'son shims .cmd, y desde la corrección de CVE-2024-27980 Node lanza EINVAL',
      'si se intenta con spawn() directo. Es el ÚNICO punto del proyecto donde se',
      'pasa por un intérprete, y está encapsulado en spawnTool(), que antes de',
      'llamar valida bin y cada argumento contra CMD_METACHARS (& | < > ^ " % CR LF)',
      'y rechaza el lanzamiento si alguno los contiene. `shell: false` impide',
      'además que Node añada una segunda capa de shell sobre la primera.'
    ].join(' ')
  },
  {
    file: 'server/services/localRunner.js',
    rule: 'interpreter-spawn',
    contains: "execFileSync('powershell', [",
    why: [
      'Consulta Get-NetTCPConnection para averiguar qué proceso ocupa un puerto;',
      'no existe equivalente nativo en Node ni utilidad no-PowerShell fiable en',
      'Windows Server. Se lanza powershell.exe por argv (execFileSync), sin cmd.exe',
      'intermedio, con -NoProfile -NonInteractive. Lo único que se interpola en el',
      'script es numPort, que en esa función ya ha pasado por parseInt() y por una',
      'comprobación isNaN: es un entero, no hay nada que un llamante pueda inyectar.'
    ].join(' ')
  }
];

function listFiles(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return out;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      listFiles(path.join(dir, entry.name), out);
    } else if (SCAN_EXT.has(path.extname(entry.name))) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/**
 * Una línea cuyo texto empieza por `//`, `*` o `/*` es documentación.
 * Se salta entera: este fichero y los módulos que arregló describen los
 * patrones prohibidos en prosa, y describirlos no es cometerlos.
 */
function isCommentLine(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*');
}

function scanRepository() {
  const findings = [];
  for (const root of SCAN_ROOTS) {
    for (const abs of listFiles(path.join(ROOT, root))) {
      const rel = path.relative(ROOT, abs).split(path.sep).join('/');
      const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
      lines.forEach((line, i) => {
        if (isCommentLine(line)) return;
        for (const rule of RULES) {
          if (rule.re.test(line)) {
            findings.push({ file: rel, rule: rule.id, what: rule.what, line: i + 1, text: line.trim() });
          }
        }
      });
    }
  }
  return findings;
}

function testShellSafety() {
  console.log('🧪 Testing Shell-Safety Invariant (sin construcción de comandos de shell)...');

  // Esta suite se audita a sí misma: los patrones viven aquí como expresiones
  // regulares, no como llamadas, así que el fichero de pruebas no se escanea.
  const findings = scanRepository().filter(f => f.file !== 'tests/shell-safety.test.js');

  const matchesAllowance = (finding, allowance) =>
    finding.file === allowance.file &&
    finding.rule === allowance.rule &&
    finding.text.includes(allowance.contains);

  // 1. Ningún hallazgo sin excepción escrita.
  const unauthorized = findings.filter(f => !ALLOWED.some(a => matchesAllowance(f, a)));
  if (unauthorized.length > 0) {
    const detail = unauthorized
      .map(f => `    ${f.file}:${f.line}  [${f.rule}] ${f.what}\n      ${f.text}`)
      .join('\n');
    assert.fail(
      'Se ha reintroducido la construcción de comandos de shell.\n' +
      'Culkibo afirma públicamente que esto no ocurre; el README deja de ser cierto.\n' +
      'Reescríbelo con spawn/execFile y un array de argumentos, o añade una\n' +
      'excepción a ALLOWED en tests/shell-safety.test.js justificando por qué es\n' +
      'segura (qué valor llega, de dónde viene y quién lo valida).\n\n' +
      `  Hallazgos sin autorizar (${unauthorized.length}):\n${detail}\n`
    );
  }

  // 2. Ninguna excepción huérfana: si el código ya no la contiene, sobra.
  //    Sin esto la lista crecería y acabaría autorizando código inexistente,
  //    que es como se cuelan los patrones la segunda vez.
  const orphans = ALLOWED.filter(a => !findings.some(f => matchesAllowance(f, a)));
  assert.strictEqual(
    orphans.length, 0,
    'Hay excepciones en ALLOWED que ya no corresponden a ningún código:\n' +
    orphans.map(a => `    ${a.file} [${a.rule}] ${a.contains}`).join('\n') +
    '\nBórralas: una excepción que no señala a nada acaba autorizando otra cosa.'
  );

  // 3. Toda excepción tiene una justificación de verdad, no un «TODO».
  for (const a of ALLOWED) {
    assert.ok(
      typeof a.why === 'string' && a.why.length >= 80,
      `La excepción ${a.file} [${a.rule}] no explica por qué es segura.`
    );
  }

  // 4. Los módulos que más manipulan entrada del usuario no pueden ni siquiera
  //    importar exec/execSync: sin la función a mano, no hay descuido posible.
  //    Detecta comillas simples/dobles, `node:child_process` y destructuring multilínea.
  const MUST_NOT_IMPORT_EXEC = [
    'server/services/dockerManager.js',
    'server/services/localRunner.js',
    'server/services/deployManager.js',
    'server/services/databaseManager.js',
    'server/services/dbBackupManager.js',
    'server/services/caddyManager.js',
    'server/services/serverFleetManager.js',
    'server/services/sleepAdvisor.js',
    'server/services/teamManager.js',
    'server/services/environmentManager.js',
    'server/services/gitopsManager.js',
    'server/services/uptimeMonitor.js',
    'server/services/previewManager.js',
    'server/services/repoSync.js',
    'server/services/catalogManager.js',
    'server/services/cronManager.js',
    'server/services/universalImporter.js',
    'server/services/wordpressMigrator.js',
    'telemetry-collector/server.js',
    'telemetry-collector/lib/storage.js'
  ];
  const cpImportRe = /(?:const|let|var)\s+(\{[^}]*\}|\w+)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g;
  for (const rel of MUST_NOT_IMPORT_EXEC) {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) continue;
    const src = fs.readFileSync(abs, 'utf8');
    // Quitar comentarios de línea y bloque antes de inspeccionar imports
    const stripped = src
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    let m;
    cpImportRe.lastIndex = 0;
    while ((m = cpImportRe.exec(stripped)) !== null) {
      const binding = m[1];
      const withoutExecFile = binding.replace(/\bexecFile(?:Sync)?\b/g, '');
      assert.ok(
        !/\bexec\b/.test(withoutExecFile) && !/\bexecSync\b/.test(withoutExecFile),
        `${rel} importa exec/execSync de child_process. Usa execFile/spawn:\n    ${m[0].trim()}`
      );
    }
  }

  console.log(`  ✓ Ningún punto sin autorizar en ${SCAN_ROOTS.join(', ')} (${findings.length} coincidencias, todas conocidas)`);
  console.log(`  ✓ ${ALLOWED.length} excepciones autorizadas, todas presentes y justificadas`);
  console.log(`  ✓ ${MUST_NOT_IMPORT_EXEC.length} módulos críticos no importan exec/execSync`);
  console.log('✅ All shell-safety tests passed!\n');
}

module.exports = testShellSafety;

if (require.main === module) {
  try {
    testShellSafety();
  } catch (err) {
    console.error('❌ Shell-safety test failure:', err.message);
    process.exit(1);
  }
}
