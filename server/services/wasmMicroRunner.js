const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { Worker } = require('worker_threads');

const { assertContainedPath } = require('./ssrfGuard');

/**
 * Runtime Edge Micro-Wasm Aislado (<2 ms) — Cero Binarios Externos, Cero Dependencias.
 *
 * Usa exclusivamente las primitivas integradas de Node.js (`WebAssembly` + `worker_threads`):
 *  - Detección automática de aplicaciones `spin.toml` y módulos `*.wasm` (`detectWasmHandler`).
 *  - Aislamiento estricto en `worker_threads` con `resourceLimits` (32 MB heap), 0 acceso a
 *    `fs`/`net`/`http`/`child_process`, caché de `WebAssembly.Module` compilado por SHA-256
 *    para ejecuciones repetidas en `<2 ms`, y terminación dura (`worker.terminate()`) ante
 *    bucles infinitos o excesos de `timeoutMs`.
 */

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);
const DEFAULT_MAX_WASM_BYTES = 4 * 1024 * 1024; // 4 MiB
const DEFAULT_TIMEOUT_MS = 2000;
const MIN_TIMEOUT_MS = 25;
const MAX_TIMEOUT_MS = 10000;

/**
 * Código del sandbox ejecutado dentro de `worker_threads`.
 * NO importa `fs`, `net`, `http`, `https`, `child_process` ni `os`: únicamente
 * recibe bytes `.wasm` validados, los compila/instancia con `WebAssembly` sin imports
 * del host y devuelve `{ result, memoryBytes, execMs }`.
 */
const ISOLATED_WASM_WORKER_CODE = `'use strict';
const { parentPort } = require('worker_threads');
const { performance } = require('perf_hooks');

const moduleCache = new Map();
const MAX_CACHE = 32;

parentPort.on('message', async (msg) => {
  const { id, cacheKey, wasmBytes, exportName, args } = msg;
  const t0 = performance.now();
  try {
    let mod = cacheKey ? moduleCache.get(cacheKey) : null;
    if (!mod) {
      const bytes = wasmBytes instanceof Uint8Array ? wasmBytes : new Uint8Array(wasmBytes);
      mod = await WebAssembly.compile(bytes);
      if (cacheKey) {
        if (moduleCache.size >= MAX_CACHE) {
          const oldestKey = moduleCache.keys().next().value;
          moduleCache.delete(oldestKey);
        }
        moduleCache.set(cacheKey, mod);
      }
    }

    const instance = await WebAssembly.instantiate(mod, Object.create(null));
    const exportsObj = instance.exports || {};
    const targetName = exportName && typeof exportsObj[exportName] === 'function'
      ? exportName
      : (typeof exportsObj.handle === 'function'
          ? 'handle'
          : Object.keys(exportsObj).find((k) => typeof exportsObj[k] === 'function'));

    if (!targetName) {
      throw new Error('WASM module exposes no callable exported function');
    }

    const fn = exportsObj[targetName];
    const callArgs = Array.isArray(args) ? args.map((v) => Number(v) || 0) : [];
    const result = fn(...callArgs);

    let memoryBytes = 0;
    if (exportsObj.memory && exportsObj.memory.buffer) {
      memoryBytes = exportsObj.memory.buffer.byteLength;
    }
    const execMs = Number((performance.now() - t0).toFixed(3));
    parentPort.postMessage({
      id,
      ok: true,
      exportName: targetName,
      result,
      memoryBytes,
      execMs
    });
  } catch (err) {
    const execMs = Number((performance.now() - t0).toFixed(3));
    parentPort.postMessage({
      id,
      ok: false,
      error: err && err.message ? err.message : String(err),
      execMs
    });
  }
});
`;

/**
 * Genera un módulo WebAssembly MVP 100% válido y autocontenido que exporta:
 *  - `memory`: 1 página (64 KiB, máximo 4 páginas)
 *  - `handle(x: i32) -> i32`: retorna `x * 2 + 1`
 * @returns {Buffer}
 */
function buildMinimalHttpTestWasm() {
  return Buffer.from([
    // Header: \0asm v1
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    // Type section (1): 1 func (i32) -> (i32)
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    // Function section (3): func 0 uses type 0
    0x03, 0x02, 0x01, 0x00,
    // Memory section (5): 1 memory, min=1 page (64 KiB), max=4 pages
    0x05, 0x04, 0x01, 0x01, 0x01, 0x04,
    // Export section (7): "handle" (func 0), "memory" (mem 0)
    0x07, 0x13, 0x02,
    0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x00, 0x00,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    // Code section (10): local.get 0; i32.const 2; i32.mul; i32.const 1; i32.add; end
    0x0a, 0x0c, 0x01, 0x0a,
    0x00,
    0x20, 0x00,
    0x41, 0x02,
    0x6c,
    0x41, 0x01,
    0x6a,
    0x0b
  ]);
}

/**
 * Genera un módulo WebAssembly válido cuyo export `handle(i32) -> i32` entra en un
 * bucle infinito (`loop br 0 end`), diseñado para verificar terminación por timeout.
 * @returns {Buffer}
 */
function buildInfiniteLoopTestWasm() {
  return Buffer.from([
    // Header: \0asm v1
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    // Type section (1): 1 func (i32) -> (i32)
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    // Function section (3): func 0 uses type 0
    0x03, 0x02, 0x01, 0x00,
    // Memory section (5): 1 memory, min=1 page, max=2 pages
    0x05, 0x04, 0x01, 0x01, 0x01, 0x02,
    // Export section (7): "handle" (func 0), "memory" (mem 0)
    0x07, 0x13, 0x02,
    0x06, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x00, 0x00,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    // Code section (10): loop (void) br 0 end; i32.const 0; end
    0x0a, 0x0b, 0x01, 0x09,
    0x00,
    0x03, 0x40,
    0x0c, 0x00,
    0x0b,
    0x41, 0x00,
    0x0b
  ]);
}

/**
 * Valida la cabecera mágica `\0asm` y límites de tamaño de un buffer WASM.
 * @param {Buffer | Uint8Array} raw
 * @param {number} [maxBytes]
 * @returns {Buffer}
 */
function assertValidWasmBuffer(raw, maxBytes = DEFAULT_MAX_WASM_BYTES) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  if (buf.length < 8) {
    throw new Error('Módulo WASM demasiado corto (< 8 bytes)');
  }
  if (buf.length > maxBytes) {
    throw new Error(`Módulo WASM supera el tamaño máximo permitido (${maxBytes} bytes)`);
  }
  if (!buf.subarray(0, 4).equals(WASM_MAGIC)) {
    throw new Error('Cabecera mágica WebAssembly inválida (se esperaba \\0asm)');
  }
  return buf;
}

/**
 * Parsea de forma segura los campos clave de un `spin.toml` (sin dependencias TOML externas).
 * @param {string} tomlText
 * @param {string} baseDir
 */
function parseSpinManifest(tomlText, baseDir) {
  const lines = String(tomlText || '').split(/\r?\n/);
  /** @type {Array<{ id: string, source: string, wasmPath: string | null, route: string }>} */
  const components = [];
  /** @type {{ id: string, source: string, route: string } | null} */
  let currentComp = null;
  let defaultRoute = '/';

  const flushComp = () => {
    if (!currentComp) return;
    /** @type {string | null} */
    let resolvedWasm = null;
    if (currentComp.source) {
      resolvedWasm = assertContainedPath(baseDir, currentComp.source);
    }
    components.push({
      id: currentComp.id || `component_${components.length + 1}`,
      source: currentComp.source,
      wasmPath: resolvedWasm,
      route: currentComp.route || defaultRoute
    });
    currentComp = null;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;

    // Formato Spin v1 (`[[component]]`) y Spin v2 (`[component.<id>]`)
    const compV2 = line.match(/^\[component\.([a-zA-Z0-9_-]+)\]$/);
    if (compV2) {
      flushComp();
      currentComp = { id: compV2[1], source: '', route: defaultRoute };
      continue;
    }
    if (line === '[[component]]') {
      flushComp();
      currentComp = { id: '', source: '', route: defaultRoute };
      continue;
    }
    if (line.startsWith('[')) {
      // Sección auxiliar (p.ej. `[[trigger.http]]` o `[component.x.build]`)
      if (line.startsWith('[[trigger.http]]') || line.startsWith('[trigger.http]')) {
        flushComp();
      }
      continue;
    }

    const kv = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const key = kv[1];
    const val = kv[2].trim().replace(/^["']|["']$/g, '');

    if (key === 'route') {
      if (currentComp) currentComp.route = val || '/';
      else defaultRoute = val || '/';
    } else if (currentComp) {
      if (key === 'id') currentComp.id = val;
      else if (key === 'source') currentComp.source = val;
    }
  }
  flushComp();

  return components;
}

/**
 * Detecta manejadores Micro-Wasm (`spin.toml` o archivos `*.wasm`) dentro de un directorio
 * de proyecto con contención estricta de rutas (rechaza path traversal).
 *
 * @param {string} dir
 */
function detectWasmHandler(dir) {
  if (!dir || typeof dir !== 'string' || /[\0\r\n]/.test(dir)) {
    return { detected: false, kind: null, manifestPath: null, wasmPath: null, route: null, components: [] };
  }
  const baseDir = path.resolve(dir);
  if (!fs.existsSync(baseDir) || !fs.statSync(baseDir).isDirectory()) {
    return { detected: false, kind: null, manifestPath: null, wasmPath: null, route: null, components: [] };
  }

  // 1. Detectar `spin.toml` (Fermyon Spin / WASI HTTP)
  const spinPath = path.join(baseDir, 'spin.toml');
  if (fs.existsSync(spinPath) && fs.statSync(spinPath).isFile()) {
    const content = fs.readFileSync(spinPath, 'utf8');
    const components = parseSpinManifest(content, baseDir);
    const primary = components.find((c) => c.wasmPath) || components[0] || null;
    return {
      detected: true,
      kind: 'spin',
      manifestPath: spinPath,
      wasmPath: primary ? primary.wasmPath : null,
      route: primary ? primary.route : '/',
      components
    };
  }

  // 2. Buscar módulos `*.wasm` en raíz o directorios de salida estándar
  const probeSubdirs = [
    '',
    'dist',
    'build',
    path.join('target', 'wasm32-wasip1', 'release'),
    path.join('target', 'wasm32-wasi', 'release'),
    path.join('target', 'wasm32-unknown-unknown', 'release')
  ];
  /** @type {Array<{ id: string, source: string, wasmPath: string, route: string }>} */
  const found = [];
  for (const sub of probeSubdirs) {
    const probeDir = sub ? path.join(baseDir, sub) : baseDir;
    if (!fs.existsSync(probeDir) || !fs.statSync(probeDir).isDirectory()) continue;
    const entries = fs.readdirSync(probeDir, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.isFile() && ent.name.toLowerCase().endsWith('.wasm')) {
        const rel = sub ? path.join(sub, ent.name) : ent.name;
        const abs = assertContainedPath(baseDir, rel);
        found.push({
          id: path.basename(ent.name, '.wasm'),
          source: rel.split(path.sep).join('/'),
          wasmPath: abs,
          route: '/'
        });
      }
    }
    if (found.length > 0) break;
  }

  if (found.length > 0) {
    return {
      detected: true,
      kind: 'wasm',
      manifestPath: null,
      wasmPath: found[0].wasmPath,
      route: '/',
      components: found
    };
  }

  return { detected: false, kind: null, manifestPath: null, wasmPath: null, route: null, components: [] };
}

class WasmMicroRunner {
  /**
   * @param {{ maxWasmBytes?: number, defaultTimeoutMs?: number, maxOldGenerationSizeMb?: number }} [opts]
   */
  constructor(opts = {}) {
    this.maxWasmBytes = Math.min(16 * 1024 * 1024, Math.max(4096, Number(opts.maxWasmBytes) || DEFAULT_MAX_WASM_BYTES));
    this.defaultTimeoutMs = Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Number(opts.defaultTimeoutMs) || DEFAULT_TIMEOUT_MS));
    this.maxOldGenerationSizeMb = Math.min(128, Math.max(16, Number(opts.maxOldGenerationSizeMb) || 32));
    /** @type {Worker | null} */
    this._worker = null;
    this._workerBusy = false;
    this._reqSeq = 0;
  }

  /** Crea (o reutiliza si libre) un `worker_threads` aislado con límites estrictos de memoria. */
  _acquireWorker(ephemeral = false) {
    const createIsolatedWorker = () => {
      const w = new Worker(ISOLATED_WASM_WORKER_CODE, {
        eval: true,
        resourceLimits: {
          maxOldGenerationSizeMb: this.maxOldGenerationSizeMb,
          maxYoungGenerationSizeMb: 8,
          stackSizeMb: 2
        }
      });
      w.unref();
      return w;
    };

    if (ephemeral || this._workerBusy) {
      return { worker: createIsolatedWorker(), pooled: false };
    }
    if (!this._worker) {
      const w = createIsolatedWorker();
      this._worker = w;
      w.on('exit', () => {
        if (this._worker === w) this._worker = null;
      });
    }
    this._workerBusy = true;
    return { worker: this._worker, pooled: true };
  }

  /**
   * Ejecuta un módulo `.wasm` real dentro de un sandbox `worker_threads` aislado,
   * midiendo el tiempo exacto de ejecución (`execMs`) y forzando `worker.terminate()`
   * ante cualquier exceso de `timeoutMs`.
   *
   * @param {{
   *   wasmBytes?: Buffer | Uint8Array | string,
   *   wasmPath?: string,
   *   exportName?: string,
   *   args?: number[],
   *   input?: number,
   *   timeoutMs?: number,
   *   ephemeral?: boolean,
   *   cacheKey?: string
   * }} opts
   */
  async invoke(opts = {}) {
    const wallStart = performance.now();
    const timeoutMs = Math.min(
      MAX_TIMEOUT_MS,
      Math.max(MIN_TIMEOUT_MS, Number(opts.timeoutMs) || this.defaultTimeoutMs)
    );

    /** @type {Buffer} */
    let wasmBuffer;
    if (opts.wasmBytes != null) {
      const raw = typeof opts.wasmBytes === 'string'
        ? Buffer.from(opts.wasmBytes, 'base64')
        : opts.wasmBytes;
      wasmBuffer = assertValidWasmBuffer(raw, this.maxWasmBytes);
    } else if (opts.wasmPath) {
      const absPath = path.resolve(String(opts.wasmPath));
      if (!fs.existsSync(absPath)) {
        throw new Error(`Archivo WASM no encontrado: ${absPath}`);
      }
      const stat = fs.statSync(absPath);
      if (stat.size > this.maxWasmBytes) {
        throw new Error(`Archivo WASM supera el límite de ${this.maxWasmBytes} bytes`);
      }
      wasmBuffer = assertValidWasmBuffer(fs.readFileSync(absPath), this.maxWasmBytes);
    } else {
      throw new Error('WasmMicroRunner.invoke requiere wasmBytes o wasmPath');
    }

    const args = Array.isArray(opts.args)
      ? opts.args.map((n) => Number(n) || 0)
      : (opts.input !== undefined ? [Number(opts.input) || 0] : [0]);
    const exportName = opts.exportName ? String(opts.exportName).trim() : 'handle';
    const cacheKey = opts.cacheKey
      || crypto.createHash('sha256').update(wasmBuffer).digest('hex').slice(0, 24);

    const { worker, pooled } = this._acquireWorker(Boolean(opts.ephemeral));
    const reqId = ++this._reqSeq;

    return new Promise((resolve, reject) => {
      let settled = false;
      /** @type {ReturnType<typeof setTimeout> | null} */
      let timer = null;

      const cleanupListeners = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        worker.removeListener('message', onMessage);
        worker.removeListener('error', onError);
        worker.removeListener('exit', onExit);
        if (pooled) {
          this._workerBusy = false;
        } else {
          worker.terminate().catch(() => {});
        }
      };

      const terminateAndFail = (err) => {
        if (settled) return;
        settled = true;
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        worker.removeListener('message', onMessage);
        worker.removeListener('error', onError);
        worker.removeListener('exit', onExit);
        if (pooled) {
          this._workerBusy = false;
          if (this._worker === worker) this._worker = null;
        }
        worker.terminate().catch(() => {});
        reject(err);
      };

      const onMessage = (msg) => {
        if (!msg || msg.id !== reqId || settled) return;
        settled = true;
        cleanupListeners();
        const wallMs = Number((performance.now() - wallStart).toFixed(3));
        if (!msg.ok) {
          const err = new Error(msg.error || 'Error ejecutando módulo WASM');
          /** @type {any} */ (err).code = 'WASM_EXECUTION_ERROR';
          /** @type {any} */ (err).execMs = msg.execMs;
          reject(err);
          return;
        }
        resolve({
          ok: true,
          status: 200,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'x-culkibo-runtime': 'micro-wasm',
            'x-culkibo-exec-ms': String(msg.execMs)
          },
          body: JSON.stringify({
            ok: true,
            exportName: msg.exportName,
            result: msg.result,
            execMs: msg.execMs,
            memoryBytes: msg.memoryBytes
          }),
          result: msg.result,
          exportName: msg.exportName,
          execMs: msg.execMs,
          wallMs,
          memoryBytes: msg.memoryBytes,
          sandboxed: true
        });
      };

      const onError = (err) => {
        const wrapped = new Error(`Fallo en sandbox Micro-Wasm: ${err && err.message ? err.message : String(err)}`);
        /** @type {any} */ (wrapped).code = 'WASM_SANDBOX_ERROR';
        terminateAndFail(wrapped);
      };

      const onExit = (code) => {
        if (settled) return;
        const wrapped = new Error(`Sandbox Micro-Wasm terminó inesperadamente (código ${code})`);
        /** @type {any} */ (wrapped).code = 'WASM_SANDBOX_EXIT';
        terminateAndFail(wrapped);
      };

      timer = setTimeout(() => {
        const timeoutErr = new Error(`Ejecución Micro-Wasm abortada por timeout (${timeoutMs} ms)`);
        /** @type {any} */ (timeoutErr).code = 'WASM_TIMEOUT';
        /** @type {any} */ (timeoutErr).status = 504;
        /** @type {any} */ (timeoutErr).timedOut = true;
        terminateAndFail(timeoutErr);
      }, timeoutMs);
      if (timer.unref) timer.unref();

      worker.on('message', onMessage);
      worker.on('error', onError);
      worker.on('exit', onExit);

      worker.postMessage({
        id: reqId,
        cacheKey,
        wasmBytes: wasmBuffer,
        exportName,
        args
      });
    });
  }

  /**
   * Invoca el handler Micro-Wasm asociado a un proyecto (o bytes base64 explícitos en `req`).
   * @param {any} project
   * @param {{ wasmBase64?: string, wasmPath?: string, exportName?: string, args?: number[], input?: number, timeoutMs?: number }} [req]
   */
  async invokeProject(project, req = {}) {
    if (req.wasmBase64) {
      return this.invoke({
        wasmBytes: req.wasmBase64,
        exportName: req.exportName,
        args: req.args,
        input: req.input,
        timeoutMs: req.timeoutMs
      });
    }
    const projectDir = project && (project.localPath || project.repoDir || project.directory || null);
    if (req.wasmPath) {
      const safePath = projectDir ? assertContainedPath(projectDir, req.wasmPath) : path.resolve(req.wasmPath);
      return this.invoke({
        wasmPath: safePath,
        exportName: req.exportName,
        args: req.args,
        input: req.input,
        timeoutMs: req.timeoutMs
      });
    }
    if (projectDir) {
      const detected = detectWasmHandler(projectDir);
      if (detected.detected && detected.wasmPath) {
        return this.invoke({
          wasmPath: detected.wasmPath,
          exportName: req.exportName,
          args: req.args,
          input: req.input,
          timeoutMs: req.timeoutMs
        });
      }
    }
    throw new Error('No se encontró ningún handler .wasm o spin.toml para este proyecto (envía wasmBase64 o despliega un módulo .wasm)');
  }

  /** Termina el worker reutilizable de forma limpia (para cierre ordenado o tests). */
  async shutdown() {
    if (this._worker) {
      const w = this._worker;
      this._worker = null;
      this._workerBusy = false;
      await w.terminate().catch(() => {});
    }
  }
}

const instance = /** @type {any} */ (new WasmMicroRunner());
instance.WasmMicroRunner = WasmMicroRunner;
instance.detectWasmHandler = detectWasmHandler;
instance.buildMinimalHttpTestWasm = buildMinimalHttpTestWasm;
instance.buildInfiniteLoopTestWasm = buildInfiniteLoopTestWasm;
module.exports = instance;
