const mcpServer = require('./mcpServer');

/**
 * Transporte Streamable HTTP de MCP, revisión 2026-07-28.
 *
 * Qué cambió respecto a lo que Culkibo servía (HTTP+SSE de 2024-11-05):
 *
 *  - No hay handshake. No existe `initialize`. Cada POST declara su versión en
 *    `_meta` y en la cabecera `MCP-Protocol-Version`, y el servidor la acepta o
 *    la rechaza por separado. El servidor no guarda estado entre peticiones.
 *  - Un solo endpoint y solo POST. El GET que abría el stream desapareció:
 *    ahora GET y DELETE se contestan con 405.
 *  - No hay sesiones (`Mcp-Session-Id`) ni reanudación (`Last-Event-ID`). Si
 *    llegan esas cabeceras se ignoran; no se acuñan ni se devuelven.
 *  - Cerrar el stream SSE *es* la cancelación. No hay `notifications/cancelled`
 *    sobre HTTP.
 *
 * Por qué se validan las cabeceras contra el cuerpo: la especificación duplica
 * `method` y `name` en cabeceras para que un balanceador pueda enrutar sin
 * parsear el cuerpo. Si nadie comprueba que coinciden, se abre la puerta a que
 * el balanceador decida por la cabecera y el servidor ejecute según el cuerpo.
 * De ahí el -32020.
 *
 * La validación de `Origin` no está aquí: ya la hace authMiddleware, que
 * responde 403, que es justo lo que pide la especificación.
 */

const {
  PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  LEGACY_PROTOCOL_VERSION,
  META_PROTOCOL_VERSION,
  META_CLIENT_CAPABILITIES,
  ERROR_CODES,
  MODERN_METHODS,
  NAME_BEARING_METHODS
} = mcpServer.protocol;

const MODERN_METHOD_SET = new Set(MODERN_METHODS);
const NAME_BEARING_SET = new Set(NAME_BEARING_METHODS);

// Comentario SSE de keep-alive. Sin él, un proxy o un timeout de inactividad
// cierran el stream durante una operación larga y el cliente lo lee como fallo.
const SSE_KEEPALIVE_MS = 15000;
const PROGRESS_INTERVAL_MS = 2000;

// Sentinela de la especificación para valores de cabecera que no caben en ASCII.
const B64_PREFIX = '=?base64?';
const B64_SUFFIX = '?=';

/**
 * Los nombres de cabecera son insensibles a mayúsculas (RFC 9110); Express ya
 * las entrega en minúscula. Una cabecera repetida llega como array: se trata
 * como malformada en lugar de elegir una, porque elegir sería adivinar.
 */
function headerValue(req, name) {
  const raw = req.headers[name];
  if (raw === undefined) return null;
  if (Array.isArray(raw)) return { duplicated: true };
  return String(raw);
}

function decodeHeaderSentinel(value) {
  if (typeof value !== 'string') return value;
  if (value.startsWith(B64_PREFIX) && value.endsWith(B64_SUFFIX) && value.length > B64_PREFIX.length + B64_SUFFIX.length) {
    const payload = value.slice(B64_PREFIX.length, -B64_SUFFIX.length);
    try {
      return Buffer.from(payload, 'base64').toString('utf8');
    } catch (e) {
      return value;
    }
  }
  return value;
}

function jsonRpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id === undefined ? null : id, error };
}

function sendError(res, status, payload) {
  res.status(status).json(payload);
  return null;
}

/**
 * Decide si la respuesta va como SSE.
 *
 * Streaming cuando el cliente pidió progreso (`progressToken`) —única forma de
 * que le lleguen notificaciones antes de la respuesta final— o cuando dijo
 * explícitamente que solo acepta `text/event-stream`. En lo demás, un único
 * objeto JSON es más barato para ambos lados.
 */
function shouldStream(req, body) {
  const progressToken = body && body.params && body.params._meta
    ? body.params._meta.progressToken
    : undefined;
  if (progressToken !== undefined) return true;

  const accept = String(req.headers.accept || '');
  return accept.includes('text/event-stream') && !accept.includes('application/json');
}

function writeSseMessage(res, message) {
  res.write(`data: ${JSON.stringify(message)}\n\n`);
}

/**
 * POST /api/mcp — el endpoint MCP.
 */
async function handlePost(req, res) {
  const body = req.body;

  // 1. Sobre JSON-RPC. Esta revisión no define lotes (arrays) sobre HTTP.
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return sendError(res, 400, jsonRpcError(
      body && typeof body === 'object' && !Array.isArray(body) ? body.id : null,
      ERROR_CODES.INVALID_REQUEST,
      'El cuerpo debe ser un único mensaje JSON-RPC 2.0 con los campos jsonrpc y method.',
      {
        expected: { jsonrpc: '2.0', id: 'string|number (ausente si es notificación)', method: 'string', params: 'object' },
        batchingSupported: false
      }
    ));
  }

  // Una notificación es una petición sin `id`. `id: null` no es válido en MCP,
  // así que no se acepta como notificación encubierta.
  const isNotification = !('id' in body) || body.id === undefined;
  if (!isNotification && body.id === null) {
    return sendError(res, 400, jsonRpcError(null, ERROR_CODES.INVALID_REQUEST,
      'El campo id no puede ser null: usa una cadena o un entero, u omítelo si es una notificación.',
      { received: null }
    ));
  }

  if (isNotification) {
    // La especificación no define requisitos de cabecera para las
    // notificaciones sobre este transporte: si se acepta, 202 sin cuerpo.
    return res.status(202).end();
  }

  const id = body.id;

  // 2. Cabecera de versión. Se comprueba antes que el cuerpo a propósito: si el
  //    cliente habla otra era, decirle qué versiones hay le sirve más que
  //    quejarse de un `_meta` que su SDK ni siquiera sabe rellenar.
  const versionHeader = headerValue(req, 'mcp-protocol-version');
  if (versionHeader === null || versionHeader.duplicated) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
      versionHeader === null
        ? 'Falta la cabecera obligatoria MCP-Protocol-Version.'
        : 'La cabecera MCP-Protocol-Version llega repetida.',
      {
        missingHeaders: versionHeader === null ? ['MCP-Protocol-Version'] : [],
        requiredHeaders: ['MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name (en tools/call, resources/read y prompts/get)'],
        supported: SUPPORTED_PROTOCOL_VERSIONS
      }
    ));
  }

  if (!SUPPORTED_PROTOCOL_VERSIONS.includes(versionHeader)) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.UNSUPPORTED_PROTOCOL_VERSION,
      `Este endpoint no implementa la revisión ${versionHeader}.`,
      {
        supported: SUPPORTED_PROTOCOL_VERSIONS,
        requested: versionHeader,
        // Pista propia, fuera del contrato: si el cliente es de la era antigua
        // tiene dónde ir sin que nadie lea la documentación.
        legacy: {
          protocolVersion: LEGACY_PROTOCOL_VERSION,
          endpoint: '/api/mcp/message',
          deprecated: true
        }
      }
    ));
  }

  // 3. `_meta` obligatorio. Sin él la petición es malformada: -32602.
  const meta = body.params && typeof body.params === 'object' ? body.params._meta : undefined;
  const missingMeta = [];
  if (!meta || typeof meta !== 'object') {
    missingMeta.push(META_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES);
  } else {
    if (typeof meta[META_PROTOCOL_VERSION] !== 'string') missingMeta.push(META_PROTOCOL_VERSION);
    if (!meta[META_CLIENT_CAPABILITIES] || typeof meta[META_CLIENT_CAPABILITIES] !== 'object') missingMeta.push(META_CLIENT_CAPABILITIES);
  }
  if (missingMeta.length > 0) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.INVALID_PARAMS,
      `Faltan campos obligatorios en params._meta: ${missingMeta.join(', ')}.`,
      {
        missing: missingMeta,
        example: {
          _meta: {
            [META_PROTOCOL_VERSION]: PROTOCOL_VERSION,
            [META_CLIENT_CAPABILITIES]: {},
            'io.modelcontextprotocol/clientInfo': { name: 'mi-cliente', version: '1.0.0' }
          }
        }
      }
    ));
  }

  // 4. La cabecera y el cuerpo deben decir lo mismo.
  if (meta[META_PROTOCOL_VERSION] !== versionHeader) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
      `La cabecera MCP-Protocol-Version ('${versionHeader}') no coincide con params._meta['${META_PROTOCOL_VERSION}'] ('${meta[META_PROTOCOL_VERSION]}').`,
      { header: { name: 'MCP-Protocol-Version', value: versionHeader }, body: { path: `params._meta.${META_PROTOCOL_VERSION}`, value: meta[META_PROTOCOL_VERSION] } }
    ));
  }

  // 5. Mcp-Method.
  const methodHeader = headerValue(req, 'mcp-method');
  if (methodHeader === null || methodHeader.duplicated) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
      methodHeader === null ? 'Falta la cabecera obligatoria Mcp-Method.' : 'La cabecera Mcp-Method llega repetida.',
      { missingHeaders: methodHeader === null ? ['Mcp-Method'] : [], expectedValue: body.method }
    ));
  }
  if (methodHeader !== body.method) {
    return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
      `La cabecera Mcp-Method ('${methodHeader}') no coincide con el método del cuerpo ('${body.method}').`,
      { header: { name: 'Mcp-Method', value: methodHeader }, body: { path: 'method', value: body.method } }
    ));
  }

  // 6. Mcp-Name, solo en los métodos que llevan nombre o URI.
  if (NAME_BEARING_SET.has(body.method)) {
    const rawName = headerValue(req, 'mcp-name');
    const bodyName = body.method === 'resources/read'
      ? (body.params && body.params.uri)
      : (body.params && body.params.name);

    if (rawName === null || rawName.duplicated) {
      return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
        rawName === null
          ? `Falta la cabecera obligatoria Mcp-Name para el método ${body.method}.`
          : 'La cabecera Mcp-Name llega repetida.',
        { missingHeaders: rawName === null ? ['Mcp-Name'] : [], expectedValue: bodyName ?? null }
      ));
    }

    const nameHeader = decodeHeaderSentinel(rawName);
    if (nameHeader !== bodyName) {
      return sendError(res, 400, jsonRpcError(id, ERROR_CODES.HEADER_MISMATCH,
        `La cabecera Mcp-Name ('${nameHeader}') no coincide con el cuerpo ('${bodyName}').`,
        {
          header: { name: 'Mcp-Name', value: nameHeader },
          body: { path: body.method === 'resources/read' ? 'params.uri' : 'params.name', value: bodyName ?? null }
        }
      ));
    }
  }

  // 7. Método conocido. Se comprueba antes de abrir el stream: una vez enviadas
  //    las cabeceras de SSE ya no se puede responder 404.
  if (!MODERN_METHOD_SET.has(body.method)) {
    return sendError(res, 404, jsonRpcError(id, ERROR_CODES.METHOD_NOT_FOUND,
      `Este servidor no implementa el método '${body.method}'.`,
      { method: body.method, supported: MODERN_METHODS }
    ));
  }

  if (shouldStream(req, body)) {
    return respondStreaming(req, res, body);
  }
  return respondJson(res, body);
}

async function respondJson(res, body) {
  try {
    const envelope = await mcpServer.handleModernRpc(body, { transport: `Streamable HTTP ${PROTOCOL_VERSION}` });
    res.status(200).json(envelope);
  } catch (err) {
    res.status(500).json(jsonRpcError(body.id, ERROR_CODES.INTERNAL_ERROR,
      `Fallo interno al procesar '${body.method}': ${err.message}`,
      { method: body.method }
    ));
  }
}

async function respondStreaming(req, res, body) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    // Sin esto, nginx acumula los eventos en su buffer y el progreso llega
    // todo junto al final, que es como no enviarlo.
    'X-Accel-Buffering': 'no'
  });

  let cancelled = false;
  const timers = [];
  const stopTimers = () => {
    while (timers.length > 0) clearInterval(timers.pop());
  };
  const alive = () => !cancelled && !res.writableEnded;

  // Cerrar el stream es la señal de cancelación de esta petición: se para el
  // trabajo que se pueda parar y no se envía ni un mensaje más.
  //
  // Se escucha en `res` y no en `req`: `req` emite 'close' en cuanto el cuerpo
  // del POST se ha leído entero, que es siempre y de inmediato, así que
  // escucharlo ahí cancelaba todas las peticiones antes de empezar. `res`
  // también emite 'close' al terminar bien, de ahí el `writableEnded`.
  res.on('close', () => {
    if (!res.writableEnded) cancelled = true;
    stopTimers();
  });

  res.write(':\r\n');
  timers.push(setInterval(() => {
    if (alive()) res.write(':\r\n');
  }, SSE_KEEPALIVE_MS));

  const progressToken = body.params && body.params._meta ? body.params._meta.progressToken : undefined;
  if (progressToken !== undefined) {
    const startedAt = Date.now();
    let lastProgress = 0;
    timers.push(setInterval(() => {
      if (!alive()) return;
      // `progress` cuenta segundos transcurridos y `total` se omite a
      // propósito: no sabemos cuánto tarda una emisión ACME ni un despliegue,
      // y un porcentaje inventado sería peor que no dar ninguno.
      const elapsed = Math.max(lastProgress + 1, Math.round((Date.now() - startedAt) / 1000));
      lastProgress = elapsed;
      writeSseMessage(res, {
        jsonrpc: '2.0',
        method: 'notifications/progress',
        params: {
          progressToken,
          progress: elapsed,
          message: `Culkibo sigue ejecutando '${body.params && body.params.name ? body.params.name : body.method}' (${elapsed} s).`
        }
      });
    }, PROGRESS_INTERVAL_MS));
  }

  let envelope;
  try {
    envelope = await mcpServer.handleModernRpc(body, {
      transport: `Streamable HTTP ${PROTOCOL_VERSION} (SSE)`,
      isCancelled: () => cancelled
    });
  } catch (err) {
    envelope = jsonRpcError(body.id, ERROR_CODES.INTERNAL_ERROR,
      `Fallo interno al procesar '${body.method}': ${err.message}`,
      { method: body.method }
    );
  }

  stopTimers();
  if (!alive()) return; // Cancelada: nada más sale por este stream.

  writeSseMessage(res, envelope);
  res.end();
}

/**
 * GET y DELETE sobre el endpoint MCP son de la forma anterior del transporte
 * (stream independiente y terminación de sesión). Ya no existen.
 */
function handleMethodNotAllowed(req, res) {
  res.setHeader('Allow', 'POST');
  res.status(405).json(jsonRpcError(null, ERROR_CODES.INVALID_REQUEST,
    `El transporte Streamable HTTP de la revisión ${PROTOCOL_VERSION} solo acepta POST en este endpoint.`,
    {
      allow: ['POST'],
      protocolVersion: PROTOCOL_VERSION,
      removed: {
        'GET (stream independiente)': 'Eliminado en 2026-07-28. Cada petición recibe su propio stream en la respuesta a su POST.',
        'DELETE (fin de sesión)': 'Eliminado en 2026-07-28. No hay sesiones: Mcp-Session-Id se ignora.'
      },
      legacy: { endpoint: '/api/mcp/sse', protocolVersion: LEGACY_PROTOCOL_VERSION, deprecated: true }
    }
  ));
}

// Última traza por etiqueta: sin esto, un cliente antiguo con reconexión
// agresiva llenaría el log de avisos idénticos y taparía todo lo demás.
const legacyWarnedAt = new Map();
const LEGACY_WARN_INTERVAL_MS = 60000;

/**
 * Marca una respuesta del transporte antiguo como deprecada.
 *
 * `Deprecation` y `Link: rel="successor-version"` son RFC 8594: un cliente
 * puede detectar la migración sin que nadie lea la documentación. El aviso en
 * el log es para la persona que administra el daemon.
 */
function markLegacyTransport(res, label) {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Link', '</api/mcp>; rel="successor-version"');
  res.setHeader('X-Culkibo-Mcp-Protocol', LEGACY_PROTOCOL_VERSION);

  const now = Date.now();
  const last = legacyWarnedAt.get(label) || 0;
  if (now - last < LEGACY_WARN_INTERVAL_MS) return;
  legacyWarnedAt.set(label, now);
  console.warn(`[Culkibo:MCP] ${label} usa el transporte HTTP+SSE ${LEGACY_PROTOCOL_VERSION}, deprecado desde la revisión 2025-03-26. Migra el cliente a POST /api/mcp (Streamable HTTP ${PROTOCOL_VERSION}).`);
}

module.exports = { handlePost, handleMethodNotAllowed, markLegacyTransport };
