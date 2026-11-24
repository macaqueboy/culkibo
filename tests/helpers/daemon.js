/**
 * Arranque bajo demanda del daemon para las suites que hablan por HTTP.
 *
 * Varias pruebas (ciclo de vida, ingress, WebSocket, estrés) asumían que
 * alguien había dejado un `node server/index.js` corriendo a mano. Cuando no lo
 * había, fallaban con un `fetch failed` que parece una regresión del producto y
 * no lo es. Esto lo vuelve determinista: si hay daemon, se reutiliza; si no, se
 * levanta uno y se cierra al terminar.
 */

const PORT = process.env.PORT || 3030;
const BASE_URL = `http://localhost:${PORT}`;

async function isUp(timeoutMs = 1500) {
  try {
    const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(timeoutMs) });
    return res.ok;
  } catch (e) {
    return false;
  }
}

/**
 * @returns {Promise<null|(() => Promise<void>)>} null si ya había un daemon
 *   (no es nuestro, no lo tocamos); si no, la función para cerrar el que hemos
 *   arrancado.
 */
async function ensureDaemon({ quiet = false } = {}) {
  if (await isUp()) {
    if (!quiet) {
      console.log(`ℹ Usando el daemon ya activo en ${BASE_URL}`);
      // Aviso importante y no cosmético. Varias suites hacen
      // `require('../server/services/projectManager')` en ESTE proceso, mientras
      // hablan por HTTP con el daemon. Si el daemon es externo hay DOS
      // instancias del gestor, cada una con su mapa en memoria, escribiendo el
      // mismo data/projects.json: la última en volcar borra los proyectos de la
      // otra y las pruebas fallan de forma aparentemente aleatoria.
      // Cuando el daemon lo arranca esta misma función no ocurre, porque el
      // módulo es el mismo y la instancia también.
      console.log('  ⚠ Es un daemon externo: comparte data/projects.json con el proceso de pruebas');
      console.log('    pero NO comparte la instancia de projectManager. Si ves fallos raros de');
      console.log('    persistencia, párado y repite para que las pruebas levanten el suyo.\n');
    }
    return null;
  }

  if (!quiet) console.log(`ℹ No hay daemon en ${BASE_URL}; arrancando uno para las pruebas...\n`);
  const { startServer, server, shutdown } = require('../../server/index');
  // Sin reponer rutas de ingress: las pruebas comparten un Caddy real y
  // `caddy.test.js` cuenta rutas absolutas. Un daemon que añadiese las de los
  // despliegues de esta máquina rompería esa suite en cuanto hubiera uno.
  await startServer(PORT, '127.0.0.1', { reconcileIngress: false });

  for (let i = 0; i < 20 && !(await isUp()); i++) {
    await new Promise(r => setTimeout(r, 150));
  }
  if (!(await isUp())) throw new Error('El daemon no respondió a /health tras arrancar');

  return async () => {
    try {
      if (typeof shutdown === 'function') {
        await shutdown('TEST_DONE');
        return;
      }
      await new Promise((resolve) => {
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
        server.close(() => resolve());
        const t = setTimeout(resolve, 1500);
        if (t.unref) t.unref();
      });
    } catch (e) {
      // ignorar errores de cierre en pruebas
    }
  };
}

module.exports = { ensureDaemon, isUp, BASE_URL, PORT };
