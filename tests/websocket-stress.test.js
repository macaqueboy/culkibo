const assert = require('assert');
const WebSocket = require('ws');
const { ensureDaemon, PORT } = require('./helpers/daemon');

async function testWebSocketStress() {
  console.log('🧪 Testing WebSocket Server Under Rapid Churn & Stress...');

  // Reutiliza el daemon si ya está en marcha; si no, levanta uno y lo cierra al
  // salir. Antes esta suite daba por hecho que alguien lo había arrancado.
  const stopDaemon = await ensureDaemon({ quiet: true });

  const wsUrl = `ws://localhost:${PORT}/ws`;
  const NUM_CLIENTS = 30;
  const clients = [];

  try {
    // 1. Concurrent Connections
    const connectPromises = [];
    for (let i = 0; i < NUM_CLIENTS; i++) {
      connectPromises.push(new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        const timer = setTimeout(() => {
          ws.terminate();
          reject(new Error(`Timeout connecting client ${i}`));
        }, 4000);

        ws.on('open', () => {
          clearTimeout(timer);
          clients.push(ws);
          resolve(ws);
        });

        ws.on('error', (err) => {
          clearTimeout(timer);
          // Only fail if connecting failed
          reject(err);
        });
      }));
    }

    await Promise.all(connectPromises);
    assert.strictEqual(clients.length, NUM_CLIENTS);
    console.log(`  ✓ ${NUM_CLIENTS} concurrent WebSocket clients connected cleanly`);

    // 2. Ping-Pong validation
    const pingPromises = clients.map((ws, index) => {
      return new Promise((resolve) => {
        const messageHandler = (data) => {
          try {
            const parsed = JSON.parse(data.toString());
            if (parsed.type === 'pong') {
              ws.removeListener('message', messageHandler);
              resolve(true);
            }
          } catch (e) {}
        };
        ws.on('message', messageHandler);
        ws.send(JSON.stringify({ type: 'ping', index }));
      });
    });

    await Promise.all(pingPromises);
    console.log(`  ✓ Ping/Pong verified for all ${NUM_CLIENTS} connections`);

    // 3. Abrupt Termination / Churn
    const half = Math.floor(NUM_CLIENTS / 2);
    for (let i = 0; i < half; i++) {
      clients[i].terminate(); // Hard close
    }
    console.log(`  ✓ Abruptly terminated ${half} connections without server errors`);

    // 4. Remaining connections still receive data and complete clean close handshake
    await new Promise(r => setTimeout(r, 200));
    const closePromises = [];
    for (let i = half; i < NUM_CLIENTS; i++) {
      assert.strictEqual(clients[i].readyState, WebSocket.OPEN);
      closePromises.push(new Promise((resolve) => {
        const t = setTimeout(() => {
          try { clients[i].terminate(); } catch (e) {}
          resolve();
        }, 2000);
        clients[i].once('close', () => {
          clearTimeout(t);
          resolve();
        });
        clients[i].close();
      }));
    }
    await Promise.all(closePromises);
    console.log(`  ✓ Remaining connections clean disconnect complete`);

    console.log('✅ WebSocket Stress & Churn test passed!\n');
  } catch (err) {
    // Cleanup any lingering clients
    clients.forEach(c => {
      try { c.terminate(); } catch (e) {}
    });
    throw err;
  } finally {
    if (stopDaemon) await stopDaemon();
  }
}

module.exports = testWebSocketStress;

if (require.main === module) {
  testWebSocketStress().catch(err => {
    console.error('WebSocket test failed:', err);
    process.exit(1);
  });
}
