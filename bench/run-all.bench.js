/**
 * Ejecutor unificado de benchmarks reproducibles de Culkibo.
 *
 *   npm run bench:all
 *   node bench/run-all.bench.js --json
 */

const runControlPlane = require('./control-plane.bench');
const runLiveSync = require('./live-sync.bench');
const runRouteSwap = require('./route-swap.bench');
const runSubsystems = require('./subsystems.bench');

async function main({ silent = null } = {}) {
  const asJson = silent === null ? process.argv.includes('--json') : Boolean(silent);

  const controlPlane = await runControlPlane({ silent: asJson });
  const liveSync = await runLiveSync({ silent: asJson });
  const routeSwap = await runRouteSwap({ silent: asJson });
  const subsystems = await runSubsystems({ silent: asJson });

  const report = {
    timestamp: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch
    },
    controlPlane,
    liveSync,
    routeSwap: routeSwap || { skipped: true, reason: 'Caddy no estaba escuchando en :2019' },
    subsystems
  };

  if (require.main === module && asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }

  return report;
}

if (require.main === module) {
  main().then(() => process.exit(0)).catch((err) => {
    console.error('❌ Error en bench/run-all.bench.js:', err);
    process.exit(1);
  });
}

module.exports = main;
