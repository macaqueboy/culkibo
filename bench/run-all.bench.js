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
const runCompetitorComparison = require('./competitor-comparison.bench');

async function main({ silent = null } = {}) {
  const asJson = silent === null ? process.argv.includes('--json') : Boolean(silent);
  const asMarkdown = silent === null ? process.argv.includes('--markdown') : false;
  const quiet = asJson || asMarkdown;

  const controlPlane = await runControlPlane({ silent: quiet });
  const liveSync = await runLiveSync({ silent: quiet });
  const routeSwap = await runRouteSwap({ silent: quiet });
  const subsystems = await runSubsystems({ silent: quiet });
  const competitorComparison = await runCompetitorComparison({
    silent: quiet,
    results: { controlPlane, liveSync, routeSwap, subsystems }
  });

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
    subsystems,
    competitorComparison
  };

  if (require.main === module && asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else if (require.main === module && asMarkdown) {
    process.stdout.write(competitorComparison.markdownTable + '\n');
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
