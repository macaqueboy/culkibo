const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  CloudflareService,
  assertCfId,
  validateTunnelHostname,
  validateTunnelServiceUrl,
  redactCloudflaredOutput
} = require('../server/services/cloudflareService');
const { DomainManager } = require('../server/services/domainManager');
const { IngressManager } = require('../server/services/ingressManager');
const { CaddyManager } = require('../server/services/caddyManager');

async function testCloudflare() {
  console.log('🧪 Testing Cloudflare Service & Zero-Open-Ports Tunnel Orchestration (aislado en tmpdir)...');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'culkibo-cf-test-'));
  try {
    /** @type {Array<{ bin: string, args: string[], envFileContent?: string | null }>} */
    const dockerCalls = [];
    let containerRunning = false;

    const mockRunCommand = async (bin, args) => {
      /** @type {{ bin: string, args: string[], envFileContent?: string | null }} */
      const rec = { bin, args: [...args], envFileContent: null };
      const envIdx = args.indexOf('--env-file');
      if (envIdx >= 0 && args[envIdx + 1] && fs.existsSync(args[envIdx + 1])) {
        rec.envFileContent = fs.readFileSync(args[envIdx + 1], 'utf8');
      }
      dockerCalls.push(rec);

      if (bin === 'docker' && args[0] === 'run') {
        containerRunning = true;
        return { code: 0, stdout: 'abcdef1234567890', stderr: '' };
      }
      if (bin === 'docker' && args[0] === 'inspect') {
        if (!containerRunning) return { code: 1, stdout: '', stderr: 'No such object' };
        return {
          code: 0,
          stdout: 'abcdef1234567890|true|running|0|2026-11-24T12:00:00Z|cloudflare/cloudflared:2026.2.0',
          stderr: ''
        };
      }
      if (bin === 'docker' && (args[0] === 'rm' || args[0] === 'stop')) {
        const existed = containerRunning;
        containerRunning = false;
        return existed
          ? { code: 0, stdout: args[args.length - 1], stderr: '' }
          : { code: 1, stdout: '', stderr: 'Error: No such container' };
      }
      if (bin === 'docker' && args[0] === 'logs') {
        return {
          code: 0,
          stdout: 'INF Registered tunnel connection connIndex=0\nDBG TUNNEL_TOKEN=eyJhIjoic2VjcmV0LXRva2VuLTEyMzQ1Njc4OTAifQ== connected',
          stderr: ''
        };
      }
      return { code: 0, stdout: '', stderr: '' };
    };

    const cf = new CloudflareService({ dataDir: tmpDir, runCommand: mockRunCommand });

    // 1. Token verification, zones, DNS CRUD, ACME TXT & masked token preservation
    const tokenRes = await cf.verifyToken('demo_token');
    assert.strictEqual(tokenRes.valid, true);
    assert.strictEqual(tokenRes.status, 'active');

    cf.saveConfig({ apiToken: 'real_token_1234567890abcdef', accountId: 'acc_1234567890', useMock: true });
    // Guardar valor enmascarado NO debe sobrescribir el token real
    cf.saveConfig({ apiToken: 'real••••cdef', accountId: 'acc_...90' });
    assert.strictEqual(cf.config.apiToken, 'real_token_1234567890abcdef');
    assert.strictEqual(cf.config.accountId, 'acc_1234567890');
    assert.ok(!JSON.stringify(cf.getConfigStatus()).includes('real_token_1234567890abcdef'));

    const zonesRes = await cf.listZones();
    assert.strictEqual(zonesRes.success, true);
    const culkiboZone = zonesRes.zones.find((z) => z.name === 'culkibo.dev');
    assert.ok(culkiboZone);

    const newRec = await cf.createDnsRecord(culkiboZone.id, {
      type: 'A',
      name: 'test-api.culkibo.dev',
      content: '142.250.180.206',
      proxied: true
    });
    assert.strictEqual(newRec.success, true);

    const acmeRec = await cf.createAcmeTxtRecord(culkiboZone.id, 'culkibo.dev', 'test-token-acme-12345');
    assert.strictEqual(acmeRec.success, true);
    assert.strictEqual(acmeRec.record.type, 'TXT');
    assert.strictEqual(acmeRec.record.name, '_acme-challenge.culkibo.dev');
    console.log('  ✓ Token, zones, DNS CRUD, ACME TXT y protección anti-sobrescritura de tokens enmascarados');

    // 2. Adversarial: assertCfId path traversal + SSRF serviceUrl + bad hostnames
    assert.throws(() => assertCfId('../zones', 'Zone ID'), /inválido/i);
    assert.throws(() => assertCfId('abc/def', 'Tunnel ID'), /inválido/i);
    assert.throws(() => assertCfId('has space', 'Account ID'), /inválido/i);
    assert.throws(() => validateTunnelHostname('bad host!.dev'), /inválido/i);
    assert.throws(() => validateTunnelServiceUrl('http://169.254.169.254/latest/meta-data/'), /SSRF/i);
    assert.throws(() => validateTunnelServiceUrl('file:///etc/passwd'), /no permitido/i);
    assert.strictEqual(validateTunnelHostname('*.App.Culkibo.Dev.'), '*.app.culkibo.dev');
    assert.strictEqual(validateTunnelServiceUrl('http://[::1]:3000'), 'http://[::1]:3000');
    console.log('  ✓ Validaciones adversariales (assertCfId traversal, SSRF metadata, wildcard & IPv6 serviceUrl)');

    // 3. routeHostnameToTunnel con wildcard + originRequest + orden exacto->comodín + fallback 404
    const tunId = cf.mockTunnels[0].id;
    const wildRoute = await cf.routeHostnameToTunnel({
      tunnelId: tunId,
      hostname: '*.apps.culkibo.dev',
      serviceUrl: 'http://[::1]:8080',
      originRequest: {
        httpHostHeader: 'apps.culkibo.dev',
        noTLSVerify: true,
        connectTimeout: '30s',
        http2Origin: true
      }
    });
    assert.strictEqual(wildRoute.success, true);
    assert.strictEqual(wildRoute.hostname, '*.apps.culkibo.dev');
    assert.strictEqual(wildRoute.originRequest.noTLSVerify, true);
    assert.strictEqual(wildRoute.originRequest.connectTimeout, 30);
    assert.strictEqual(wildRoute.dns.success, true, 'Debe crear CNAME proxied hacia .cfargotunnel.com');
    const lastIngress = wildRoute.ingress[wildRoute.ingress.length - 1];
    assert.deepStrictEqual(lastIngress, { service: 'http_status:404' }, 'Fallback http_status:404 obligatorio al final');

    // Reglas exactas deben aparecer ANTES que comodines y comodín largo antes que corto
    const exactIdx = wildRoute.ingress.findIndex((r) => r.hostname === 'forge.culkibo.dev');
    const longWildIdx = wildRoute.ingress.findIndex((r) => r.hostname === '*.apps.culkibo.dev');
    const shortWildIdx = wildRoute.ingress.findIndex((r) => r.hostname === '*.culkibo.dev');
    assert.ok(exactIdx >= 0 && exactIdx < longWildIdx && longWildIdx < shortWildIdx, 'Orden determinista exact -> *.apps -> *.root');

    // 4. unrouteHostnameFromTunnel: elimina regla y limpia CNAME asociado
    const unrouted = await cf.unrouteHostnameFromTunnel({
      tunnelId: tunId,
      hostname: '*.apps.culkibo.dev',
      removeDns: true
    });
    assert.strictEqual(unrouted.success, true);
    assert.strictEqual(unrouted.removedRules, 1);
    assert.strictEqual(unrouted.dns.removed, true, 'Debe eliminar el CNAME asociado al túnel');
    assert.ok(!unrouted.ingress.some((r) => r.hostname === '*.apps.culkibo.dev'));
    assert.deepStrictEqual(unrouted.ingress[unrouted.ingress.length - 1], { service: 'http_status:404' });
    console.log('  ✓ routeHostnameToTunnel (wildcard + IPv6 + originRequest) y unrouteHostnameFromTunnel (+ CNAME cleanup)');

    // 5. configureAllResourcesTunnel (CGNAT 0 puertos abiertos -> Caddy)
    const allRes = await cf.configureAllResourcesTunnel({
      tunnelId: tunId,
      hostnames: ['culkibo.dev', '*.culkibo.dev'],
      caddyUpstream: 'http://127.0.0.1:80',
      noTLSVerify: false
    });
    assert.strictEqual(allRes.success, true);
    assert.strictEqual(allRes.mode, 'all_to_caddy');
    assert.strictEqual(allRes.ingress.length, 3); // 2 hostnames + 404 fallback
    assert.strictEqual(allRes.ingress[0].hostname, 'culkibo.dev');
    assert.strictEqual(allRes.ingress[1].hostname, '*.culkibo.dev');
    console.log('  ✓ configureAllResourcesTunnel (modo CGNAT 0-puertos hacia Caddy) verificado');

    // 6. Ciclo de vida completo del conector Docker `cloudflared` (0 secretos en argv, 0 fugas en logs)
    const secretToken = 'eyJhIjoiY2YtcmVhbC1zZWNyZXQtdGVzdC10b2tlbi0xMjM0NTY3ODkwIn0=';
    await assert.rejects(() => cf.startCloudflaredDocker({ tunnelToken: 'bad token\n' }), /inválido/i);
    await assert.rejects(() => cf.startCloudflaredDocker({ tunnelToken: secretToken, containerName: '--privileged' }), /inválido/i);
    await assert.rejects(() => cf.startCloudflaredDocker({ tunnelToken: secretToken, protocol: 'ftp' }), /inválido/i);
    await assert.rejects(() => cf.startCloudflaredDocker({ tunnelToken: secretToken, metricsPort: 22 }), /métricas/i);

    const started = await cf.startCloudflaredDocker({
      tunnelToken: secretToken,
      containerName: 'culkibo-cf-test',
      protocol: 'quic',
      metricsPort: 20241
    });
    assert.strictEqual(started.started, true);
    assert.strictEqual(started.protocol, 'quic');
    assert.strictEqual(started.status.running, true);

    const runCall = dockerCalls.find((c) => c.args[0] === 'run');
    assert.ok(runCall);
    assert.ok(!runCall.args.join(' ').includes(secretToken), 'El TUNNEL_TOKEN JAMÁS debe pasar por argv');
    assert.ok(String(runCall.envFileContent || '').includes(`TUNNEL_TOKEN=${secretToken}`), 'El token debe ir por --env-file');
    // El archivo .env temporal debe haberse borrado en finally
    const envArg = runCall.args[runCall.args.indexOf('--env-file') + 1];
    assert.ok(!fs.existsSync(envArg), 'El archivo .env temporal debe borrarse inmediatamente tras arrancar');

    const logs = await cf.getCloudflaredLogs({ containerName: 'culkibo-cf-test', tail: 50 });
    assert.strictEqual(logs.ok, true);
    assert.ok(!logs.lines.join('\n').includes('eyJhIjoic2VjcmV0'), 'Los logs deben redactar tokens JWT/TUNNEL_TOKEN');
    assert.ok(logs.lines.join('\n').includes('[REDACTED]'));
    assert.strictEqual(redactCloudflaredOutput('--token abc123 Bearer xyz999'), '--token [REDACTED] Bearer [REDACTED]');

    const stopped = await cf.stopCloudflaredDocker({ containerName: 'culkibo-cf-test', remove: true });
    assert.strictEqual(stopped.stopped, true);
    const afterStop = await cf.getCloudflaredStatus({ containerName: 'culkibo-cf-test' });
    assert.strictEqual(afterStop.running, false);
    assert.strictEqual(afterStop.status, 'not_found');
    console.log('  ✓ Ciclo de vida cloudflared Docker (start --env-file 0600, status, logs redactados, stop)');

    // 7. Orquestación integrada en IngressManager (CGNAT tunnel + multi-provider Wildcard DNS-01 persistencia)
    const isoDm = new DomainManager({ dataDir: tmpDir, seedDefaults: false, cloudflareService: cf });
    await isoDm.addDomain({ hostname: 'app.culkibo.dev', targetPod: 'citadel', targetPort: 8080, routingMode: 'cloudflare_tunnel' });
    await isoDm.addDomain({ hostname: '*.preview.culkibo.dev', targetPod: 'forge', targetPort: 3001, routingMode: 'cloudflare_tunnel' });

    const offlineCaddy = new CaddyManager();
    offlineCaddy.adminUrl = 'http://127.0.0.1:1'; // fuerza degradación local sin depender de Caddy real
    const isoIm = new IngressManager({
      dataDir: tmpDir,
      caddyManager: offlineCaddy,
      domainManager: isoDm,
      cloudflareService: cf
    });

    const configured = isoIm.configureCloudflareTunnel({
      enabled: true,
      tunnelId: tunId,
      mode: 'per_hostname',
      containerName: 'culkibo-cf-test'
    });
    assert.strictEqual(configured.enabled, true);
    assert.strictEqual(configured.tunnelId, tunId);

    const syncedPerHost = await isoIm.syncTunnelIngress();
    assert.strictEqual(syncedPerHost.synced, true);
    assert.strictEqual(syncedPerHost.routesCount, 2);
    assert.strictEqual(syncedPerHost.ingress[0].hostname, 'app.culkibo.dev');
    assert.strictEqual(syncedPerHost.ingress[1].hostname, '*.preview.culkibo.dev');

    isoIm.configureCloudflareTunnel({ mode: 'all_to_caddy', caddyUpstream: 'http://127.0.0.1:80' });
    const syncedAll = await isoIm.syncTunnelIngress();
    assert.strictEqual(syncedAll.synced, true);
    assert.strictEqual(syncedAll.mode, 'all_to_caddy');
    assert.strictEqual(syncedAll.routesCount, 2);

    // Multi-provider Wildcard DNS-01 en IngressManager (Hetzner v2 + Porkbun + Route53) + recarga desde disco
    await isoIm.addWildcardPolicy('hetz.example.test', { provider: 'hetzner', tokenEnv: 'HETZNER_AUTH_API_TOKEN' });
    await isoIm.addWildcardPolicy('pork.example.test', {
      provider: 'porkbun',
      credentialsEnv: { api_key: 'PB_KEY', api_secret_key: 'PB_SECRET' }
    });
    await assert.rejects(
      () => isoIm.addWildcardPolicy('bad.example.test', { provider: 'nonexistent_dns' }),
      /no soportado/i
    );

    const reloadedIm = new IngressManager({
      dataDir: tmpDir,
      caddyManager: offlineCaddy,
      domainManager: isoDm,
      cloudflareService: cf
    });
    assert.strictEqual(reloadedIm.tunnelConfig.tunnelId, tunId);
    assert.strictEqual(reloadedIm.tunnelConfig.mode, 'all_to_caddy');
    const savedHetz = reloadedIm.listWildcardPolicies().find((p) => p.rootDomain === 'hetz.example.test');
    const savedPork = reloadedIm.listWildcardPolicies().find((p) => p.rootDomain === 'pork.example.test');
    assert.ok(savedHetz && savedHetz.provider === 'hetzner');
    assert.ok(savedPork && savedPork.provider === 'porkbun' && savedPork.credentialsEnv.api_secret_key === 'PB_SECRET');
    console.log('  ✓ IngressManager: persistencia de túnel CGNAT (all_to_caddy + per_hostname) y Multi-DNS-01');

    console.log('✅ All Cloudflare & Tunnel Orchestration tests passed!\n');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

module.exports = testCloudflare;

if (require.main === module) {
  testCloudflare().catch((err) => {
    console.error('❌ Cloudflare test failure:', err);
    process.exit(1);
  });
}
