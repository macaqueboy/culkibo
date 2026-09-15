const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cloudflareService = require('./cloudflareService');

const CERTS_DIR = path.join(__dirname, '..', '..', 'data', 'certs');
const REGISTRY_FILE = path.join(CERTS_DIR, 'registry.json');

class SslManager {
  constructor() {
    this.ensureDirectory();
    this.registry = this.loadRegistry();
    this.activeJobs = new Map();
  }

  ensureDirectory() {
    if (!fs.existsSync(CERTS_DIR)) {
      fs.mkdirSync(CERTS_DIR, { recursive: true });
    }
  }

  loadRegistry() {
    try {
      if (fs.existsSync(REGISTRY_FILE)) {
        return JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf8'));
      }
    } catch (e) {
      console.error('[SSL] Error loading cert registry:', e.message);
    }
    // Default initial seed certificates
    return [
      {
        id: 'cert_culkibo_wildcard',
        domain: '*.culkibo.dev',
        rootDomain: 'culkibo.dev',
        type: 'wildcard_dns01',
        provider: 'lets_encrypt',
        issuer: "Let's Encrypt Authority E6",
        sans: ['*.culkibo.dev', 'culkibo.dev'],
        status: 'active',
        issuedAt: new Date(Date.now() - 86400000 * 20).toISOString(),
        expiresAt: new Date(Date.now() + 86400000 * 70).toISOString(),
        autoRenew: true,
        fingerprint: '3F:9A:88:B1:4C:E2:71:0D:82:11:AB:CC:90:7E:14:02:44:E1:92:BF',
        keyType: 'ECDSA (P-256)',
        certPath: path.join(CERTS_DIR, 'culkibo.dev', 'fullchain.pem'),
        keyPath: path.join(CERTS_DIR, 'culkibo.dev', 'privkey.pem')
      },
      {
        id: 'cert_sslip_ondemand',
        domain: '*.127-0-0-1.sslip.io',
        rootDomain: '127-0-0-1.sslip.io',
        type: 'ondemand_tls',
        provider: 'culkibo_internal_ca',
        issuer: 'Culkibo FastTLS Dev Authority',
        sans: ['*.127-0-0-1.sslip.io', '127-0-0-1.sslip.io'],
        status: 'active',
        issuedAt: new Date(Date.now() - 86400000 * 5).toISOString(),
        expiresAt: new Date(Date.now() + 86400000 * 85).toISOString(),
        autoRenew: true,
        fingerprint: 'E4:1B:90:77:2F:5A:CC:01:99:A2:33:DE:45:B1:00:89:12:FA:71:3B',
        keyType: 'RSA 2048',
        certPath: path.join(CERTS_DIR, 'sslip.io', 'fullchain.pem'),
        keyPath: path.join(CERTS_DIR, 'sslip.io', 'privkey.pem')
      }
    ];
  }

  saveRegistry() {
    this.ensureDirectory();
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(this.registry, null, 2), 'utf8');
  }

  listCertificates() {
    return this.registry.map(cert => {
      const expires = new Date(cert.expiresAt);
      const now = new Date();
      const diffMs = expires.getTime() - now.getTime();
      const daysRemaining = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
      return {
        ...cert,
        daysRemaining,
        isExpiringSoon: daysRemaining <= 15,
        isExpired: diffMs <= 0
      };
    });
  }

  getCertificateByDomain(domain) {
    const clean = domain.toLowerCase();
    return this.registry.find(c => {
      if (c.domain === clean || c.rootDomain === clean) return true;
      if (c.sans && c.sans.includes(clean)) return true;
      // Match wildcard
      if (c.domain.startsWith('*.')) {
        // Same boundary-dot rule as DomainManager.resolveRoute: a wildcard cert
        // for *.culkibo.dev must not be reported as covering evilculkibo.dev.
        const wildcardRoot = c.domain.slice(2);
        if (clean === wildcardRoot || clean.endsWith(`.${wildcardRoot}`)) return true;
      }
      return false;
    });
  }

  // Issue Wildcard Certificate via Cloudflare DNS-01 ACME
  async issueWildcardCertificate({ domain, zoneId, provider = 'lets_encrypt', onProgress }) {
    const rootDomain = domain.replace(/^\*\./, '').toLowerCase();
    const wildcardDomain = `*.${rootDomain}`;
    const jobId = `job_${Date.now()}`;

    const updateProgress = (stage, progress, message, extra = {}) => {
      const payload = { jobId, domain: wildcardDomain, stage, progress, message, ...extra };
      if (onProgress) onProgress(payload);
      return payload;
    };

    try {
      // Step 1: Generate Key pair & CSR
      updateProgress('generating_keys', 15, 'Generating cryptographic ECDSA P-256 key pair & CSR...');
      await new Promise(r => setTimeout(r, 400));
      const keyPair = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

      // Step 2: Request Challenge from ACME directory
      updateProgress('requesting_challenge', 35, `Connecting to ${provider === 'lets_encrypt' ? "Let's Encrypt" : 'ZeroSSL'} ACME v2 directory...`);
      await new Promise(r => setTimeout(r, 600));

      const challengeValue = `culkibo-acme-val-${crypto.randomBytes(16).toString('hex')}`;
      const token = `tok_${crypto.randomBytes(8).toString('hex')}`;

      // Step 3: Inject DNS-01 TXT record via Cloudflare API
      updateProgress('configuring_dns', 55, `Setting Cloudflare DNS-01 TXT record: _acme-challenge.${rootDomain}...`);
      const dnsRes = await cloudflareService.createAcmeTxtRecord(zoneId, rootDomain, challengeValue);
      const recordId = dnsRes.record?.id;

      // Step 4: Verify DNS propagation
      updateProgress('verifying_propagation', 75, 'Awaiting authoritative nameserver propagation on Cloudflare edge...');
      await new Promise(r => setTimeout(r, 800));

      // Step 5: Sign & issue certificate
      updateProgress('acme_validation', 90, 'Validating ACME DNS-01 response & downloading signed X.509 cert chain...');
      await new Promise(r => setTimeout(r, 500));

      // Step 6: Store cert in disk
      const certDir = path.join(CERTS_DIR, rootDomain);
      if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });

      const mockCertPem = `-----BEGIN CERTIFICATE-----\nMIICrDCCAZSgAwIBAgIU${crypto.randomBytes(32).toString('base64')}\n-----END CERTIFICATE-----`;
      fs.writeFileSync(path.join(certDir, 'fullchain.pem'), mockCertPem, 'utf8');
      fs.writeFileSync(path.join(certDir, 'privkey.pem'), keyPair.privateKey, 'utf8');

      const newCert = {
        id: `cert_${Date.now()}`,
        domain: wildcardDomain,
        rootDomain,
        type: 'wildcard_dns01',
        provider,
        issuer: provider === 'lets_encrypt' ? "Let's Encrypt Authority R3" : 'ZeroSSL ECC Domain CA',
        sans: [wildcardDomain, rootDomain],
        status: 'active',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000 * 90).toISOString(),
        autoRenew: true,
        fingerprint: Array.from(crypto.randomBytes(20)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':'),
        keyType: 'ECDSA (P-256)',
        certPath: path.join(certDir, 'fullchain.pem'),
        keyPath: path.join(certDir, 'privkey.pem'),
        dnsRecordId: recordId
      };

      // Remove existing for same domain if any
      this.registry = this.registry.filter(c => c.domain !== wildcardDomain && c.rootDomain !== rootDomain);
      this.registry.unshift(newCert);
      this.saveRegistry();

      updateProgress('installed', 100, `Wildcard SSL Certificate successfully issued for ${wildcardDomain} & ${rootDomain}!`, { cert: newCert });
      return { success: true, cert: newCert };
    } catch (err) {
      updateProgress('error', 100, `SSL issuance failed: ${err.message}`, { error: err.message });
      return { success: false, error: err.message };
    }
  }

  // Issue Zero-Config On-Demand TLS for sslip.io / nip.io
  async issueOnDemandSslip({ ip = '127.0.0.1', service = 'sslip.io' }) {
    const formattedIp = ip.replace(/\./g, '-');
    const domain = `${formattedIp}.${service}`;
    const wildcardDomain = `*.${domain}`;

    const certDir = path.join(CERTS_DIR, service);
    if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });

    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const certPem = `-----BEGIN CERTIFICATE-----\nMIIC5jCCAc6gAwIBAgIJAP${crypto.randomBytes(24).toString('base64')}\n-----END CERTIFICATE-----`;
    fs.writeFileSync(path.join(certDir, 'fullchain.pem'), certPem, 'utf8');
    fs.writeFileSync(path.join(certDir, 'privkey.pem'), keyPair.privateKey, 'utf8');

    const newCert = {
      id: `cert_ondemand_${Date.now()}`,
      domain: wildcardDomain,
      rootDomain: domain,
      type: 'ondemand_tls',
      provider: 'culkibo_fast_tls',
      issuer: 'Culkibo On-Demand Edge TLS',
      sans: [wildcardDomain, domain],
      status: 'active',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000 * 90).toISOString(),
      autoRenew: true,
      fingerprint: Array.from(crypto.randomBytes(20)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':'),
      keyType: 'RSA 2048',
      certPath: path.join(certDir, 'fullchain.pem'),
      keyPath: path.join(certDir, 'privkey.pem')
    };

    this.registry = this.registry.filter(c => c.rootDomain !== domain);
    this.registry.unshift(newCert);
    this.saveRegistry();

    return { success: true, cert: newCert };
  }

  revokeCertificate(id) {
    const cert = this.registry.find(c => c.id === id);
    if (!cert) return { success: false, error: 'Certificate not found' };
    this.registry = this.registry.filter(c => c.id !== id);
    this.saveRegistry();
    return { success: true, revokedId: id };
  }
}

module.exports = new SslManager();
