'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Carga la configuración del recolector desde variables de entorno.
 * Si ADMIN_TOKEN no está definido, genera uno seguro y lo guarda en `data/admin-token.txt` (0600).
 * @param {Record<string, any>} [overrides]
 */
function loadConfig(overrides = {}) {
  const env = { ...process.env, ...overrides };
  const dataDir = path.resolve(String(env.DATA_DIR || path.join(__dirname, '..', 'data')));
  fs.mkdirSync(dataDir, { recursive: true });

  let adminToken = String(env.ADMIN_TOKEN || '').trim();
  let tokenGenerated = false;
  const tokenFile = path.join(dataDir, 'admin-token.txt');

  if (!adminToken) {
    try {
      if (fs.existsSync(tokenFile)) {
        adminToken = fs.readFileSync(tokenFile, 'utf8').trim();
      }
    } catch {
      // regenerar si no se puede leer
    }
    if (!adminToken || adminToken.length < 24) {
      adminToken = crypto.randomBytes(32).toString('hex');
      try {
        fs.writeFileSync(tokenFile, `${adminToken}\n`, { mode: 0o600 });
      } catch {
        // continuar con token en memoria
      }
      tokenGenerated = true;
    }
  }

  const portRaw = Number(env.PORT ?? 8787);
  const port = Number.isInteger(portRaw) && portRaw >= 0 && portRaw <= 65535 ? portRaw : 8787;
  const retentionRaw = Number(env.RETENTION_DAYS ?? 90);
  const retentionDays = Number.isFinite(retentionRaw) && retentionRaw >= 1 && retentionRaw <= 3650 ? Math.floor(retentionRaw) : 90;
  const cooldownRaw = Number(env.ALERT_COOLDOWN_MS ?? 15 * 60 * 1000);
  const alertCooldownMs = Number.isFinite(cooldownRaw) && cooldownRaw >= 0 ? cooldownRaw : 15 * 60 * 1000;
  const spikeRaw = Number(env.ALERT_SPIKE_THRESHOLD ?? 25);
  const alertSpikeThreshold = Number.isFinite(spikeRaw) && spikeRaw >= 2 ? Math.floor(spikeRaw) : 25;

  return {
    port,
    bind: String(env.BIND || '0.0.0.0').trim() || '0.0.0.0',
    dataDir,
    dbPath: path.join(dataDir, 'telemetry.sqlite'),
    archiveDir: path.join(dataDir, 'archive'),
    adminToken,
    tokenGenerated,
    tokenFile,
    retentionDays,
    trustProxy: env.TRUST_PROXY === '1' || env.TRUST_PROXY === 'true',
    maxBodyBytes: 64 * 1024,
    alertCooldownMs,
    alertSpikeThreshold,
    alerts: {
      telegramBotToken: String(env.ALERT_TELEGRAM_BOT_TOKEN || '').trim(),
      telegramChatId: String(env.ALERT_TELEGRAM_CHAT_ID || '').trim(),
      discordWebhook: String(env.ALERT_DISCORD_WEBHOOK || '').trim(),
      slackWebhook: String(env.ALERT_SLACK_WEBHOOK || '').trim(),
      webhookUrl: String(env.ALERT_WEBHOOK_URL || '').trim(),
      webhookSecret: String(env.ALERT_WEBHOOK_SECRET || '').trim(),
    },
  };
}

module.exports = { loadConfig };
