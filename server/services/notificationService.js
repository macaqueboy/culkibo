const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const { assertSafeUrl, safeFetch, atomicWriteJsonSync, loadJsonWithBackupSync } = require('./ssrfGuard');

function resolveDataDir() {
  return process.env.CULKIBO_DATA_DIR
    ? path.join(path.resolve(process.env.CULKIBO_DATA_DIR), 'data')
    : path.join(__dirname, '..', '..', 'data');
}

const TELEGRAM_TOKEN_RE = /^\d{5,15}:[A-Za-z0-9_-]{20,80}$/;
const DISCORD_WEBHOOK_HOSTS = new Set(['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com']);
const SLACK_WEBHOOK_HOSTS = new Set(['hooks.slack.com', 'hooks.gov-slack.com']);

const DEFAULT_CONFIG = {
  enabled: false,
  // Qué eventos disparan un aviso. Coinciden con los tipos usados en notify().
  events: {
    service_down: true,
    service_failed: true,
    deploy_started: false,
    deploy_failed: true,
    deploy_succeeded: false,
    rollback: true,
    backup_failed: true,
    backup_succeeded: false,
    production_unhealthy: true,
    tls_expiring: true,
    disk_warning: true,
    cron_failed: true,
    ssl_issued: false,
    project_stopped: false,
    uptime_down: true,
    uptime_recovered: true,
    alert_fired: true,
    alert_resolved: true,
    host_ram_high: true,
    host_cpu_high: true,
    host_disk_high: true,
    container_oom: true,
    container_restart_loop: true
  },
  channels: {
    telegram: { enabled: false, botToken: '', chatId: '' },
    discord: { enabled: false, webhookUrl: '' },
    slack: { enabled: false, webhookUrl: '' },
    webhook: { enabled: false, url: '', secretHeader: '' }
  }
};

const LEVEL_META = {
  error: { emoji: '🔴', color: 0xdc2626, label: 'Error' },
  warn: { emoji: '🟠', color: 0xf59e0b, label: 'Aviso' },
  warning: { emoji: '🟠', color: 0xf59e0b, label: 'Aviso' },
  success: { emoji: '🟢', color: 0x059669, label: 'Correcto' },
  info: { emoji: '🔵', color: 0x2563eb, label: 'Información' }
};

/**
 * Envío de alertas salientes a Telegram / Discord / Slack / webhook genérico.
 *
 * Reglas de diseño:
 *  - Nunca lanza hacia el llamante: una alerta caída jamás debe tumbar un
 *    despliegue ni el daemon.
 *  - Nunca bloquea: `notify()` devuelve una promesa que el llamante puede ignorar.
 *  - Nunca devuelve secretos: `getConfig()` entrega los tokens enmascarados.
 */
class NotificationService extends EventEmitter {
  /**
   * @param {{ configFile?: string | null, historyFile?: string | null, postFn?: ((url: string, body: any, extraHeaders?: Record<string, string>) => Promise<any>) | null }} [options]
   */
  constructor(options = {}) {
    super();
    this._customConfigFile = options.configFile || null;
    this._customHistoryFile = options.historyFile || null;
    this._customPostFn = options.postFn || null;
    this.config = this.loadConfig();
    /** @type {Array<any>} */
    this.history = [];
    this._historyLoaded = false;
    this.maxHistory = 100;
    // Evita tormentas de avisos idénticos (p. ej. un proceso en bucle de crash).
    this.lastSentAt = new Map();
    this.dedupeWindowMs = 60000;
  }

  getConfigFile() {
    return this._customConfigFile || path.join(resolveDataDir(), 'notifications.json');
  }

  getHistoryFile() {
    return this._customHistoryFile || path.join(resolveDataDir(), 'notification-history.json');
  }

  loadConfig() {
    try {
      const file = this.getConfigFile();
      if (fs.existsSync(file)) {
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
        return this.mergeConfig(DEFAULT_CONFIG, raw);
      }
    } catch (err) {
      console.error('[Notifications] No se pudo leer la configuración:', err.message);
    }
    return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  }

  _ensureHistoryLoaded() {
    if (this._historyLoaded) return;
    this._historyLoaded = true;
    const res = loadJsonWithBackupSync(this.getHistoryFile(), {
      validate: (p) => Array.isArray(p)
    });
    if (res.ok && Array.isArray(res.data)) {
      this.history = res.data.slice(0, this.maxHistory);
    }
  }

  _saveHistory() {
    try {
      atomicWriteJsonSync(this.getHistoryFile(), this.history.slice(0, this.maxHistory), { mode: 0o600, backup: true });
    } catch (e) {}
  }

  mergeConfig(base, override) {
    const out = JSON.parse(JSON.stringify(base));
    if (!override || typeof override !== 'object') return out;
    if (typeof override.enabled === 'boolean') out.enabled = override.enabled;
    if (override.events && typeof override.events === 'object') {
      for (const key of Object.keys(out.events)) {
        if (typeof override.events[key] === 'boolean') out.events[key] = override.events[key];
      }
    }
    if (override.channels && typeof override.channels === 'object') {
      for (const name of Object.keys(out.channels)) {
        const incoming = override.channels[name];
        if (incoming && typeof incoming === 'object') {
          out.channels[name] = { ...out.channels[name], ...incoming };
        }
      }
    }
    return out;
  }

  saveConfig() {
    atomicWriteJsonSync(this.getConfigFile(), this.config, { mode: 0o600, backup: true });
  }

  mask(value) {
    if (!value) return '';
    const str = String(value);
    if (str.length <= 8) return '••••••••';
    return `${str.slice(0, 4)}••••${str.slice(-4)}`;
  }

  /** Configuración segura para la UI: los secretos salen enmascarados. */
  getConfig() {
    const c = this.config;
    return {
      enabled: c.enabled,
      events: { ...c.events },
      channels: {
        telegram: {
          enabled: c.channels.telegram.enabled,
          botToken: this.mask(c.channels.telegram.botToken),
          chatId: c.channels.telegram.chatId,
          configured: Boolean(c.channels.telegram.botToken && c.channels.telegram.chatId)
        },
        discord: {
          enabled: c.channels.discord.enabled,
          webhookUrl: this.mask(c.channels.discord.webhookUrl),
          configured: Boolean(c.channels.discord.webhookUrl)
        },
        slack: {
          enabled: c.channels.slack.enabled,
          webhookUrl: this.mask(c.channels.slack.webhookUrl),
          configured: Boolean(c.channels.slack.webhookUrl)
        },
        webhook: {
          enabled: c.channels.webhook.enabled,
          url: c.channels.webhook.url,
          hasSecretHeader: Boolean(c.channels.webhook.secretHeader),
          configured: Boolean(c.channels.webhook.url)
        }
      }
    };
  }

  /**
   * Aplica cambios de configuración. Un secreto enviado enmascarado (o vacío)
   * se interpreta como "no lo cambies"; enviar `null` lo limpia explícitamente.
   */
  setConfig(patch = {}) {
    const isMasked = (v) => typeof v === 'string' && (v === '' || v.includes('••'));
    const sanitized = JSON.parse(JSON.stringify(patch));

    // Anti-exfiltración (Dokploy #5926): cambiar la URL del webhook teniendo un secretHeader
    // almacenado exige reintroducir explícitamente `secretHeader` (o `null` para borrarlo).
    const incomingWhUrl = sanitized.channels?.webhook?.url;
    const prevWhUrl = this.config.channels.webhook.url || '';
    const prevWhSecret = this.config.channels.webhook.secretHeader || '';
    if (
      typeof incomingWhUrl === 'string' &&
      incomingWhUrl.trim() !== prevWhUrl &&
      prevWhSecret
    ) {
      const incomingSecret = sanitized.channels?.webhook?.secretHeader;
      if (incomingSecret !== null && (incomingSecret === undefined || isMasked(incomingSecret))) {
        throw new Error('Para cambiar la URL del webhook debes volver a introducir el secretHeader (o enviar null para limpiarlo)');
      }
    }

    const secretPaths = [
      ['telegram', 'botToken'],
      ['discord', 'webhookUrl'],
      ['slack', 'webhookUrl'],
      ['webhook', 'secretHeader']
    ];
    for (const [channel, field] of secretPaths) {
      const incoming = sanitized.channels?.[channel]?.[field];
      if (incoming === null) {
        sanitized.channels[channel][field] = '';
      } else if (isMasked(incoming)) {
        delete sanitized.channels[channel][field];
      }
    }
    this.config = this.mergeConfig(this.config, sanitized);
    this.saveConfig();
    return this.getConfig();
  }

  activeChannels() {
    if (!this.config.enabled) return [];
    const c = this.config.channels;
    const active = [];
    if (c.telegram.enabled && c.telegram.botToken && c.telegram.chatId) active.push('telegram');
    if (c.discord.enabled && c.discord.webhookUrl) active.push('discord');
    if (c.slack.enabled && c.slack.webhookUrl) active.push('slack');
    if (c.webhook.enabled && c.webhook.url) active.push('webhook');
    return active;
  }

  getHistory(limit = 30) {
    this._ensureHistoryLoaded();
    return this.history.slice(0, limit);
  }

  /**
   * Envía una alerta por todos los canales activos.
   * @param {{event?:string, level?:string, title?:string, message?:string,
   *          projectId?:string | null, projectName?:string | null, url?:string | null,
   *          force?:boolean, cooldownMs?:number}} [payload]
   */
  async notify(payload = {}) {
    const {
      event = 'info',
      level = 'info',
      title = 'Culkibo',
      message = '',
      projectId = null,
      projectName = null,
      url = null,
      force = false,
      cooldownMs
    } = payload;

    const effectiveWindowMs = typeof cooldownMs === 'number' && cooldownMs >= 0 ? cooldownMs : this.dedupeWindowMs;

    try {
      /** @type {string | null} */
      let dedupeKey = null;
      let dedupeNow = 0;
      if (!force) {
        if (!this.config.enabled) return { sent: false, reason: 'disabled' };
        if (this.config.events[event] === false) return { sent: false, reason: 'event_muted' };

        dedupeKey = `${event}:${projectId || ''}:${title}`;
        dedupeNow = Date.now();
        const last = this.lastSentAt.get(dedupeKey) || 0;
        if (effectiveWindowMs > 0 && dedupeNow - last < effectiveWindowMs) {
          return { sent: false, reason: 'deduplicated' };
        }
        if (this.lastSentAt.size > 500) {
          for (const [k, at] of this.lastSentAt) {
            if (dedupeNow - at >= this.dedupeWindowMs) this.lastSentAt.delete(k);
          }
          if (this.lastSentAt.size > 500) this.lastSentAt.clear();
        }
      }

      const channels = force
        ? this.activeChannelsForTest()
        : this.activeChannels();

      if (channels.length === 0) return { sent: false, reason: 'no_channels' };

      const entry = {
        id: `ntf_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
        timestamp: new Date().toISOString(),
        event,
        level,
        title,
        message,
        projectId,
        projectName,
        channels,
        results: {}
      };

      const sends = channels.map(async (name) => {
        try {
          await this.sendToChannel(name, { level, title, message, projectName, url });
          entry.results[name] = 'ok';
        } catch (err) {
          entry.results[name] = `error: ${err.message}`;
          console.warn(`[Notifications] Falló el envío por ${name}:`, err.message);
        }
      });

      await Promise.allSettled(sends);

      this._ensureHistoryLoaded();
      this.history.unshift(entry);
      if (this.history.length > this.maxHistory) this.history.pop();
      this._saveHistory();
      this.emit('notification', entry);

      const okCount = Object.values(entry.results).filter(r => r === 'ok').length;
      // Registrar ventana anti-tormenta si entregó, o backoff corto (15s) si todos fallaron
      if (dedupeKey) {
        if (okCount > 0) {
          this.lastSentAt.set(dedupeKey, dedupeNow || Date.now());
        } else if (effectiveWindowMs > 15000) {
          this.lastSentAt.set(dedupeKey, (dedupeNow || Date.now()) - effectiveWindowMs + 15000);
        }
      }
      return { sent: okCount > 0, delivered: okCount, results: entry.results, id: entry.id };
    } catch (err) {
      // Una alerta jamás puede propagar un fallo al flujo que la originó.
      console.error('[Notifications] Error inesperado al notificar:', err.message);
      return { sent: false, reason: 'internal_error', error: err.message };
    }
  }

  /** Para el botón "Probar": ignora `enabled` global pero exige credenciales. */
  activeChannelsForTest() {
    const c = this.config.channels;
    const active = [];
    if (c.telegram.botToken && c.telegram.chatId) active.push('telegram');
    if (c.discord.webhookUrl) active.push('discord');
    if (c.slack.webhookUrl) active.push('slack');
    if (c.webhook.url) active.push('webhook');
    return active;
  }

  async sendToChannel(name, { level, title, message, projectName, url }) {
    const meta = LEVEL_META[level] || LEVEL_META.info;
    const heading = projectName ? `${title} — ${projectName}` : title;

    const safeLinkUrl = (() => {
      if (!url || typeof url !== 'string') return null;
      try {
        const u = new URL(url.trim());
        return (u.protocol === 'https:' || u.protocol === 'http:') ? u.toString() : null;
      } catch (e) {
        return null;
      }
    })();

    if (name === 'telegram') {
      const { botToken, chatId } = this.config.channels.telegram;
      const cleanToken = String(botToken || '').trim();
      if (!TELEGRAM_TOKEN_RE.test(cleanToken)) {
        throw new Error('Formato de botToken de Telegram inválido');
      }
      // Escapar primero y truncar el texto plano/escapado SIN cortar nunca etiquetas HTML ni entidades `&...;` ni surrogates UTF-16
      const esc = (s) => this.escapeHtml(s);
      const headerHtml = `<b>${esc(meta.label)}: ${esc(heading.slice(0, 180))}</b>\n`;
      const footerHtml = safeLinkUrl ? `\n<a href="${esc(safeLinkUrl)}">${esc(safeLinkUrl)}</a>` : '';
      const budget = Math.max(128, 4096 - headerHtml.length - footerHtml.length);
      const safeBody = this.truncateHtmlEscaped(esc(String(message || '')), budget);
      const text = `${headerHtml}${safeBody}${footerHtml}`;
      return this.post(`https://api.telegram.org/bot${cleanToken}/sendMessage`, {
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true
      });
    }

    if (name === 'discord') {
      const preParsed = new URL(this.config.channels.discord.webhookUrl);
      if (preParsed.protocol !== 'https:' || !DISCORD_WEBHOOK_HOSTS.has(preParsed.hostname.toLowerCase()) || !preParsed.pathname.startsWith('/api/webhooks/')) {
        throw new Error('La URL de Discord debe ser un webhook oficial (https://discord.com/api/webhooks/...)');
      }
      const { url: parsed } = await assertSafeUrl(preParsed.toString(), { requireHttps: true });
      return this.post(parsed.toString(), {
        username: 'Culkibo',
        embeds: [{
          title: `${meta.emoji} ${heading}`.slice(0, 256),
          description: String(message || '').slice(0, 4000),
          color: meta.color,
          url: safeLinkUrl || undefined,
          footer: { text: 'Culkibo Orchestrator' },
          timestamp: new Date().toISOString()
        }]
      });
    }

    if (name === 'slack') {
      const preParsed = new URL(this.config.channels.slack.webhookUrl);
      if (preParsed.protocol !== 'https:' || !SLACK_WEBHOOK_HOSTS.has(preParsed.hostname.toLowerCase())) {
        throw new Error('La URL de Slack debe ser un webhook oficial (https://hooks.slack.com/...)');
      }
      const { url: parsed } = await assertSafeUrl(preParsed.toString(), { requireHttps: true });
      const escSlack = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const linkPart = safeLinkUrl ? `\n<${safeLinkUrl}|Abrir en Culkibo>` : '';
      const slackBody = `${meta.emoji} *${escSlack(heading.slice(0, 200))}*\n${escSlack(String(message || '').slice(0, 3200))}${linkPart}`;
      return this.post(parsed.toString(), {
        text: slackBody.slice(0, 3900)
      });
    }

    if (name === 'webhook') {
      const { url: target, secretHeader } = this.config.channels.webhook;
      const { url: parsed } = await assertSafeUrl(target, { requireHttps: true });
      const bodyObj = {
        source: 'culkibo',
        level,
        title: heading,
        message,
        projectName,
        url,
        timestamp: new Date().toISOString()
      };
      const rawJson = JSON.stringify(bodyObj);
      /** @type {Record<string, string>} */
      const extraHeaders = {};
      if (secretHeader) {
        extraHeaders['X-Culkibo-Secret'] = secretHeader;
        const hmac = crypto.createHmac('sha256', String(secretHeader)).update(rawJson).digest('hex');
        extraHeaders['X-Culkibo-Signature-256'] = `sha256=${hmac}`;
      }
      return this.post(parsed.toString(), rawJson, extraHeaders);
    }

    throw new Error(`Canal desconocido: ${name}`);
  }

  escapeHtml(text) {
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Trunca texto ya escapado para HTML sin partir entidades `&amp;`/`&lt;` ni pares sustitutos UTF-16. */
  truncateHtmlEscaped(escaped, maxLen) {
    if (escaped.length <= maxLen) return escaped;
    let end = Math.max(0, maxLen - 1);
    // Evitar partir un par sustituto UTF-16 (emoji)
    if (end > 0) {
      const code = escaped.charCodeAt(end - 1);
      if (code >= 0xd800 && code <= 0xdbff) end--;
    }
    // Evitar partir una entidad HTML (`&amp;`, `&lt;`, `&gt;`, `&quot;`)
    const lastAmp = escaped.lastIndexOf('&', end - 1);
    if (lastAmp !== -1 && lastAmp >= end - 7) {
      const semi = escaped.indexOf(';', lastAmp);
      if (semi === -1 || semi >= end) end = lastAmp;
    }
    return `${escaped.slice(0, end)}…`;
  }

  escapeMarkdown(text) {
    return String(text == null ? '' : text).replace(/([_*[\]()~`>#+\-=|{}.!])/g, '\\$1');
  }

  async post(url, body, extraHeaders = {}) {
    if (this._customPostFn) {
      return this._customPostFn(url, body, extraHeaders);
    }
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    let lastStatus = 0;
    let lastText = '';
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await safeFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...extraHeaders },
        body: payload,
        requireHttps: true,
        maxRedirects: 0,
        timeoutMs: 8000
      });
      if (res.ok) return true;
      lastStatus = res.status;
      lastText = res.text().slice(0, 200);
      const retryable = res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504;
      if (attempt === 0 && retryable) {
        const ra = Number(res.headers?.['retry-after'] || 0);
        const delayMs = Number.isFinite(ra) && ra > 0 ? Math.min(5000, ra * 1000) : 1000;
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      break;
    }
    throw new Error(`HTTP ${lastStatus} ${lastText}`);
  }
}

const notificationServiceInstance = Object.assign(new NotificationService(), {
  NotificationService,
  DEFAULT_CONFIG
});
module.exports = notificationServiceInstance;
