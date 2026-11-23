const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const { assertSafeUrl, safeFetch, atomicWriteJsonSync } = require('./ssrfGuard');

const CONFIG_FILE = path.join(__dirname, '..', '..', 'data', 'notifications.json');
const TELEGRAM_TOKEN_RE = /^\d{5,15}:[A-Za-z0-9_-]{20,80}$/;
const DISCORD_WEBHOOK_HOSTS = new Set(['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com']);
const SLACK_WEBHOOK_HOSTS = new Set(['hooks.slack.com', 'hooks.gov-slack.com']);

const DEFAULT_CONFIG = {
  enabled: false,
  // Qué eventos disparan un aviso. Coinciden con los tipos usados en notify().
  events: {
    service_down: true,
    deploy_failed: true,
    deploy_succeeded: false,
    rollback: true,
    backup_failed: true,
    production_unhealthy: true,
    ssl_issued: false,
    project_stopped: false
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
  constructor() {
    super();
    this.config = this.loadConfig();
    this.history = [];
    this.maxHistory = 100;
    // Evita tormentas de avisos idénticos (p. ej. un proceso en bucle de crash).
    this.lastSentAt = new Map();
    this.dedupeWindowMs = 60000;
  }

  loadConfig() {
    try {
      if (fs.existsSync(CONFIG_FILE)) {
        const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        return this.mergeConfig(DEFAULT_CONFIG, raw);
      }
    } catch (err) {
      console.error('[Notifications] No se pudo leer la configuración:', err.message);
    }
    return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
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
    atomicWriteJsonSync(CONFIG_FILE, this.config, 0o600);
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
    return this.history.slice(0, limit);
  }

  /**
   * Envía una alerta por todos los canales activos.
   * @param {{event?:string, level?:string, title?:string, message?:string,
   *          projectId?:string | null, projectName?:string | null, url?:string | null, force?:boolean}} [payload]
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
      force = false
    } = payload;

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
        if (dedupeNow - last < this.dedupeWindowMs) {
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

      this.history.unshift(entry);
      if (this.history.length > this.maxHistory) this.history.pop();
      this.emit('notification', entry);

      const okCount = Object.values(entry.results).filter(r => r === 'ok').length;
      // Solo registrar ventana anti-tormenta cuando al menos un canal entregó la alerta.
      if (okCount > 0 && dedupeKey) {
        this.lastSentAt.set(dedupeKey, dedupeNow || Date.now());
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

    if (name === 'telegram') {
      const { botToken, chatId } = this.config.channels.telegram;
      const cleanToken = String(botToken || '').trim();
      if (!TELEGRAM_TOKEN_RE.test(cleanToken)) {
        throw new Error('Formato de botToken de Telegram inválido');
      }
      // P1-6: no aplicar encodeURIComponent al token (convertía ':' en '%3A' y daba 404 en Telegram)
      // y usar HTML con escape seguro en lugar de Markdown v1 con escapes v2.
      const esc = (s) => this.escapeHtml(s);
      const safeUrl = url ? `\n<a href="${esc(url)}">${esc(url)}</a>` : '';
      const rawText = `<b>${esc(meta.label)}: ${esc(heading.slice(0, 200))}</b>\n${esc(String(message).slice(0, 3600))}${safeUrl}`;
      const text = rawText.slice(0, 4096);
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
          url: url || undefined,
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
      return this.post(parsed.toString(), {
        text: `${meta.emoji} *${heading}*\n${message}${url ? `\n<${url}|Abrir en Culkibo>` : ''}`
      });
    }

    if (name === 'webhook') {
      const { url: target, secretHeader } = this.config.channels.webhook;
      const { url: parsed } = await assertSafeUrl(target, { requireHttps: true });
      return this.post(parsed.toString(), {
        source: 'culkibo',
        level,
        title: heading,
        message,
        projectName,
        url,
        timestamp: new Date().toISOString()
      }, secretHeader ? { 'X-Culkibo-Secret': secretHeader } : {});
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

  escapeMarkdown(text) {
    return String(text == null ? '' : text).replace(/([_*[\]()~`>#+\-=|{}.!])/g, '\\$1');
  }

  async post(url, body, extraHeaders = {}) {
    const res = await safeFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body: JSON.stringify(body),
      requireHttps: true,
      maxRedirects: 0,
      timeoutMs: 8000
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.text().slice(0, 200)}`);
    }
    return true;
  }
}

module.exports = new NotificationService();
