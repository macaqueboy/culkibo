'use strict';

const crypto = require('crypto');

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Envía alertas instantáneas a Telegram, Discord, Slack o Webhook genérico
 * cuando aparece un nuevo fallo, una regresión en una nueva versión o un pico de errores.
 * Incluye cooldown por fingerprint para evitar tormentas de alertas.
 */
class TelemetryAlerter {
  /** @param {{ alerts: Record<string, string>, alertCooldownMs?: number, fetchImpl?: typeof fetch }} opts */
  constructor(opts) {
    this.alerts = opts.alerts || {};
    this.cooldownMs = typeof opts.alertCooldownMs === 'number' ? opts.alertCooldownMs : 15 * 60 * 1000;
    this.fetchImpl = opts.fetchImpl || globalThis.fetch;
    /** @type {Map<string, number>} */
    this._cooldowns = new Map();
  }

  hasAnyChannel() {
    const a = this.alerts;
    return Boolean(
      (a.telegramBotToken && a.telegramChatId) ||
      a.discordWebhook ||
      a.slackWebhook ||
      a.webhookUrl
    );
  }

  /** @param {{ trigger: string, fingerprint: string, type: string, title: string, appVersion: string, occurrences: number, affectedInstances: number, sample?: any }} candidate */
  async notify(candidate) {
    if (!this.hasAnyChannel()) return { sent: 0, skipped: 'no_channels' };
    const now = Date.now();
    const key = `${candidate.trigger}:${candidate.fingerprint}`;
    const prev = this._cooldowns.get(key) || 0;
    if (this.cooldownMs > 0 && now - prev < this.cooldownMs) {
      return { sent: 0, skipped: 'cooldown' };
    }
    this._cooldowns.set(key, now);
    if (this._cooldowns.size > 2000) {
      for (const [k, ts] of this._cooldowns.entries()) {
        if (now - ts >= this.cooldownMs) this._cooldowns.delete(k);
      }
    }

    const triggerLabel = candidate.trigger === 'regression'
      ? 'REGRESIÓN DETECTADA'
      : candidate.trigger === 'spike'
        ? 'PICO DE FALLOS'
        : 'NUEVO FALLO EN CULKIBO';

    const tasks = [];
    const a = this.alerts;

    if (a.telegramBotToken && a.telegramChatId) {
      const html = [
        `<b>🚨 ${escapeHtml(triggerLabel)}</b>`,
        `<b>Tipo:</b> <code>${escapeHtml(candidate.type)}</code>`,
        `<b>Versión:</b> <code>v${escapeHtml(candidate.appVersion)}</code> · <b>Ocurrencias:</b> ${candidate.occurrences} (${candidate.affectedInstances} inst.)`,
        `<b>Resumen:</b> ${escapeHtml(candidate.title).slice(0, 300)}`,
        `<b>Fingerprint:</b> <code>${escapeHtml(candidate.fingerprint)}</code>`,
      ].join('\n');
      tasks.push(this._postJson(
        `https://api.telegram.org/bot${encodeURIComponent(a.telegramBotToken)}/sendMessage`,
        { chat_id: a.telegramChatId, text: html, parse_mode: 'HTML', disable_web_page_preview: true }
      ));
    }

    if (a.discordWebhook) {
      tasks.push(this._postJson(a.discordWebhook, {
        embeds: [{
          title: `🚨 ${triggerLabel} (${candidate.type})`,
          description: String(candidate.title || '').slice(0, 400),
          color: candidate.type === 'server_crash' ? 0xdc2626 : 0xf59e0b,
          fields: [
            { name: 'Versión', value: `v${candidate.appVersion}`, inline: true },
            { name: 'Ocurrencias', value: String(candidate.occurrences), inline: true },
            { name: 'Instancias', value: String(candidate.affectedInstances), inline: true },
            { name: 'Fingerprint', value: `\`${candidate.fingerprint}\``, inline: false },
          ],
          timestamp: new Date().toISOString(),
        }],
      }));
    }

    if (a.slackWebhook) {
      const text = `*🚨 ${triggerLabel}* (\`${candidate.type}\` · v${candidate.appVersion})\n${String(candidate.title || '').slice(0, 350)}\nOcurrencias: *${candidate.occurrences}* · Instancias: *${candidate.affectedInstances}* · FP: \`${candidate.fingerprint}\``;
      tasks.push(this._postJson(a.slackWebhook, { text }));
    }

    if (a.webhookUrl) {
      const bodyObj = {
        event: 'culkibo_telemetry_alert',
        sentAt: new Date().toISOString(),
        ...candidate,
      };
      const rawBody = JSON.stringify(bodyObj);
      /** @type {Record<string, string>} */
      const extraHeaders = {};
      if (a.webhookSecret) {
        const sig = crypto.createHmac('sha256', a.webhookSecret).update(rawBody).digest('hex');
        extraHeaders['X-Culkibo-Signature'] = `sha256=${sig}`;
      }
      tasks.push(this._postJson(a.webhookUrl, bodyObj, extraHeaders));
    }

    const settled = await Promise.allSettled(tasks);
    const sent = settled.filter((r) => r.status === 'fulfilled' && r.value).length;
    return { sent };
  }

  /** @param {string} url @param {any} payload @param {Record<string, string>} [extraHeaders] */
  async _postJson(url, payload, extraHeaders = {}) {
    try {
      const res = await this.fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...extraHeaders },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

module.exports = { TelemetryAlerter };
