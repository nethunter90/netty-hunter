/**
 * Notification service — sends alerts to Slack, Discord, or custom webhooks
 * when high-severity findings are confirmed.
 */
import axios from "axios";
import logger from "../../utils/logger";

export interface NotificationPayload {
  type: "finding_confirmed" | "report_submitted" | "hunt_complete" | "ssrf_pivot" | "secret_found";
  severity?: string;
  vulnType?: string;
  targetUrl?: string;
  cvssScore?: number;
  reportUrl?: string;
  detail?: string;
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};

class NotificationService {
  private readonly slackWebhook  = process.env.SLACK_WEBHOOK_URL;
  private readonly discordWebhook = process.env.DISCORD_WEBHOOK_URL;
  private readonly genericWebhook = process.env.NOTIFY_WEBHOOK_URL;

  async notify(payload: NotificationPayload): Promise<void> {
    const promises: Promise<void>[] = [];
    if (this.slackWebhook)   promises.push(this.sendSlack(payload));
    if (this.discordWebhook) promises.push(this.sendDiscord(payload));
    if (this.genericWebhook) promises.push(this.sendGeneric(payload));
    await Promise.allSettled(promises);
  }

  // Only notify for high-value events — avoid noise
  shouldNotify(payload: NotificationPayload): boolean {
    if (payload.type === "finding_confirmed") {
      return ["critical", "high"].includes(payload.severity ?? "");
    }
    if (payload.type === "secret_found")  return true;
    if (payload.type === "ssrf_pivot")    return true;
    if (payload.type === "report_submitted") return true;
    return false;
  }

  async notifyIfWorthy(payload: NotificationPayload): Promise<void> {
    if (this.shouldNotify(payload)) await this.notify(payload);
  }

  private formatMessage(payload: NotificationPayload): string {
    const emoji = SEVERITY_EMOJI[payload.severity ?? "info"] ?? "⚪";
    switch (payload.type) {
      case "finding_confirmed":
        return `${emoji} *[FINDING]* ${payload.vulnType?.toUpperCase()} on \`${payload.targetUrl}\` — CVSS ${payload.cvssScore ?? "?"} (${payload.severity?.toUpperCase()})${payload.detail ? `\n> ${payload.detail}` : ""}`;
      case "secret_found":
        return `🔑 *[SECRET LEAK]* Credentials found in \`${payload.targetUrl}\`\n> ${payload.detail}`;
      case "ssrf_pivot":
        return `🔗 *[SSRF PIVOT]* Internal services reachable via \`${payload.targetUrl}\`\n> ${payload.detail}`;
      case "report_submitted":
        return `📤 *[REPORT SUBMITTED]* ${payload.vulnType} → ${payload.reportUrl ?? "submitted"}`;
      case "hunt_complete":
        return `✅ *[HUNT COMPLETE]* \`${payload.targetUrl}\` — ${payload.detail}`;
      default:
        return `ℹ️ *[NETTY-HUNTER]* ${payload.detail ?? JSON.stringify(payload)}`;
    }
  }

  private async sendSlack(payload: NotificationPayload): Promise<void> {
    try {
      await axios.post(this.slackWebhook!, {
        text: this.formatMessage(payload),
        mrkdwn: true,
      }, { timeout: 5000 });
    } catch (err) {
      logger.warn("[NotificationService] Slack send failed", { err: String(err) });
    }
  }

  private async sendDiscord(payload: NotificationPayload): Promise<void> {
    try {
      // Discord uses "content" for plain/markdown messages
      await axios.post(this.discordWebhook!, {
        content: this.formatMessage(payload).replace(/\*/g, "**"),
        username: "Netty Hunter",
      }, { timeout: 5000 });
    } catch (err) {
      logger.warn("[NotificationService] Discord send failed", { err: String(err) });
    }
  }

  private async sendGeneric(payload: NotificationPayload): Promise<void> {
    try {
      await axios.post(this.genericWebhook!, payload, {
        headers: { "Content-Type": "application/json" },
        timeout: 5000,
      });
    } catch (err) {
      logger.warn("[NotificationService] Generic webhook send failed", { err: String(err) });
    }
  }
}

export const notificationService = new NotificationService();
