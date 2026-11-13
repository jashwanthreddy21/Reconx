import {
  Assessment,
  Finding,
  FindingSeverity,
  WebhookNotificationConfig,
  WebhookSeverityThreshold,
} from '../types';

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const THRESHOLD_RANK: Record<WebhookSeverityThreshold, number> = {
  medium: 2,
  high: 3,
  critical: 4,
};

export interface SlackWebhookDispatchResult {
  ok: boolean;
  statusCode: number;
  alertedCount: number;
  message: string;
  deliveredAt: string;
}

export interface SlackBlockPayload {
  text: string;
  blocks: Array<Record<string, any>>;
}

export function isValidSlackWebhookUrl(rawUrl: string): {
  valid: boolean;
  reason?: string;
  isOfficialSlackHost: boolean;
} {
  const trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    return { valid: false, reason: 'Webhook URL is required when Slack alerting is enabled.', isOfficialSlackHost: false };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: 'Enter a valid URL (e.g. https://hooks.slack.com/services/T.../B.../...).', isOfficialSlackHost: false };
  }

  if (parsed.protocol !== 'https:') {
    return { valid: false, reason: 'Slack webhook URLs must use HTTPS.', isOfficialSlackHost: false };
  }

  const isOfficialSlackHost =
    parsed.hostname === 'hooks.slack.com' || parsed.hostname.endsWith('.slack.com');

  if (isOfficialSlackHost && !parsed.pathname.startsWith('/services/')) {
    return {
      valid: false,
      reason: 'Slack Incoming Webhook URLs should start with https://hooks.slack.com/services/...',
      isOfficialSlackHost: true,
    };
  }

  return { valid: true, isOfficialSlackHost };
}

export function shouldAlertForFinding(
  finding: Finding,
  config?: WebhookNotificationConfig
): boolean {
  if (!config || !config.enabled || !config.webhookUrl?.trim()) return false;
  const threshold = THRESHOLD_RANK[config.minSeverity || 'high'] ?? 3;
  const rank = SEVERITY_RANK[finding.severity] ?? 0;
  return rank >= threshold;
}

export function filterAlertableFindings(
  findings: Finding[],
  config?: WebhookNotificationConfig
): Finding[] {
  return findings
    .filter((f) => shouldAlertForFinding(f, config))
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
}

export function buildSlackAlertPayload(params: {
  assessment: Pick<Assessment, 'id' | 'name' | 'scope' | 'clientName'>;
  findings: Finding[];
  webhookConfig: WebhookNotificationConfig;
  riskScore?: number;
  riskTier?: FindingSeverity;
  isTest?: boolean;
}): SlackBlockPayload {
  const { assessment, findings, webhookConfig, riskScore, riskTier, isTest } = params;
  const domain = assessment.scope?.rootDomain || 'unknown-target';
  const channelLabel = webhookConfig.channelName?.trim() || '#security-alerts';
  const minSeverityLabel = (webhookConfig.minSeverity || 'high').toUpperCase();

  if (isTest) {
    return {
      text: `[ReconX] Webhook verification test succeeded for ${domain} (${channelLabel})`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: 'ReconX Security Alert — Webhook Test Verified',
            emoji: true,
          },
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `Automated Slack alerting is configured for *${assessment.name || 'New Assessment'}* targeting \`${domain}\`.`,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Target Domain:*\n\`${domain}\`` },
            { type: 'mrkdwn', text: `*Target Channel:*\n${channelLabel}` },
            { type: 'mrkdwn', text: `*Severity Threshold:*\n${minSeverityLabel}+` },
            { type: 'mrkdwn', text: `*Status:*\nConnection Ready` },
          ],
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: `ReconX Attack Surface Management • Sent ${new Date().toISOString()}`,
            },
          ],
        },
      ],
    };
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;

  const headline =
    criticalCount > 0
      ? `[ReconX CRITICAL] ${findings.length} high-priority vulnerability alert(s) discovered on ${domain}`
      : `[ReconX ALERT] ${findings.length} high-severity vulnerability alert(s) discovered on ${domain}`;

  const topFindings = findings.slice(0, 5);
  const findingLines = topFindings.map((f, idx) => {
    const tag = f.severity.toUpperCase();
    return `*${idx + 1}. [${tag}] ${f.title}*\nAsset: \`${f.assetRef}\` • Tool: ${f.sourceTool}\n_${f.evidence || f.description}_`;
  });

  const extraCount = findings.length - topFindings.length;
  if (extraCount > 0) {
    findingLines.push(`_+${extraCount} additional ${minSeverityLabel}+ finding(s) recorded in ReconX._`);
  }

  const blocks: Array<Record<string, any>> = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text:
          criticalCount > 0
            ? `🚨 Critical Attack Surface Alert — ${domain}`
            : `⚠️ High-Severity Scan Alert — ${domain}`,
        emoji: true,
      },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Assessment:*\n${assessment.name}` },
        { type: 'mrkdwn', text: `*Target Domain:*\n\`${domain}\`` },
        {
          type: 'mrkdwn',
          text: `*Alert Counts:*\nCritical: *${criticalCount}* | High: *${highCount}*${mediumCount > 0 ? ` | Medium: *${mediumCount}*` : ''}`,
        },
        {
          type: 'mrkdwn',
          text:
            riskScore !== undefined
              ? `*Weighted Risk Score:*\n*${riskScore}/100* (${(riskTier || 'high').toUpperCase()})`
              : `*Alert Channel:*\n${channelLabel}`,
        },
      ],
    },
    { type: 'divider' },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text:
          findingLines.length > 0
            ? findingLines.join('\n\n')
            : `Scan completed for \`${domain}\` with webhook notification trigger active.`,
      },
    },
    {
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `ReconX Assessment ID: \`${assessment.id}\` • Threshold: ${minSeverityLabel}+ • Channel: ${channelLabel}`,
        },
      ],
    },
  ];

  return {
    text: headline,
    blocks,
  };
}

export async function dispatchSlackWebhookAlert(params: {
  assessment: Pick<Assessment, 'id' | 'name' | 'scope' | 'clientName'>;
  findings: Finding[];
  webhookConfig: WebhookNotificationConfig;
  riskScore?: number;
  riskTier?: FindingSeverity;
  isTest?: boolean;
  apiBaseUrl?: string;
}): Promise<SlackWebhookDispatchResult> {
  const {
    assessment,
    findings,
    webhookConfig,
    riskScore,
    riskTier,
    isTest = false,
    apiBaseUrl = '',
  } = params;

  const payload = buildSlackAlertPayload({
    assessment,
    findings,
    webhookConfig,
    riskScore,
    riskTier,
    isTest,
  });

  const res = await fetch(`${apiBaseUrl}/api/notifications/slack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      webhookUrl: webhookConfig.webhookUrl.trim(),
      channelName: webhookConfig.channelName?.trim() || undefined,
      assessmentId: assessment.id,
      assessmentName: assessment.name,
      rootDomain: assessment.scope?.rootDomain,
      alertedCount: isTest ? 0 : findings.length,
      isTest,
      payload,
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.ok) {
    return {
      ok: false,
      statusCode: res.status || 500,
      alertedCount: 0,
      message: data.error || data.message || `Webhook delivery failed (HTTP ${res.status})`,
      deliveredAt: new Date().toISOString(),
    };
  }

  return {
    ok: true,
    statusCode: data.statusCode || 200,
    alertedCount: data.alertedCount ?? (isTest ? 0 : findings.length),
    message: data.message || 'Slack alert dispatched successfully.',
    deliveredAt: data.deliveredAt || new Date().toISOString(),
  };
}
