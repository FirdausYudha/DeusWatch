// Mock data for DeusWatch redesign prototype
export const stats = { totalEvents: '2.4M', totalAlerts: '18,204', alerts24h: 312, dbSize: '41.2 GB / 200 GB' };

export const severityBreakdown = [
  { label: 'Critical', value: 42, color: '#f43f5e' },
  { label: 'High', value: 118, color: '#fb923c' },
  { label: 'Medium', value: 640, color: '#f59e0b' },
  { label: 'Low', value: 1240, color: '#38bdf8' },
  { label: 'Info', value: 3800, color: '#64748b' }
];

export const eventsOverTime = [12,18,14,22,30,26,34,40,31,44,38,52,48,60,55,70,62,58,66,74];

export const topIPs = [
  { ip: '185.220.101.42', country: 'RO', count: 812, band: 'critical' },
  { ip: '45.155.204.11', country: 'RU', count: 540, band: 'high' },
  { ip: '103.28.52.9', country: 'CN', count: 391, band: 'high' },
  { ip: '192.42.116.20', country: 'DE', count: 210, band: 'medium' },
  { ip: '198.98.51.7', country: 'US', count: 96, band: 'low' }
];

export const topRules = [
  { name: 'SSH Brute Force Attempt', hits: 2140, severity: 'high' },
  { name: 'Suspicious PowerShell Encoded Command', hits: 980, severity: 'critical' },
  { name: 'Multiple Failed Logins - Web Portal', hits: 760, severity: 'medium' },
  { name: 'Outbound Connection to Known Tor Exit', hits: 512, severity: 'high' },
  { name: 'File Integrity: Unexpected System32 Change', hits: 210, severity: 'critical' }
];

export const topMitre = [
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', hits: 2140 },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', hits: 980 },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', hits: 512 },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', hits: 44 }
];

export const attackOrigins = [
  { country: 'Romania', code: 'RO', count: 812 },
  { country: 'Russia', code: 'RU', count: 540 },
  { country: 'China', code: 'CN', count: 391 },
  { country: 'Germany', code: 'DE', count: 210 },
  { country: 'United States', code: 'US', count: 96 }
];

export const riskyIPs = [
  { ip: '185.220.101.42', score: 94, band: 'critical', abuse: 98, otx: 6 },
  { ip: '45.155.204.11', score: 78, band: 'high', abuse: 82, otx: 3 },
  { ip: '103.28.52.9', score: 61, band: 'high', abuse: 55, otx: 2 },
  { ip: '192.42.116.20', score: 38, band: 'medium', abuse: 30, otx: 0 }
];

export const suspiciousIPs = [
  { ip: '77.91.68.14', fanout: 0.82, failure: 0.61, spread: 0.7, note: 'Scanning 40+ hosts, low volume per host' },
  { ip: '203.0.113.6', fanout: 0.55, failure: 0.4, spread: 0.44, note: 'Slow credential probing over 6 days' }
];

export const llmVerdicts = [
  { label: 'Benign', value: 812, color: '#10b981' },
  { label: 'Suspicious', value: 96, color: '#f59e0b' },
  { label: 'Malicious', value: 22, color: '#f43f5e' },
  { label: 'Not analyzed', value: 340, color: '#64748b' }
];

export const eventsTable = [
  { time: '14:32:08', severity: 'critical', rule: 'File Integrity: Encrypted Extension Detected', ip: '10.0.4.18', geo: 'Internal', agent: 'db-prod-02', mitre: 'T1486', score: 91, band: 'critical', llm: 'malicious', action: 'recommended' },
  { time: '14:29:51', severity: 'high', rule: 'SSH Brute Force Attempt', ip: '185.220.101.42', geo: 'RO', agent: 'edge-gw-01', mitre: 'T1110', score: 94, band: 'critical', llm: 'suspicious', action: 'approved' },
  { time: '14:21:03', severity: 'medium', rule: 'Multiple Failed Logins - Web Portal', ip: '45.155.204.11', geo: 'RU', agent: 'web-01', mitre: 'T1110', score: 78, band: 'high', llm: 'not-analyzed', action: '—' },
  { time: '14:10:44', severity: 'high', rule: 'Suspicious PowerShell Encoded Command', ip: '10.0.2.5', geo: 'Internal', agent: 'ws-finance-07', mitre: 'T1059.001', score: 52, band: 'medium', llm: 'suspicious', action: 'executed' },
  { time: '13:58:12', severity: 'low', rule: 'Outbound Connection to Known Tor Exit', ip: '103.28.52.9', geo: 'CN', agent: 'edge-gw-01', mitre: 'T1071', score: 61, band: 'high', llm: 'not-analyzed', action: '—' },
  { time: '13:40:29', severity: 'info', rule: 'Agent Configuration Updated', ip: '—', geo: '—', agent: 'db-prod-02', mitre: '—', score: 0, band: 'low', llm: 'not-analyzed', action: '—' }
];

export const responseByIP = [
  { ip: '185.220.101.42', count: 14, pending: 2, score: 94, band: 'critical', status: 'approved', duration: '1h' },
  { ip: '45.155.204.11', count: 6, pending: 1, score: 78, band: 'high', status: 'recommended', duration: '30m' },
  { ip: '103.28.52.9', count: 3, pending: 0, score: 61, band: 'high', status: 'executed', duration: '10m' },
  { ip: '192.42.116.20', count: 1, pending: 0, score: 38, band: 'medium', status: 'dismissed', duration: '—' }
];

export const responseEvents = [
  { time: '14:29:51', ip: '185.220.101.42', entity: 'external_ip', action: 'block', status: 'approved', by: 'a.rahman' },
  { time: '14:21:10', ip: '45.155.204.11', entity: 'external_ip', action: 'block', status: 'recommended', by: 'system' },
  { time: '13:12:44', ip: 'ws-finance-07', entity: 'host', action: 'network_containment', status: 'executed', by: 'system' },
  { time: '11:02:19', ip: '103.28.52.9', entity: 'external_ip', action: 'block', status: 'executed', by: 'a.rahman' }
];

export const containedHosts = [
  { agent: 'ws-finance-07', host: 'FINANCE-07', ip: '10.0.2.5', reason: 'Ransomware behavior detected', status: 'contained', expiry: '2026-07-20 09:00', auto: true },
  { agent: 'db-prod-02', host: 'DB-PROD-02', ip: '10.0.4.18', reason: 'Mass file encryption', status: 'recommended', expiry: '—', auto: false }
];

export const decisionTable = [
  { entity: 'external_ip', action: 'block', enforcement: 'auto', rationale: 'Confirmed malicious source, firewall bouncer active' },
  { entity: 'host', action: 'network_containment', rationale: 'Isolate to stop lateral spread', enforcement: 'auto' },
  { entity: 'user', action: 'alert', rationale: 'Account actions require human review', enforcement: 'alert-only' },
  { entity: 'hash', action: 'alert', rationale: 'No automated file removal without confirmation', enforcement: 'alert-only' }
];

export const agents = [
  { name: 'edge-gw-01', os: 'Linux (Debian 12)', status: 'online', lastSeen: '2s ago', version: 'v42' },
  { name: 'db-prod-02', os: 'Linux (Ubuntu 22.04)', status: 'degraded', lastSeen: '11s ago', version: 'v42' },
  { name: 'ws-finance-07', os: 'Windows 11', status: 'disconnected', lastSeen: '3h ago', version: 'v39' },
  { name: 'web-01', os: 'Linux (Alpine)', status: 'online', lastSeen: '4s ago', version: 'v42' },
  { name: 'ws-hr-02', os: 'Windows 10', status: 'stale', lastSeen: '6d ago', version: 'v31' }
];

export const watchedFiles = [
  { path: '/etc/passwd', versions: 4, agent: 'edge-gw-01' },
  { path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', versions: 2, agent: 'ws-finance-07' },
  { path: '/var/www/app/config.php', versions: 7, agent: 'web-01' }
];

export const fileVersions = [
  { time: '2026-07-19 14:32', trigger: 'on_change', storage: 'manager', size: '2.1 KB', sha: 'a91f...c02e', changeType: 'encrypted' },
  { time: '2026-07-18 09:03', trigger: 'scheduled', storage: 'agent', size: '1.8 KB', sha: '77bd...11a4', changeType: 'modified' },
  { time: '2026-07-11 22:14', trigger: 'manual', storage: 'manager', size: '1.8 KB', sha: 'f302...9e01', changeType: 'modified' },
  { time: '2026-06-30 00:00', trigger: 'on_change', storage: 'agent', size: '1.7 KB', sha: '0c5d...44bb', changeType: 'created' }
];

export const diffLines = [
  { type: 'ctx', text: '  root:x:0:0:root:/root:/bin/bash' },
  { type: 'del', text: '- daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' },
  { type: 'add', text: '+ daemon:x:1:1:daemon:/usr/sbin:/bin/bash' },
  { type: 'add', text: '+ backdoor:x:0:0::/root:/bin/bash' },
  { type: 'ctx', text: '  bin:x:2:2:bin:/bin:/usr/sbin/nologin' }
];

export const integrationCategories = [
  { name: 'CTI', items: [
    { name: 'AbuseIPDB', desc: 'IP reputation & abuse confidence score', enabled: true },
    { name: 'AlienVault OTX', desc: 'Pulse-based threat intel feed', enabled: true }
  ]},
  { name: 'FIM Reputation', items: [
    { name: 'VirusTotal', desc: 'Hash reputation lookups', enabled: true },
    { name: 'MalwareBazaar', desc: 'Malware sample hash database', enabled: false },
    { name: 'CIRCL hashlookup', desc: 'Known-good hash database', enabled: false }
  ]},
  { name: 'Firewall / Bouncer', items: [
    { name: 'MikroTik', desc: 'Multi-router ban sync', enabled: false },
    { name: 'CrowdSec LAPI', desc: 'Community blocklist bouncer', enabled: false },
    { name: 'Agent nftables', desc: 'Local enforcement via agent', enabled: true }
  ]},
  { name: 'LLM', items: [
    { name: 'Ollama', desc: 'Self-hosted model for triage & report', enabled: true },
    { name: 'OpenAI-compatible', desc: 'External API, triage/report', enabled: false },
    { name: 'Anthropic', desc: 'External API, triage/report', enabled: false }
  ]},
  { name: 'Ingest', items: [
    { name: 'Wazuh Webhook', desc: 'Sensor alert ingestion', enabled: true },
    { name: 'OpenSearch Pull', desc: 'Pull logs from OpenSearch/Elasticsearch', enabled: false }
  ]}
];

export const reportSummary = {
  range: '2026-07-12 → 2026-07-19',
  totals: { events: '2.4M', alerts: 18204, critical: 42 },
  topRule: 'SSH Brute Force Attempt',
  topIP: '185.220.101.42',
  topTechnique: 'T1110 — Brute Force'
};

export const rulesList = [
  { name: 'SSH Brute Force Attempt', severity: 'high', mitre: 'T1110', category: 'Auth', enabled: true },
  { name: 'Suspicious PowerShell Encoded Command', severity: 'critical', mitre: 'T1059.001', category: 'Execution', enabled: true },
  { name: 'File Integrity: Unexpected System32 Change', severity: 'critical', mitre: 'T1486', category: 'FIM', enabled: true },
  { name: 'Outbound Connection to Known Tor Exit', severity: 'high', mitre: 'T1071', category: 'Network', enabled: false }
];

export const decodersList = [
  { name: 'nginx-access', match: 'combined log format', fields: 8 },
  { name: 'wineventlog-security', match: 'Windows Security channel', fields: 14 },
  { name: 'sshd-syslog', match: 'sshd auth lines', fields: 6 }
];

export const playbooksList = [
  { label: 'ransomware-encryption-burst', title: 'Ransomware — Encryption Burst', steps: 5 },
  { label: 'ssh-bruteforce', title: 'SSH Brute Force', steps: 3 },
  { label: 'suspicious-powershell', title: 'Suspicious PowerShell Execution', steps: 4 }
];
