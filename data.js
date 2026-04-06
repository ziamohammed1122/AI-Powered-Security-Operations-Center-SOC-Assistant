// ============================================================
// AI SOC Assistant - Simulated Security Data & AI Engine
// ============================================================

const ATTACK_TYPES = [
  'Brute Force', 'SQL Injection', 'XSS Attack', 'DDoS', 'Phishing',
  'Ransomware', 'Malware', 'Port Scanning', 'Privilege Escalation',
  'Data Exfiltration', 'Man-in-the-Middle', 'Zero-Day Exploit',
  'Credential Stuffing', 'DNS Tunneling', 'Cryptojacking'
];

const SOURCES = [
  { name: 'Firewall', icon: '🛡️' },
  { name: 'IDS/IPS', icon: '🔍' },
  { name: 'SIEM', icon: '📊' },
  { name: 'Endpoint', icon: '💻' },
  { name: 'Cloud WAF', icon: '☁️' },
  { name: 'Email Gateway', icon: '📧' },
  { name: 'DNS Server', icon: '🌐' },
  { name: 'Active Directory', icon: '🗂️' },
  { name: 'VPN Gateway', icon: '🔐' },
  { name: 'Web Server', icon: '🖥️' }
];

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ff1744', bg: 'rgba(255,23,68,0.15)', weight: 4 },
  high:     { label: 'High',     color: '#ff9100', bg: 'rgba(255,145,0,0.15)', weight: 3 },
  medium:   { label: 'Medium',   color: '#ffea00', bg: 'rgba(255,234,0,0.15)', weight: 2 },
  low:      { label: 'Low',      color: '#00e676', bg: 'rgba(0,230,118,0.15)', weight: 1 }
};

const STATUS_OPTIONS = ['Open', 'Investigating', 'Contained', 'Resolved', 'False Positive'];

const SAMPLE_IPS = [
  '192.168.1.105', '10.0.0.23', '172.16.0.88', '203.0.113.42', '198.51.100.17',
  '45.33.32.156', '91.198.174.192', '185.199.108.153', '104.244.42.1', '151.101.1.140',
  '23.235.39.102', '64.233.160.34', '157.240.1.35', '52.84.150.12', '34.107.243.93'
];

const TARGET_ASSETS = [
  'Web Server (prod-web-01)', 'Database Server (db-primary)', 'API Gateway (api-gw-01)',
  'Mail Server (mail-01)', 'Domain Controller (dc-01)', 'File Server (fs-01)',
  'CI/CD Pipeline (jenkins-01)', 'Kubernetes Cluster (k8s-prod)', 'S3 Bucket (data-lake)',
  'VPN Concentrator (vpn-01)', 'Load Balancer (lb-01)', 'DNS Server (dns-01)'
];

const REMEDIATION_ACTIONS = {
  'Brute Force': [
    'Block source IP immediately at firewall level',
    'Enable account lockout policy (5 failed attempts)',
    'Implement CAPTCHA on login forms',
    'Deploy multi-factor authentication (MFA)',
    'Review and rotate compromised credentials'
  ],
  'SQL Injection': [
    'Deploy Web Application Firewall (WAF) rules',
    'Implement parameterized queries across all endpoints',
    'Sanitize and validate all user inputs',
    'Review database permissions and apply least privilege',
    'Scan for additional injection vulnerabilities'
  ],
  'XSS Attack': [
    'Implement Content Security Policy (CSP) headers',
    'Enable output encoding on all dynamic content',
    'Deploy XSS protection WAF rules',
    'Sanitize all user-generated content',
    'Review and patch affected web pages'
  ],
  'DDoS': [
    'Activate DDoS mitigation service (e.g., Cloudflare)',
    'Rate-limit incoming requests by source IP',
    'Enable geo-blocking for non-essential regions',
    'Scale infrastructure horizontally to absorb traffic',
    'Implement traffic analysis and anomaly detection'
  ],
  'Phishing': [
    'Quarantine suspicious emails across organization',
    'Block sender domain and associated URLs',
    'Alert affected users and force password resets',
    'Scan endpoints for downloaded attachments/malware',
    'Update email gateway filtering rules'
  ],
  'Ransomware': [
    'Isolate affected systems from network IMMEDIATELY',
    'Disable compromised user accounts',
    'Initiate incident response plan and notify CISO',
    'Verify backup integrity and prepare for restoration',
    'Preserve forensic evidence for investigation'
  ],
  'Malware': [
    'Quarantine infected endpoints immediately',
    'Run full system scans with updated signatures',
    'Block C2 communication IPs at firewall',
    'Analyze malware sample in sandbox environment',
    'Reset credentials for affected user accounts'
  ],
  'Port Scanning': [
    'Block scanning source IP at perimeter firewall',
    'Audit exposed services and close unnecessary ports',
    'Enable port scan detection on IDS/IPS',
    'Review firewall rules for misconfigurations',
    'Monitor for follow-up exploitation attempts'
  ],
  'Privilege Escalation': [
    'Revoke elevated privileges immediately',
    'Audit all recent privilege changes and access logs',
    'Patch vulnerable system components',
    'Implement just-in-time (JIT) access controls',
    'Review and harden service account permissions'
  ],
  'Data Exfiltration': [
    'Block outbound connections to suspicious destinations',
    'Enable DLP policies on all egress points',
    'Identify and classify exfiltrated data',
    'Preserve network traffic logs for forensic analysis',
    'Notify legal/compliance teams for breach assessment'
  ],
  'Man-in-the-Middle': [
    'Enforce TLS 1.3 on all communications',
    'Revoke and reissue potentially compromised certificates',
    'Implement certificate pinning on critical services',
    'Deploy network segmentation to limit lateral movement',
    'Enable HSTS on all web services'
  ],
  'Zero-Day Exploit': [
    'Apply vendor patches or workarounds immediately',
    'Implement virtual patching via WAF/IPS',
    'Isolate affected systems until patch is available',
    'Enable enhanced monitoring on vulnerable components',
    'Engage threat intelligence feeds for IOC updates'
  ],
  'Credential Stuffing': [
    'Deploy credential stuffing detection rules',
    'Implement rate limiting on authentication endpoints',
    'Force password resets on compromised accounts',
    'Enable breached credential detection service',
    'Implement progressive delays on failed logins'
  ],
  'DNS Tunneling': [
    'Block suspicious DNS queries at resolver level',
    'Implement DNS query length and frequency analysis',
    'Deploy DNS security solutions (DNSSEC, DoH)',
    'Monitor for unusual DNS traffic patterns',
    'Restrict DNS access to authorized resolvers only'
  ],
  'Cryptojacking': [
    'Terminate unauthorized mining processes',
    'Block known mining pool domains and IPs',
    'Scan for cryptomining scripts in web assets',
    'Review container/VM resource usage anomalies',
    'Implement endpoint detection for mining software'
  ]
};

const AI_ANALYSIS_TEMPLATES = {
  'Brute Force': {
    summary: 'Automated password guessing attack detected targeting authentication services.',
    details: 'The AI engine identified a sustained brute force attack pattern with {count} failed login attempts from {ip} over a {duration}-minute window. The attack is targeting {target} using a dictionary-based approach with credential combinations from known breach databases.',
    confidence: 94,
    mitre: 'T1110 - Brute Force',
    killChain: 'Initial Access'
  },
  'SQL Injection': {
    summary: 'SQL injection attempt detected in web application input fields.',
    details: 'Malicious SQL payloads were identified in HTTP POST parameters targeting {target}. The attacker from {ip} is attempting to extract database schema information using UNION-based injection techniques. {count} unique injection payloads were detected.',
    confidence: 97,
    mitre: 'T1190 - Exploit Public-Facing Application',
    killChain: 'Initial Access'
  },
  'DDoS': {
    summary: 'Distributed Denial of Service attack in progress against network infrastructure.',
    details: 'A volumetric DDoS attack has been detected with traffic peaking at {count} Gbps. The attack originates from a botnet spanning multiple geographies targeting {target}. SYN flood and HTTP flood vectors have been identified.',
    confidence: 99,
    mitre: 'T1498 - Network Denial of Service',
    killChain: 'Impact'
  },
  'Ransomware': {
    summary: 'Ransomware activity detected with file encryption behavior on critical systems.',
    details: 'The AI engine detected ransomware behavior on {target}. File encryption activity affecting {count} files was detected with rapid succession writes. The ransomware variant communicates with C2 server at {ip}. Immediate containment is critical.',
    confidence: 98,
    mitre: 'T1486 - Data Encrypted for Impact',
    killChain: 'Impact'
  },
  'Phishing': {
    summary: 'Phishing campaign targeting organizational email accounts detected.',
    details: 'A sophisticated phishing campaign was identified targeting {count} email accounts. Emails contain malicious links to credential harvesting pages mimicking internal login portals. Source infrastructure traced to {ip}.',
    confidence: 91,
    mitre: 'T1566 - Phishing',
    killChain: 'Initial Access'
  }
};

// Default template for attack types not explicitly defined
const DEFAULT_ANALYSIS = {
  summary: 'Suspicious activity detected requiring security analyst review.',
  details: 'The AI engine detected anomalous behavior from {ip} targeting {target}. {count} related events were correlated across multiple data sources over a {duration}-minute observation window.',
  confidence: 85,
  mitre: 'TA0001 - Initial Access',
  killChain: 'Reconnaissance'
};

// ============================================================
// Data Generation Functions
// ============================================================

let alertIdCounter = 10000;
let allAlerts = [];

function generateRandomIP() {
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
}

function getRandomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateSeverity() {
  const rand = Math.random();
  if (rand < 0.12) return 'critical';
  if (rand < 0.35) return 'high';
  if (rand < 0.65) return 'medium';
  return 'low';
}

function generateAlert() {
  const attackType = getRandomElement(ATTACK_TYPES);
  const severity = generateSeverity();
  const source = getRandomElement(SOURCES);
  const srcIP = Math.random() > 0.3 ? generateRandomIP() : getRandomElement(SAMPLE_IPS);
  const target = getRandomElement(TARGET_ASSETS);
  const now = new Date();
  const minutesAgo = Math.floor(Math.random() * 1440);
  const timestamp = new Date(now.getTime() - minutesAgo * 60000);
  const count = Math.floor(Math.random() * 500) + 1;
  const duration = Math.floor(Math.random() * 120) + 1;

  const template = AI_ANALYSIS_TEMPLATES[attackType] || DEFAULT_ANALYSIS;
  const analysis = {
    summary: template.summary,
    details: template.details
      .replace('{ip}', srcIP)
      .replace('{target}', target)
      .replace('{count}', count)
      .replace('{duration}', duration),
    confidence: template.confidence + Math.floor(Math.random() * 6) - 3,
    mitre: template.mitre,
    killChain: template.killChain
  };

  alertIdCounter++;
  return {
    id: `ALT-${alertIdCounter}`,
    timestamp,
    attackType,
    severity,
    source,
    srcIP,
    target,
    status: Math.random() > 0.6 ? 'Open' : getRandomElement(STATUS_OPTIONS),
    eventCount: count,
    duration,
    analysis,
    remediation: REMEDIATION_ACTIONS[attackType] || ['Investigate the alert and apply appropriate countermeasures.'],
    isNew: minutesAgo < 5
  };
}

function generateInitialAlerts(count = 50) {
  allAlerts = [];
  for (let i = 0; i < count; i++) {
    allAlerts.push(generateAlert());
  }
  allAlerts.sort((a, b) => b.timestamp - a.timestamp);
  return allAlerts;
}

function generateNewAlert() {
  const alert = generateAlert();
  alert.timestamp = new Date();
  alert.isNew = true;
  alert.status = 'Open';
  allAlerts.unshift(alert);
  return alert;
}

// ============================================================
// Dashboard Metrics
// ============================================================

function getMetrics() {
  const total = allAlerts.length;
  const critical = allAlerts.filter(a => a.severity === 'critical').length;
  const high = allAlerts.filter(a => a.severity === 'high').length;
  const medium = allAlerts.filter(a => a.severity === 'medium').length;
  const low = allAlerts.filter(a => a.severity === 'low').length;
  const open = allAlerts.filter(a => a.status === 'Open').length;
  const investigating = allAlerts.filter(a => a.status === 'Investigating').length;
  const resolved = allAlerts.filter(a => a.status === 'Resolved').length;
  const falsePositive = allAlerts.filter(a => a.status === 'False Positive').length;

  const attackDistribution = {};
  ATTACK_TYPES.forEach(type => {
    const count = allAlerts.filter(a => a.attackType === type).length;
    if (count > 0) attackDistribution[type] = count;
  });

  const sourceDistribution = {};
  SOURCES.forEach(src => {
    const count = allAlerts.filter(a => a.source.name === src.name).length;
    if (count > 0) sourceDistribution[src.name] = count;
  });

  // Timeline data (last 24 hours, grouped by hour)
  const timeline = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const hourStart = new Date(now.getTime() - i * 3600000);
    const hourEnd = new Date(hourStart.getTime() + 3600000);
    const hourAlerts = allAlerts.filter(a => a.timestamp >= hourStart && a.timestamp < hourEnd);
    timeline.push({
      hour: hourStart.getHours(),
      total: hourAlerts.length,
      critical: hourAlerts.filter(a => a.severity === 'critical').length,
      high: hourAlerts.filter(a => a.severity === 'high').length,
      medium: hourAlerts.filter(a => a.severity === 'medium').length,
      low: hourAlerts.filter(a => a.severity === 'low').length
    });
  }

  const avgConfidence = allAlerts.reduce((sum, a) => sum + a.analysis.confidence, 0) / total;
  const mttr = Math.floor(Math.random() * 30) + 5; // Mean Time To Respond (minutes)

  return {
    total, critical, high, medium, low,
    open, investigating, resolved, falsePositive,
    attackDistribution, sourceDistribution, timeline,
    avgConfidence: Math.round(avgConfidence),
    mttr,
    threatScore: Math.min(100, Math.round((critical * 4 + high * 3 + medium * 2 + low) / total * 25))
  };
}

// ============================================================
// AI Chat Engine
// ============================================================

const AI_RESPONSES = {
  greetings: [
    "Hello! I'm your AI SOC Assistant. I can help you analyze security alerts, investigate threats, and recommend remediation actions. What would you like to know?",
    "Welcome to AI SOC. I'm here to help you navigate your security landscape. Ask me about alerts, threats, or security best practices."
  ],
  threats: [
    () => {
      const metrics = getMetrics();
      return `📊 **Current Threat Landscape:**\n\n` +
        `• **Total Alerts:** ${metrics.total}\n` +
        `• **Critical:** ${metrics.critical} | **High:** ${metrics.high} | **Medium:** ${metrics.medium} | **Low:** ${metrics.low}\n` +
        `• **Open Alerts:** ${metrics.open}\n` +
        `• **Threat Score:** ${metrics.threatScore}/100\n` +
        `• **AI Confidence:** ${metrics.avgConfidence}%\n\n` +
        `The most prevalent attack type is **${Object.entries(metrics.attackDistribution).sort((a,b) => b[1]-a[1])[0]?.[0] || 'N/A'}**. ` +
        `I recommend prioritizing the ${metrics.critical} critical alerts for immediate investigation.`;
    }
  ],
  critical: [
    () => {
      const critAlerts = allAlerts.filter(a => a.severity === 'critical').slice(0, 5);
      if (critAlerts.length === 0) return "✅ No critical alerts at this time. Your security posture looks strong!";
      let response = `🚨 **Critical Alerts (Top ${critAlerts.length}):**\n\n`;
      critAlerts.forEach(a => {
        response += `• **${a.id}** - ${a.attackType} from ${a.srcIP} → ${a.target}\n  Status: ${a.status} | Confidence: ${a.analysis.confidence}%\n\n`;
      });
      response += `\nI recommend immediate investigation of these alerts. Would you like me to analyze any specific alert in detail?`;
      return response;
    }
  ],
  investigate: [
    () => {
      const recentAlert = allAlerts.find(a => a.severity === 'critical' || a.severity === 'high') || allAlerts[0];
      return `🔍 **Investigation Report - ${recentAlert.id}:**\n\n` +
        `**Attack Type:** ${recentAlert.attackType}\n` +
        `**Severity:** ${recentAlert.severity.toUpperCase()}\n` +
        `**Source IP:** ${recentAlert.srcIP}\n` +
        `**Target:** ${recentAlert.target}\n` +
        `**MITRE ATT&CK:** ${recentAlert.analysis.mitre}\n` +
        `**Kill Chain Phase:** ${recentAlert.analysis.killChain}\n\n` +
        `**AI Analysis:**\n${recentAlert.analysis.details}\n\n` +
        `**Recommended Actions:**\n${recentAlert.remediation.map((r, i) => `${i+1}. ${r}`).join('\n')}\n\n` +
        `AI Confidence: **${recentAlert.analysis.confidence}%**`;
    }
  ],
  remediation: [
    "🛡️ **General Remediation Framework:**\n\n" +
    "1. **Contain** - Isolate affected systems to prevent lateral movement\n" +
    "2. **Eradicate** - Remove the threat from all affected systems\n" +
    "3. **Recover** - Restore systems to normal operation from clean backups\n" +
    "4. **Lessons Learned** - Document the incident and update security controls\n\n" +
    "For specific remediation steps, ask me about a particular alert or attack type."
  ],
  help: [
    "🤖 **I can help you with:**\n\n" +
    "• `threat summary` - Get current threat landscape overview\n" +
    "• `critical alerts` - View critical severity alerts\n" +
    "• `investigate` - Get AI investigation of recent threats\n" +
    "• `remediation` - Get remediation recommendations\n" +
    "• `attack types` - Learn about different attack categories\n" +
    "• `best practices` - Security best practices\n" +
    "• `MITRE ATT&CK` - MITRE framework information\n" +
    "• Ask about any specific alert ID (e.g., ALT-10001)\n\n" +
    "Just type your question naturally - I understand security context!"
  ],
  mitre: [
    "📋 **MITRE ATT&CK Framework Overview:**\n\n" +
    "The MITRE ATT&CK framework categorizes adversary tactics and techniques:\n\n" +
    "• **Reconnaissance** - Gathering information for planning attacks\n" +
    "• **Initial Access** - Getting into the network (phishing, exploits)\n" +
    "• **Execution** - Running malicious code\n" +
    "• **Persistence** - Maintaining access across restarts\n" +
    "• **Privilege Escalation** - Gaining higher-level permissions\n" +
    "• **Defense Evasion** - Avoiding detection\n" +
    "• **Lateral Movement** - Moving through the network\n" +
    "• **Collection** - Gathering target data\n" +
    "• **Exfiltration** - Stealing data\n" +
    "• **Impact** - Disrupting systems (ransomware, DDoS)\n\n" +
    "Our AI engine maps all detected threats to MITRE ATT&CK for standardized classification."
  ],
  bestPractices: [
    "🏆 **Security Best Practices:**\n\n" +
    "1. **Zero Trust Architecture** - Never trust, always verify\n" +
    "2. **Multi-Factor Authentication** - Enforce MFA on all accounts\n" +
    "3. **Patch Management** - Apply security patches within 24-72 hours\n" +
    "4. **Network Segmentation** - Limit lateral movement\n" +
    "5. **Least Privilege** - Minimum necessary access rights\n" +
    "6. **Security Awareness Training** - Regular employee education\n" +
    "7. **Incident Response Plan** - Test and update regularly\n" +
    "8. **Backup Strategy** - 3-2-1 backup rule\n" +
    "9. **Log Monitoring** - Centralized logging with AI analysis\n" +
    "10. **Threat Intelligence** - Stay informed about emerging threats"
  ],
  default: [
    "I understand you're asking about security. Let me analyze that for you. Could you provide more context? You can ask about:\n\n• Current threats and alerts\n• Specific attack investigation\n• Remediation recommendations\n• Security best practices\n\nType `help` for a full list of commands.",
    "That's an excellent security question. Based on our current alert data and AI analysis, I'd recommend reviewing the dashboard for the latest insights. Can you be more specific about what you'd like to investigate?",
    "I'm processing your request through our AI threat intelligence engine. For the most detailed analysis, try asking about specific alerts, attack types, or use keywords like 'investigate', 'remediation', or 'critical alerts'."
  ]
};

function processAIQuery(query) {
  const q = query.toLowerCase().trim();

  // Check for alert ID
  const alertIdMatch = q.match(/alt-(\d+)/i);
  if (alertIdMatch) {
    const alert = allAlerts.find(a => a.id.toLowerCase() === `alt-${alertIdMatch[1]}`);
    if (alert) {
      return `🔍 **Alert Details - ${alert.id}:**\n\n` +
        `**Type:** ${alert.attackType}\n` +
        `**Severity:** ${alert.severity.toUpperCase()}\n` +
        `**Source:** ${alert.source.icon} ${alert.source.name}\n` +
        `**Source IP:** ${alert.srcIP}\n` +
        `**Target:** ${alert.target}\n` +
        `**Status:** ${alert.status}\n` +
        `**Events:** ${alert.eventCount}\n` +
        `**Timestamp:** ${alert.timestamp.toLocaleString()}\n\n` +
        `**AI Analysis:**\n${alert.analysis.summary}\n\n${alert.analysis.details}\n\n` +
        `**MITRE ATT&CK:** ${alert.analysis.mitre}\n` +
        `**Kill Chain:** ${alert.analysis.killChain}\n` +
        `**Confidence:** ${alert.analysis.confidence}%\n\n` +
        `**Remediation Steps:**\n${alert.remediation.map((r, i) => `${i+1}. ${r}`).join('\n')}`;
    }
    return `Alert ${alertIdMatch[0]} not found. Please check the alert ID and try again.`;
  }

  if (/hello|hi|hey|greet/i.test(q)) return getRandomElement(AI_RESPONSES.greetings);
  if (/threat|summary|overview|landscape|status/i.test(q)) return AI_RESPONSES.threats[0]();
  if (/critical|urgent|severe|emergency/i.test(q)) return AI_RESPONSES.critical[0]();
  if (/investigate|analyze|examine|inspect|detail/i.test(q)) return AI_RESPONSES.investigate[0]();
  if (/remediat|fix|resolve|mitigat|respond|action/i.test(q)) return getRandomElement(AI_RESPONSES.remediation);
  if (/help|command|what can|how to/i.test(q)) return getRandomElement(AI_RESPONSES.help);
  if (/mitre|att&ck|attack framework/i.test(q)) return getRandomElement(AI_RESPONSES.mitre);
  if (/best practice|recommend|tip|advice|harden/i.test(q)) return getRandomElement(AI_RESPONSES.bestPractices);

  // Attack type specific
  for (const type of ATTACK_TYPES) {
    if (q.includes(type.toLowerCase())) {
      const typeAlerts = allAlerts.filter(a => a.attackType === type);
      const remediation = REMEDIATION_ACTIONS[type];
      return `🎯 **${type} Analysis:**\n\n` +
        `**Active Alerts:** ${typeAlerts.length}\n` +
        `**Severity Breakdown:** Critical: ${typeAlerts.filter(a=>a.severity==='critical').length} | ` +
        `High: ${typeAlerts.filter(a=>a.severity==='high').length} | ` +
        `Medium: ${typeAlerts.filter(a=>a.severity==='medium').length} | ` +
        `Low: ${typeAlerts.filter(a=>a.severity==='low').length}\n\n` +
        `**Remediation Steps:**\n${remediation ? remediation.map((r, i) => `${i+1}. ${r}`).join('\n') : 'Standard investigation recommended.'}\n\n` +
        `Would you like me to investigate a specific ${type} alert?`;
    }
  }

  return getRandomElement(AI_RESPONSES.default);
}

// Export for use in app.js
window.SOCData = {
  generateInitialAlerts,
  generateNewAlert,
  getMetrics,
  processAIQuery,
  allAlerts: () => allAlerts,
  SEVERITY_CONFIG,
  ATTACK_TYPES,
  SOURCES,
  STATUS_OPTIONS
};
