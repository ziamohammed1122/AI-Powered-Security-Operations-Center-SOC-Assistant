// ============================================================
// AI SOC Assistant – Real-Time Vulnerability Feeds
// NVD (National Vulnerability Database) + CISA KEV
// ============================================================

class RealTimeFeed {
  constructor() {
    this.nvdBaseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    this.cisaKevUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    // CORS proxy chain — tries each in order until one works
    this.corsProxies = [
      url => url,                                                         // Direct (works if server has CORS headers)
      url => `https://corsproxy.io/?${encodeURIComponent(url)}`,          // corsproxy.io
      url => `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`, // allorigins
      url => `https://corsproxy.org/?${encodeURIComponent(url)}`,         // corsproxy.org
    ];
    this._workingProxyIndex = null; // cache the first proxy that worked

    // Cached data
    this.nvdVulnerabilities = [];
    this.cisaKevEntries = [];
    this.lastNvdFetch = null;
    this.lastCisaFetch = null;
    this.isFetchingNvd = false;
    this.isFetchingCisa = false;
    this.nvdError = null;
    this.cisaError = null;

    // Rate limiting for NVD (5 requests per 30s without API key)
    this.nvdRequestTimes = [];
  }

  // ── CORS-Aware Fetch (tries direct, then proxies) ────────
  async _corsFetch(url, options = {}) {
    // If we already found a working proxy, try it first
    const startIdx = this._workingProxyIndex != null ? this._workingProxyIndex : 0;
    const order = [
      ...this.corsProxies.slice(startIdx),
      ...this.corsProxies.slice(0, startIdx)
    ];

    for (let i = 0; i < order.length; i++) {
      const proxyFn = order[i];
      const proxiedUrl = proxyFn(url);
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);

        const response = await fetch(proxiedUrl, {
          signal: controller.signal,
          headers: options.headers || {}
        });
        clearTimeout(timeoutId);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        // Cache the working proxy index for future requests
        const actualIdx = this.corsProxies.indexOf(proxyFn);
        if (actualIdx >= 0) this._workingProxyIndex = actualIdx;

        console.log(`[CORS] ✅ Success via ${actualIdx === 0 ? 'direct' : `proxy #${actualIdx}`}`);
        return response;
      } catch (err) {
        const actualIdx = this.corsProxies.indexOf(proxyFn);
        console.warn(`[CORS] ❌ ${actualIdx === 0 ? 'Direct' : `Proxy #${actualIdx}`} failed for ${url.substring(0,60)}…: ${err.message}`);
        continue;
      }
    }
    throw new Error(`All fetch methods failed for ${url}`);
  }

  // ── NVD API ──────────────────────────────────────────────
  async fetchNVD(options = {}) {
    if (this.isFetchingNvd) return this.nvdVulnerabilities;

    // Rate limit check
    const now = Date.now();
    this.nvdRequestTimes = this.nvdRequestTimes.filter(t => now - t < 30000);
    if (this.nvdRequestTimes.length >= 4) {
      console.warn('[NVD] Rate limit approaching, skipping request');
      return this.nvdVulnerabilities;
    }

    this.isFetchingNvd = true;
    this.nvdError = null;

    try {
      const params = new URLSearchParams();
      params.set('resultsPerPage', options.resultsPerPage || '20');

      // Default: fetch CVEs from the last 7 days
      if (!options.keyword) {
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - (options.days || 7));
        params.set('pubStartDate', startDate.toISOString().split('.')[0] + '.000');
        params.set('pubEndDate', endDate.toISOString().split('.')[0] + '.000');
      }

      if (options.keyword) {
        params.set('keywordSearch', options.keyword);
      }
      if (options.severity) {
        params.set('cvssV3Severity', options.severity.toUpperCase());
      }
      if (options.startIndex) {
        params.set('startIndex', options.startIndex);
      }

      const url = `${this.nvdBaseUrl}?${params.toString()}`;
      console.log('[NVD] Fetching:', url);

      this.nvdRequestTimes.push(Date.now());
      const response = await this._corsFetch(url, { timeout: 20000 });

      const data = await response.json();
      const parsed = this._parseNVDResponse(data);

      this.nvdVulnerabilities = parsed;
      this.lastNvdFetch = new Date();

      console.log(`[NVD] Fetched ${parsed.length} of ${data.totalResults} total CVEs`);
      return parsed;

    } catch (error) {
      console.error('[NVD] Fetch error:', error.message);
      this.nvdError = error.message;
      return this.nvdVulnerabilities; // Return cached data
    } finally {
      this.isFetchingNvd = false;
    }
  }

  _parseNVDResponse(data) {
    if (!data.vulnerabilities) return [];

    return data.vulnerabilities.map(item => {
      const cve = item.cve;
      const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';

      // Extract CVSS score (prefer v3.1, fallback to v4.0, then v2.0)
      let cvssScore = null;
      let severity = 'low';
      let cvssVector = '';

      if (cve.metrics?.cvssMetricV31?.length > 0) {
        const metric = cve.metrics.cvssMetricV31[0];
        cvssScore = metric.cvssData.baseScore;
        severity = metric.cvssData.baseSeverity?.toLowerCase() || 'low';
        cvssVector = metric.cvssData.vectorString;
      } else if (cve.metrics?.cvssMetricV40?.length > 0) {
        const metric = cve.metrics.cvssMetricV40[0];
        cvssScore = metric.cvssData.baseScore;
        severity = metric.cvssData.baseSeverity?.toLowerCase() || 'low';
        cvssVector = metric.cvssData.vectorString;
      } else if (cve.metrics?.cvssMetricV2?.length > 0) {
        const metric = cve.metrics.cvssMetricV2[0];
        cvssScore = metric.cvssData.baseScore;
        severity = metric.baseSeverity?.toLowerCase() || 'low';
        cvssVector = metric.cvssData.vectorString;
      }

      // Map NVD severity to our severity levels
      const severityMap = { 'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low' };
      severity = severityMap[severity] || 'low';

      // Extract CWE
      const cwes = [];
      cve.weaknesses?.forEach(w => {
        w.description?.forEach(d => {
          if (d.value && d.value !== 'NVD-CWE-noinfo' && d.value !== 'NVD-CWE-Other') {
            cwes.push(d.value);
          }
        });
      });

      // Extract references
      const references = (cve.references || []).map(ref => ({
        url: ref.url,
        tags: ref.tags || []
      })).slice(0, 5);

      // Extract affected products from configurations
      const affectedProducts = [];
      cve.configurations?.forEach(config => {
        config.nodes?.forEach(node => {
          node.cpeMatch?.forEach(cpe => {
            if (cpe.vulnerable) {
              const parts = cpe.criteria.split(':');
              if (parts.length >= 5) {
                const vendor = parts[3]?.replace(/_/g, ' ') || '';
                const product = parts[4]?.replace(/_/g, ' ') || '';
                const version = parts[5] !== '*' ? parts[5] : '';
                affectedProducts.push(`${vendor} ${product} ${version}`.trim());
              }
            }
          });
        });
      });

      return {
        id: cve.id,
        source: 'NVD',
        sourceIcon: '🏛️',
        description: desc,
        severity,
        cvssScore,
        cvssVector,
        cwes,
        published: new Date(cve.published),
        lastModified: new Date(cve.lastModified),
        status: cve.vulnStatus || 'Analyzed',
        references,
        affectedProducts: [...new Set(affectedProducts)].slice(0, 5),
        // Map to SOC alert format
        attackType: this._cweToAttackType(cwes),
        isRealtime: true
      };
    });
  }

  // ── CISA KEV ─────────────────────────────────────────────
  async fetchCISA(options = {}) {
    if (this.isFetchingCisa) return this.cisaKevEntries;

    this.isFetchingCisa = true;
    this.cisaError = null;

    try {
      console.log('[CISA] Fetching Known Exploited Vulnerabilities catalog...');

      const response = await this._corsFetch(this.cisaKevUrl, { timeout: 30000 });

      const data = await response.json();
      const limit = options.limit || 30;

      // Sort by dateAdded descending (most recent first) and take the limit
      const sorted = (data.vulnerabilities || [])
        .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
        .slice(0, limit);

      this.cisaKevEntries = sorted.map(vuln => this._parseCISAEntry(vuln));
      this.lastCisaFetch = new Date();

      console.log(`[CISA] Fetched ${this.cisaKevEntries.length} most recent KEV entries (total catalog: ${data.count})`);
      return this.cisaKevEntries;

    } catch (error) {
      console.error('[CISA] Fetch error:', error.message);
      this.cisaError = error.message;
      return this.cisaKevEntries;
    } finally {
      this.isFetchingCisa = false;
    }
  }

  _parseCISAEntry(vuln) {
    // Determine severity based on ransomware use and description keywords
    let severity = 'high'; // CISA KEV entries are inherently high-priority
    if (vuln.knownRansomwareCampaignUse === 'Known') {
      severity = 'critical';
    }
    const desc = (vuln.shortDescription || '').toLowerCase();
    if (desc.includes('remote code execution') || desc.includes('arbitrary code')) {
      severity = 'critical';
    }

    return {
      id: vuln.cveID,
      source: 'CISA KEV',
      sourceIcon: '🇺🇸',
      vendor: vuln.vendorProject,
      product: vuln.product,
      vulnerabilityName: vuln.vulnerabilityName,
      description: vuln.shortDescription,
      severity,
      requiredAction: vuln.requiredAction,
      dateAdded: new Date(vuln.dateAdded),
      dueDate: vuln.dueDate ? new Date(vuln.dueDate) : null,
      ransomwareUse: vuln.knownRansomwareCampaignUse,
      cwes: vuln.cwes || [],
      notes: vuln.notes || '',
      attackType: this._cweToAttackType(vuln.cwes || []),
      isRealtime: true,
      isKEV: true
    };
  }

  // ── CWE to Attack Type Mapping ──────────────────────────
  _cweToAttackType(cwes) {
    const cweMap = {
      'CWE-89': 'SQL Injection',
      'CWE-79': 'XSS Attack',
      'CWE-78': 'Command Injection',
      'CWE-77': 'Command Injection',
      'CWE-94': 'Code Injection',
      'CWE-119': 'Buffer Overflow',
      'CWE-120': 'Buffer Overflow',
      'CWE-121': 'Buffer Overflow',
      'CWE-122': 'Buffer Overflow',
      'CWE-125': 'Out-of-Bounds Read',
      'CWE-787': 'Out-of-Bounds Write',
      'CWE-416': 'Use-After-Free',
      'CWE-190': 'Integer Overflow',
      'CWE-287': 'Authentication Bypass',
      'CWE-306': 'Authentication Bypass',
      'CWE-522': 'Credential Exposure',
      'CWE-798': 'Credential Exposure',
      'CWE-200': 'Information Disclosure',
      'CWE-22': 'Path Traversal',
      'CWE-23': 'Path Traversal',
      'CWE-352': 'CSRF Attack',
      'CWE-434': 'Unrestricted File Upload',
      'CWE-502': 'Deserialization Attack',
      'CWE-611': 'XXE Injection',
      'CWE-918': 'SSRF Attack',
      'CWE-269': 'Privilege Escalation',
      'CWE-862': 'Missing Authorization',
      'CWE-863': 'Incorrect Authorization',
      'CWE-476': 'Null Pointer Dereference',
      'CWE-400': 'Denial of Service',
      'CWE-770': 'Denial of Service'
    };

    for (const cwe of cwes) {
      if (cweMap[cwe]) return cweMap[cwe];
    }
    return 'Security Vulnerability';
  }

  // ── Convert to SOC Alert Format ──────────────────────────
  convertToAlerts(vulns) {
    return vulns.map(vuln => {
      const isKEV = vuln.isKEV;
      return {
        id: vuln.id,
        timestamp: vuln.published || vuln.dateAdded || new Date(),
        attackType: vuln.attackType || 'Security Vulnerability',
        severity: vuln.severity,
        source: {
          name: vuln.source,
          icon: vuln.sourceIcon
        },
        srcIP: 'N/A (CVE)',
        target: isKEV
          ? `${vuln.vendor || ''} ${vuln.product || ''}`.trim()
          : (vuln.affectedProducts?.[0] || 'Multiple Products'),
        status: isKEV ? 'Action Required' : 'Open',
        eventCount: 1,
        duration: 0,
        analysis: {
          summary: isKEV
            ? `${vuln.vulnerabilityName || vuln.id} — Known Exploited Vulnerability`
            : `${vuln.id} — ${vuln.attackType}`,
          details: vuln.description || 'No details available.',
          confidence: vuln.cvssScore ? Math.min(99, Math.round(vuln.cvssScore * 10)) : 85,
          mitre: vuln.cwes?.length > 0 ? vuln.cwes.join(', ') : 'N/A',
          killChain: vuln.severity === 'critical' ? 'Exploitation' : 'Reconnaissance',
          cvssScore: vuln.cvssScore,
          cvssVector: vuln.cvssVector
        },
        remediation: isKEV
          ? [
              vuln.requiredAction || 'Apply vendor patches immediately.',
              `Due date for remediation: ${vuln.dueDate ? vuln.dueDate.toLocaleDateString() : 'ASAP'}`,
              `Ransomware campaign use: ${vuln.ransomwareUse || 'Unknown'}`,
              'Review CISA BOD 22-01 for compliance requirements.',
              `Refer to: ${vuln.notes || 'CISA KEV catalog'}`
            ]
          : [
              'Review the CVE details and assess if your systems are affected.',
              `Check if you use any of the affected products: ${vuln.affectedProducts?.join(', ') || 'See NVD for details'}`,
              'Apply vendor-recommended patches or workarounds.',
              'Monitor for exploitation attempts in your environment.',
              `Reference: https://nvd.nist.gov/vuln/detail/${vuln.id}`
            ],
        isNew: false,
        isRealtime: true,
        isKEV: isKEV || false,
        references: vuln.references || [],
        cvssScore: vuln.cvssScore
      };
    });
  }

  // ── Fetch All Sources ────────────────────────────────────
  async fetchAll(options = {}) {
    const results = { nvd: [], cisa: [], errors: [] };

    try {
      const [nvdData, cisaData] = await Promise.allSettled([
        this.fetchNVD(options.nvd || {}),
        this.fetchCISA(options.cisa || {})
      ]);

      if (nvdData.status === 'fulfilled') {
        results.nvd = nvdData.value;
      } else {
        results.errors.push(`NVD: ${nvdData.reason}`);
      }

      if (cisaData.status === 'fulfilled') {
        results.cisa = cisaData.value;
      } else {
        results.errors.push(`CISA: ${cisaData.reason}`);
      }
    } catch (error) {
      results.errors.push(error.message);
    }

    return results;
  }

  // ── CWE-Based Remediation Playbooks ──────────────────────
  static REMEDIATION_PLAYBOOKS = {
    'CWE-89': {
      title: 'SQL Injection Remediation',
      icon: '💉',
      risk: 'Attackers can read, modify, or delete database contents, bypass authentication, and potentially execute OS commands.',
      steps: [
        { action: 'Use parameterized queries / prepared statements for ALL database interactions', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Deploy a Web Application Firewall (WAF) with SQL injection rules as a temporary shield', urgency: 'immediate', category: 'Mitigation' },
        { action: 'Validate and sanitize all user inputs using allowlists (not blocklists)', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Apply least-privilege database permissions — app accounts should never be db admin', urgency: 'short-term', category: 'Configuration' },
        { action: 'Enable database query logging and monitor for anomalous patterns', urgency: 'short-term', category: 'Monitoring' },
        { action: 'Run a full SQL injection scan using tools like SQLMap or Burp Suite', urgency: 'short-term', category: 'Testing' },
        { action: 'Implement an ORM layer to abstract raw SQL queries', urgency: 'long-term', category: 'Architecture' },
        { action: 'Set up automated SAST/DAST scans in CI/CD pipeline', urgency: 'long-term', category: 'Process' }
      ],
      verification: ['Run SQL injection tests against all endpoints', 'Verify parameterized queries in code review', 'Check WAF logs for blocked attempts'],
      references: ['OWASP SQL Injection Prevention Cheat Sheet', 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command']
    },
    'CWE-79': {
      title: 'Cross-Site Scripting (XSS) Remediation',
      icon: '🔤',
      risk: 'Attackers can execute malicious scripts in user browsers, steal session tokens, deface websites, and redirect users.',
      steps: [
        { action: 'Implement context-aware output encoding for all dynamic content', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Deploy Content Security Policy (CSP) headers to restrict script sources', urgency: 'immediate', category: 'Configuration' },
        { action: 'Sanitize HTML input using proven libraries (DOMPurify, Bleach)', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Set HttpOnly and Secure flags on all session cookies', urgency: 'short-term', category: 'Configuration' },
        { action: 'Enable X-XSS-Protection and X-Content-Type-Options headers', urgency: 'short-term', category: 'Configuration' },
        { action: 'Review all template rendering for raw/unescaped output', urgency: 'short-term', category: 'Code Review' },
        { action: 'Adopt a modern frontend framework with auto-escaping (React, Vue, Angular)', urgency: 'long-term', category: 'Architecture' },
        { action: 'Implement automated XSS scanning in CI/CD', urgency: 'long-term', category: 'Process' }
      ],
      verification: ['Test with XSS payloads on all input fields', 'Verify CSP headers are active', 'Check cookies for security flags'],
      references: ['OWASP XSS Prevention Cheat Sheet', 'CWE-79: Improper Neutralization of Input During Web Page Generation']
    },
    'CWE-119': {
      title: 'Buffer Overflow Remediation',
      icon: '📦',
      risk: 'Attackers can execute arbitrary code, crash applications, or gain control of the system by overwriting memory.',
      steps: [
        { action: 'Apply vendor patches immediately — buffer overflows are often remotely exploitable', urgency: 'immediate', category: 'Patching' },
        { action: 'Enable ASLR (Address Space Layout Randomization) on all systems', urgency: 'immediate', category: 'Configuration' },
        { action: 'Enable DEP/NX (Data Execution Prevention) on all systems', urgency: 'immediate', category: 'Configuration' },
        { action: 'Isolate affected systems behind network segmentation until patched', urgency: 'immediate', category: 'Mitigation' },
        { action: 'Replace unsafe C/C++ functions (strcpy, sprintf) with safe alternatives (strncpy, snprintf)', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Compile with stack protection flags (-fstack-protector-strong)', urgency: 'short-term', category: 'Build' },
        { action: 'Run static analysis for memory safety issues (Coverity, cppcheck)', urgency: 'short-term', category: 'Testing' },
        { action: 'Consider memory-safe language alternatives (Rust, Go) for critical components', urgency: 'long-term', category: 'Architecture' }
      ],
      verification: ['Confirm patches are applied', 'Verify ASLR/DEP are enabled', 'Run fuzzing tests on affected components'],
      references: ['CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer', 'CERT C Secure Coding Standard']
    },
    'CWE-120': {
      title: 'Buffer Overflow (Classic) Remediation',
      icon: '📦',
      risk: 'Classic buffer overflow can lead to arbitrary code execution. This is a high-priority vulnerability.',
      steps: [
        { action: 'Apply vendor patches immediately', urgency: 'immediate', category: 'Patching' },
        { action: 'Enable ASLR and DEP/NX on the system', urgency: 'immediate', category: 'Configuration' },
        { action: 'Isolate the affected service behind a firewall until patched', urgency: 'immediate', category: 'Mitigation' },
        { action: 'Replace unsafe buffer operations with bounds-checked alternatives', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Compile with stack canaries and fortified source flags', urgency: 'short-term', category: 'Build' },
        { action: 'Perform fuzz testing on input handling code paths', urgency: 'short-term', category: 'Testing' }
      ],
      verification: ['Confirm all patches installed', 'Test with oversized inputs', 'Verify memory protections enabled'],
      references: ['CWE-120: Buffer Copy without Checking Size of Input']
    },
    'CWE-287': {
      title: 'Authentication Bypass Remediation',
      icon: '🔓',
      risk: 'Attackers can access systems without valid credentials, gaining unauthorized access to sensitive data and functionality.',
      steps: [
        { action: 'Apply vendor security patches immediately', urgency: 'immediate', category: 'Patching' },
        { action: 'Enforce multi-factor authentication (MFA) on all accounts', urgency: 'immediate', category: 'Configuration' },
        { action: 'Audit all authentication endpoints for bypass paths', urgency: 'immediate', category: 'Code Review' },
        { action: 'Implement rate limiting on login and authentication endpoints', urgency: 'short-term', category: 'Configuration' },
        { action: 'Use proven authentication frameworks (OAuth 2.0, SAML, OpenID Connect)', urgency: 'short-term', category: 'Architecture' },
        { action: 'Log and alert on all authentication failures and anomalies', urgency: 'short-term', category: 'Monitoring' },
        { action: 'Implement session management best practices (secure tokens, expiry)', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Conduct a full authentication architecture review', urgency: 'long-term', category: 'Architecture' }
      ],
      verification: ['Attempt authentication bypass test cases', 'Verify MFA enforcement', 'Check audit logs for unauthorized access'],
      references: ['OWASP Authentication Cheat Sheet', 'CWE-287: Improper Authentication']
    },
    'CWE-416': {
      title: 'Use-After-Free Remediation',
      icon: '🧹',
      risk: 'Can lead to arbitrary code execution, data corruption, or system crashes. Commonly exploited in browser and OS attacks.',
      steps: [
        { action: 'Apply vendor patches immediately — UAF is a critical exploitation vector', urgency: 'immediate', category: 'Patching' },
        { action: 'Restrict network access to affected services', urgency: 'immediate', category: 'Mitigation' },
        { action: 'Enable exploit mitigations (CFI, ASLR, sandbox)', urgency: 'immediate', category: 'Configuration' },
        { action: 'Set freed pointers to NULL immediately after deallocation', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Use smart pointers and RAII patterns in C++', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Run memory safety tools (AddressSanitizer, Valgrind)', urgency: 'short-term', category: 'Testing' },
        { action: 'Consider migrating critical code to memory-safe languages', urgency: 'long-term', category: 'Architecture' }
      ],
      verification: ['Confirm patches applied', 'Run ASan/Valgrind checks', 'Test with memory-corruption fuzzers'],
      references: ['CWE-416: Use After Free', 'Google Project Zero advisories']
    },
    'CWE-502': {
      title: 'Deserialization Attack Remediation',
      icon: '📋',
      risk: 'Insecure deserialization can lead to remote code execution, privilege escalation, and denial of service.',
      steps: [
        { action: 'Apply available vendor patches or upgrade to fixed versions', urgency: 'immediate', category: 'Patching' },
        { action: 'Do NOT deserialize data from untrusted sources', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Implement integrity checks (HMAC signatures) on serialized data', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Use safe serialization formats (JSON) instead of native serialization (Java ObjectInputStream, PHP unserialize, Python pickle)', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Implement deserialization allowlists to restrict class instantiation', urgency: 'short-term', category: 'Configuration' },
        { action: 'Run deserialization-specific security scanners (ysoserial, marshalsec)', urgency: 'short-term', category: 'Testing' },
        { action: 'Monitor for deserialization anomalies in application logs', urgency: 'short-term', category: 'Monitoring' }
      ],
      verification: ['Test with known deserialization payloads', 'Verify no native deserialization of user input', 'Check integrity verification is active'],
      references: ['OWASP Deserialization Cheat Sheet', 'CWE-502: Deserialization of Untrusted Data']
    },
    'CWE-22': {
      title: 'Path Traversal Remediation',
      icon: '📂',
      risk: 'Attackers can read arbitrary files from the server, potentially accessing passwords, configuration files, and source code.',
      steps: [
        { action: 'Apply vendor patches to affected software', urgency: 'immediate', category: 'Patching' },
        { action: 'Validate and sanitize all file path inputs — reject paths with "../" sequences', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Use a chroot jail or sandbox to restrict file system access', urgency: 'short-term', category: 'Configuration' },
        { action: 'Implement an allowlist of permitted file paths', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Run the application with minimum required file system permissions', urgency: 'short-term', category: 'Configuration' },
        { action: 'Enable file integrity monitoring on sensitive directories', urgency: 'short-term', category: 'Monitoring' }
      ],
      verification: ['Test with path traversal payloads', 'Verify file access restrictions', 'Review file serving code'],
      references: ['OWASP Path Traversal', 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory']
    },
    'CWE-200': {
      title: 'Information Disclosure Remediation',
      icon: '📢',
      risk: 'Sensitive information exposure can aid attackers in crafting targeted attacks and gaining unauthorized access.',
      steps: [
        { action: 'Remove sensitive data from error messages and HTTP responses', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Disable verbose error pages and stack traces in production', urgency: 'immediate', category: 'Configuration' },
        { action: 'Review and remove debugging endpoints and test accounts', urgency: 'short-term', category: 'Code Review' },
        { action: 'Implement proper access controls on all data endpoints', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Set security headers (X-Content-Type-Options, Cache-Control)', urgency: 'short-term', category: 'Configuration' },
        { action: 'Audit API responses for over-exposure of data fields', urgency: 'short-term', category: 'Code Review' }
      ],
      verification: ['Check error pages for sensitive data', 'Review API responses', 'Scan for exposed endpoints'],
      references: ['CWE-200: Exposure of Sensitive Information to an Unauthorized Actor']
    },
    'CWE-522': {
      title: 'Credential Exposure Remediation',
      icon: '🔑',
      risk: 'Insufficiently protected credentials can be intercepted or extracted, leading to full account compromise.',
      steps: [
        { action: 'Rotate all potentially exposed credentials immediately', urgency: 'immediate', category: 'Mitigation' },
        { action: 'Enforce encrypted credential storage using strong hashing (bcrypt, Argon2)', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Enforce TLS 1.2+ for all credential transmission', urgency: 'immediate', category: 'Configuration' },
        { action: 'Implement a secrets management solution (HashiCorp Vault, AWS Secrets Manager)', urgency: 'short-term', category: 'Architecture' },
        { action: 'Remove hardcoded credentials from source code and configuration files', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Enable breached credential detection for user passwords', urgency: 'short-term', category: 'Monitoring' },
        { action: 'Enforce MFA for all accounts, especially privileged ones', urgency: 'short-term', category: 'Configuration' }
      ],
      verification: ['Scan codebase for hardcoded secrets', 'Verify credential hashing algorithms', 'Check TLS configuration'],
      references: ['CWE-522: Insufficiently Protected Credentials', 'OWASP Credential Storage Cheat Sheet']
    },
    'CWE-434': {
      title: 'Unrestricted File Upload Remediation',
      icon: '📤',
      risk: 'Attackers can upload malicious files (web shells, malware) to gain remote code execution on the server.',
      steps: [
        { action: 'Restrict allowed file types using an allowlist (not blocklist)', urgency: 'immediate', category: 'Code Fix' },
        { action: 'Store uploaded files outside the web root directory', urgency: 'immediate', category: 'Configuration' },
        { action: 'Validate file content (magic bytes), not just the extension', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Rename uploaded files to random names to prevent direct execution', urgency: 'short-term', category: 'Code Fix' },
        { action: 'Set maximum file size limits', urgency: 'short-term', category: 'Configuration' },
        { action: 'Scan uploaded files with antivirus before processing', urgency: 'short-term', category: 'Security' },
        { action: 'Serve uploaded files from a separate domain/CDN', urgency: 'long-term', category: 'Architecture' }
      ],
      verification: ['Attempt uploading various malicious file types', 'Verify files stored outside web root', 'Check file content validation'],
      references: ['CWE-434: Unrestricted Upload of File with Dangerous Type', 'OWASP File Upload Cheat Sheet']
    }
  };

  // Default playbook for unrecognized CWEs
  static DEFAULT_PLAYBOOK = {
    title: 'General Vulnerability Remediation',
    icon: '🛡️',
    risk: 'This vulnerability may allow attackers to compromise system security. Follow the general remediation steps below.',
    steps: [
      { action: 'Apply all available vendor patches and security updates', urgency: 'immediate', category: 'Patching' },
      { action: 'Assess whether your systems are running affected software versions', urgency: 'immediate', category: 'Assessment' },
      { action: 'Restrict network access to affected services until patched', urgency: 'immediate', category: 'Mitigation' },
      { action: 'Enable enhanced logging and monitoring on affected components', urgency: 'short-term', category: 'Monitoring' },
      { action: 'Review vendor advisories for specific workarounds', urgency: 'short-term', category: 'Research' },
      { action: 'Conduct a vulnerability scan to identify all affected assets', urgency: 'short-term', category: 'Testing' },
      { action: 'Update incident response plan to include this vulnerability type', urgency: 'long-term', category: 'Process' }
    ],
    verification: ['Confirm patches are installed', 'Verify services are not exposed unnecessarily', 'Run vulnerability scan to validate fix'],
    references: ['NVD Vulnerability Database', 'CISA Cybersecurity Advisories']
  };

  getRemediationPlaybook(cwes) {
    if (!cwes || cwes.length === 0) return RealTimeFeed.DEFAULT_PLAYBOOK;
    for (const cwe of cwes) {
      if (RealTimeFeed.REMEDIATION_PLAYBOOKS[cwe]) {
        return RealTimeFeed.REMEDIATION_PLAYBOOKS[cwe];
      }
    }
    // Try base CWE (e.g., CWE-121 → CWE-119)
    const bufferCWEs = ['CWE-121', 'CWE-122', 'CWE-125', 'CWE-787'];
    if (cwes.some(c => bufferCWEs.includes(c))) return RealTimeFeed.REMEDIATION_PLAYBOOKS['CWE-119'];
    const authCWEs = ['CWE-306', 'CWE-798'];
    if (cwes.some(c => authCWEs.includes(c))) return RealTimeFeed.REMEDIATION_PLAYBOOKS['CWE-287'];
    return RealTimeFeed.DEFAULT_PLAYBOOK;
  }

  // ── Getters ──────────────────────────────────────────────
  getStatus() {
    return {
      nvd: {
        count: this.nvdVulnerabilities.length,
        lastFetch: this.lastNvdFetch,
        error: this.nvdError,
        isFetching: this.isFetchingNvd
      },
      cisa: {
        count: this.cisaKevEntries.length,
        lastFetch: this.lastCisaFetch,
        error: this.cisaError,
        isFetching: this.isFetchingCisa
      }
    };
  }
}

window.RealTimeFeed = RealTimeFeed;
