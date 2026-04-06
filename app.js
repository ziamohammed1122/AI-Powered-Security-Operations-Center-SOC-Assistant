// ============================================================
// AI SOC Assistant – Main Application Logic
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  // Initialize data
  SOCData.generateInitialAlerts(60);
  const charts = new SOCCharts();

  // State
  let currentView = 'dashboard';
  let alertFilter = 'all';
  let selectedAlert = null;
  let vulnFilter = 'all';
  let vulnSourceFilter = 'all';
  let allVulnerabilities = [];

  // Real-time feed
  const feed = new RealTimeFeed();
  let vulnsLoaded = false;

  // ── DOM References ───────────────────────────────────────
  const navItems = document.querySelectorAll('.nav-item[data-view]');
  const pageViews = document.querySelectorAll('.page-view');
  const alertDetailOverlay = document.getElementById('alertDetailOverlay');
  const searchInput = document.getElementById('headerSearch');
  const chatInput = document.getElementById('chatInput');
  const chatMessages = document.getElementById('chatMessages');
  const chatSendBtn = document.getElementById('chatSendBtn');
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const sidebar = document.querySelector('.sidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const clockEl = document.getElementById('headerClock');

  // ── Navigation ───────────────────────────────────────────
  function switchView(viewName) {
    currentView = viewName;
    navItems.forEach(item => item.classList.toggle('active', item.dataset.view === viewName));
    pageViews.forEach(page => page.classList.toggle('active', page.id === `view-${viewName}`));

    if (viewName === 'dashboard') renderDashboard();
    if (viewName === 'alerts') renderAlerts();
    if (viewName === 'investigate') {} // ready for user input
    if (viewName === 'threats') renderThreats();
    if (viewName === 'vulns') loadVulnerabilities();

    // Close mobile sidebar
    sidebar.classList.remove('open');
    sidebarOverlay.classList.remove('active');
  }

  navItems.forEach(item => {
    item.addEventListener('click', () => switchView(item.dataset.view));
  });

  // Hamburger
  hamburgerBtn?.addEventListener('click', () => {
    sidebar.classList.toggle('open');
    sidebarOverlay.classList.toggle('active');
  });

  sidebarOverlay?.addEventListener('click', () => {
    sidebar.classList.remove('open');
    sidebarOverlay.classList.remove('active');
  });

  // ── Clock ────────────────────────────────────────────────
  function updateClock() {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    if (clockEl) clockEl.textContent = `${h}:${m}:${s}`;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ── Dashboard ────────────────────────────────────────────
  function renderDashboard() {
    const metrics = SOCData.getMetrics();

    // Metric cards
    setText('metricTotal', metrics.total);
    setText('metricCritical', metrics.critical);
    setText('metricOpen', metrics.open);
    setText('metricMTTR', `${metrics.mttr}m`);

    // Charts
    charts.drawThreatScore('threatScoreCanvas', metrics.threatScore);
    charts.drawSeverityDonut('severityDonutCanvas', metrics);
    charts.drawTimeline('timelineCanvas', metrics.timeline);
    charts.drawAttackDistribution('attackDistCanvas', metrics.attackDistribution);
    charts.drawSourceDistribution('sourceDistCanvas', metrics.sourceDistribution);

    // Metric sparklines
    const sparkData = metrics.timeline.map(t => t.total);
    charts.drawSparkline('sparkTotal', sparkData, '#40c4ff');
    charts.drawSparkline('sparkCritical', sparkData.map((_,i) => metrics.timeline[i].critical), '#ff1744');
    charts.drawSparkline('sparkOpen', sparkData.map(v => Math.round(v * 0.6)), '#ff9100');
    charts.drawSparkline('sparkMTTR', sparkData.map(v => Math.max(1, v - Math.floor(Math.random()*3))), '#7c4dff');

    // Recent alerts mini list
    renderRecentAlerts(metrics);

    // Update nav badge
    const badge = document.getElementById('alertsBadge');
    if (badge) badge.textContent = metrics.open;
  }

  function renderRecentAlerts() {
    const container = document.getElementById('recentAlertsList');
    if (!container) return;
    const recent = SOCData.allAlerts().slice(0, 6);

    container.innerHTML = recent.map(a => `
      <div class="alert-item alert-item--compact" onclick="window.showAlertDetail('${a.id}')">
        <div class="alert-severity-dot ${a.severity}"></div>
        <span class="alert-id">${a.id}</span>
        <span class="alert-type">${a.attackType}</span>
        <span class="severity-badge severity-badge--sm ${a.severity}">${a.severity}</span>
      </div>
    `).join('');
  }

  // ── Alerts View ──────────────────────────────────────────
  function renderAlerts() {
    const alerts = getFilteredAlerts();
    const container = document.getElementById('alertsList');
    const countBadge = document.getElementById('alertsCount');

    if (countBadge) countBadge.textContent = `${alerts.length} alerts`;

    if (!container) return;
    container.innerHTML = alerts.map(a => {
      const timeDiff = getTimeDiff(a.timestamp);
      const statusClass = a.status.toLowerCase().replace(' ', '-');
      return `
        <div class="alert-item ${a.isNew ? 'new' : ''}" onclick="window.showAlertDetail('${a.id}')">
          <div class="alert-severity-dot ${a.severity}"></div>
          <span class="alert-id">${a.id}</span>
          <span class="alert-type">${a.source.icon} ${a.attackType}</span>
          <span class="alert-source">${a.srcIP}</span>
          <span class="alert-target">${a.target}</span>
          <span class="alert-time">${timeDiff}</span>
          <span class="alert-status-badge ${statusClass}">${a.status}</span>
        </div>
      `;
    }).join('');
  }

  function getFilteredAlerts() {
    let alerts = SOCData.allAlerts();
    if (alertFilter !== 'all') {
      alerts = alerts.filter(a => a.severity === alertFilter);
    }
    const searchTerm = searchInput?.value?.toLowerCase() || '';
    if (searchTerm) {
      alerts = alerts.filter(a =>
        a.id.toLowerCase().includes(searchTerm) ||
        a.attackType.toLowerCase().includes(searchTerm) ||
        a.srcIP.includes(searchTerm) ||
        a.target.toLowerCase().includes(searchTerm) ||
        a.source.name.toLowerCase().includes(searchTerm)
      );
    }
    return alerts;
  }

  // Filter buttons
  document.querySelectorAll('.filter-btn[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      alertFilter = btn.dataset.filter;
      document.querySelectorAll('.filter-btn[data-filter]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderAlerts();
    });
  });

  // Search
  searchInput?.addEventListener('input', () => {
    if (currentView === 'alerts') renderAlerts();
  });

  // ── Alert Detail ─────────────────────────────────────────
  window.showAlertDetail = function(alertId) {
    const alert = SOCData.allAlerts().find(a => a.id === alertId);
    if (!alert) return;
    selectedAlert = alert;
    renderAlertDetail(alert);
    alertDetailOverlay.classList.add('active');
  };

  window.closeAlertDetail = function() {
    alertDetailOverlay.classList.remove('active');
    selectedAlert = null;
  };

  alertDetailOverlay?.addEventListener('click', (e) => {
    if (e.target === alertDetailOverlay) window.closeAlertDetail();
  });

  function renderAlertDetail(alert) {
    document.getElementById('detailId').textContent = alert.id;
    document.getElementById('detailSeverity').innerHTML = `<span class="severity-badge ${alert.severity}">${alert.severity.toUpperCase()}</span>`;
    document.getElementById('detailType').textContent = alert.attackType;
    document.getElementById('detailSource').textContent = `${alert.source.icon} ${alert.source.name}`;
    document.getElementById('detailSrcIP').textContent = alert.srcIP;
    document.getElementById('detailTarget').textContent = alert.target;
    document.getElementById('detailStatus').textContent = alert.status;
    document.getElementById('detailTime').textContent = alert.timestamp.toLocaleString();
    document.getElementById('detailEvents').textContent = alert.eventCount;
    document.getElementById('detailMitre').textContent = alert.analysis.mitre;
    document.getElementById('detailKillChain').textContent = alert.analysis.killChain;

    document.getElementById('detailAIAnalysis').innerHTML = `
      <strong>${alert.analysis.summary}</strong><br><br>
      ${alert.analysis.details}<br><br>
      <strong>MITRE ATT&CK:</strong> ${alert.analysis.mitre}<br>
      <strong>Kill Chain Phase:</strong> ${alert.analysis.killChain}
    `;

    document.getElementById('detailConfidence').textContent = `${alert.analysis.confidence}%`;
    document.getElementById('confidenceFill').style.width = `${alert.analysis.confidence}%`;

    const remList = document.getElementById('detailRemediation');
    remList.innerHTML = alert.remediation.map((r, i) => `
      <li><span class="step-num">${i + 1}</span> ${r}</li>
    `).join('');
  }

  // ── Chat / AI Assistant ──────────────────────────────────
  let chatHistory = [];

  function addChatMessage(text, type = 'ai') {
    const msgDiv = document.createElement('div');
    msgDiv.className = `chat-message ${type}`;

    const avatar = document.createElement('div');
    avatar.className = 'chat-avatar';
    avatar.textContent = type === 'ai' ? '🤖' : '👤';

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble';

    // Format markdown-like text
    const formatted = formatChatText(text);
    bubble.innerHTML = `<div class="formatted-text">${formatted}</div>`;

    msgDiv.appendChild(avatar);
    msgDiv.appendChild(bubble);
    chatMessages.appendChild(msgDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function formatChatText(text) {
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`(.*?)`/g, '<code class="inline-code">$1</code>')
      .replace(/\n/g, '<br>');
  }

  function showTypingIndicator() {
    const indicator = document.createElement('div');
    indicator.className = 'chat-message ai';
    indicator.id = 'typingIndicator';
    indicator.innerHTML = `
      <div class="chat-avatar">🤖</div>
      <div class="chat-bubble">
        <div class="chat-typing">
          <div class="dot"></div>
          <div class="dot"></div>
          <div class="dot"></div>
        </div>
      </div>
    `;
    chatMessages.appendChild(indicator);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function removeTypingIndicator() {
    const indicator = document.getElementById('typingIndicator');
    if (indicator) indicator.remove();
  }

  function handleChatSend() {
    const msg = chatInput.value.trim();
    if (!msg) return;

    addChatMessage(msg, 'user');
    chatInput.value = '';
    chatHistory.push({ role: 'user', text: msg });

    showTypingIndicator();

    // Simulate AI thinking time
    const delay = 600 + Math.random() * 800;
    setTimeout(() => {
      removeTypingIndicator();
      const response = SOCData.processAIQuery(msg);
      addChatMessage(response, 'ai');
      chatHistory.push({ role: 'ai', text: response });
    }, delay);
  }

  chatSendBtn?.addEventListener('click', handleChatSend);
  chatInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleChatSend();
  });

  // Quick actions
  document.querySelectorAll('.quick-action').forEach(btn => {
    btn.addEventListener('click', () => {
      chatInput.value = btn.dataset.query;
      handleChatSend();
    });
  });

  // Initial AI greeting
  setTimeout(() => {
    addChatMessage("🛡️ **Welcome to AI SOC Assistant**\n\nI'm your intelligent security co-pilot, ready to help you analyze threats, investigate incidents, and recommend remediation actions.\n\nTry asking me about:\n• Current threat summary\n• Critical alerts\n• Investigation of specific incidents\n• Security best practices\n\nOr type `help` for a full command list.", 'ai');
  }, 500);

  // ── Investigate View ─────────────────────────────────────
  const investigateInput = document.getElementById('investigateInput');
  const investigateBtn = document.getElementById('investigateBtn');
  const investigateResult = document.getElementById('investigateResult');

  investigateBtn?.addEventListener('click', runInvestigation);
  investigateInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runInvestigation();
  });

  function runInvestigation() {
    const query = investigateInput?.value?.trim();
    if (!query) return;

    const result = SOCData.processAIQuery(query);
    const formatted = formatChatText(result);

    if (investigateResult) {
      investigateResult.innerHTML = `
        <h3>🔍 Investigation Results</h3>
        <div class="investigation-text">${formatted}</div>
      `;
      investigateResult.classList.remove('investigation-result--hidden');
    }
  }

  // ── Threats View ─────────────────────────────────────────
  function renderThreats() {
    const container = document.getElementById('threatsGrid');
    if (!container) return;

    const alerts = SOCData.allAlerts();
    const attackTypes = {};

    alerts.forEach(a => {
      if (!attackTypes[a.attackType]) {
        attackTypes[a.attackType] = { count: 0, severities: { critical: 0, high: 0, medium: 0, low: 0 }, latest: a.timestamp };
      }
      attackTypes[a.attackType].count++;
      attackTypes[a.attackType].severities[a.severity]++;
      if (a.timestamp > attackTypes[a.attackType].latest) {
        attackTypes[a.attackType].latest = a.timestamp;
      }
    });

    const sorted = Object.entries(attackTypes).sort((a, b) => b[1].count - a[1].count);

    container.innerHTML = sorted.map(([type, data]) => {
      const topSeverity = Object.entries(data.severities).sort((a, b) => b[1] - a[1])[0][0];
      const desc = window.SOCData.processAIQuery(type).split('\n').find(l => l.includes('Remediation')) ? '' : '';
      return `
        <div class="threat-card">
          <div class="threat-card-header">
            <h4>${type}</h4>
            <span class="severity-badge ${topSeverity}">${topSeverity}</span>
          </div>
          <p>${data.count} alerts detected. Severity breakdown: Critical(${data.severities.critical}) High(${data.severities.high}) Medium(${data.severities.medium}) Low(${data.severities.low})</p>
          <div class="threat-card-footer">
            <span>Last seen: ${getTimeDiff(data.latest)}</span>
            <span class="card-link-muted" onclick="document.querySelector('[data-view=chat]').click();">Investigate →</span>
          </div>
        </div>
      `;
    }).join('');
  }

  // ── Settings (toggles) ──────────────────────────────────
  document.querySelectorAll('.toggle-switch').forEach(toggle => {
    toggle.addEventListener('click', () => {
      toggle.classList.toggle('active');
    });
  });

  // ── Utility ──────────────────────────────────────────────
  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function getTimeDiff(date) {
    const diff = (Date.now() - date.getTime()) / 1000;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  // ── Live Alert Simulation ────────────────────────────────
  setInterval(() => {
    const newAlert = SOCData.generateNewAlert();

    // Update badge
    const badge = document.getElementById('alertsBadge');
    const metrics = SOCData.getMetrics();
    if (badge) badge.textContent = metrics.open;

    // If on dashboard, refresh
    if (currentView === 'dashboard') renderDashboard();

    // If on alerts, add to top
    if (currentView === 'alerts') renderAlerts();

    // Flash notification
    showNotification(newAlert);
  }, 15000 + Math.random() * 15000); // New alert every 15-30 seconds

  function showNotification(alert) {
    const notif = document.createElement('div');
    notif.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 14px 20px;
      background: ${SOCData.SEVERITY_CONFIG[alert.severity].bg};
      border: 1px solid ${SOCData.SEVERITY_CONFIG[alert.severity].color}44;
      border-left: 3px solid ${SOCData.SEVERITY_CONFIG[alert.severity].color};
      border-radius: 10px;
      z-index: 2000;
      animation: notifSlide 0.3s ease;
      cursor: pointer;
      backdrop-filter: blur(12px);
      max-width: 360px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      font-family: 'Inter', sans-serif;
    `;
    notif.innerHTML = `
      <div style="font-size: 12px; font-weight: 700; color: ${SOCData.SEVERITY_CONFIG[alert.severity].color}; margin-bottom: 4px;">
        🔔 New ${alert.severity.toUpperCase()} Alert
      </div>
      <div style="font-size: 11px; color: rgba(255,255,255,0.7);">
        ${alert.attackType} from ${alert.srcIP}
      </div>
      <div style="font-size: 10px; color: rgba(255,255,255,0.4); margin-top: 4px;">
        ${alert.id} • ${alert.source.icon} ${alert.source.name}
      </div>
    `;

    notif.onclick = () => {
      window.showAlertDetail(alert.id);
      notif.remove();
    };

    document.body.appendChild(notif);

    // Add animation styles
    if (!document.getElementById('notifStyles')) {
      const style = document.createElement('style');
      style.id = 'notifStyles';
      style.textContent = `
        @keyframes notifSlide {
          from { opacity: 0; transform: translateX(40px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes notifSlideOut {
          from { opacity: 1; transform: translateX(0); }
          to   { opacity: 0; transform: translateX(40px); }
        }
      `;
      document.head.appendChild(style);
    }

    setTimeout(() => {
      notif.style.animation = 'notifSlideOut 0.3s ease forwards';
      setTimeout(() => notif.remove(), 300);
    }, 5000);
  }

  // ── Vulnerabilities View (Real-Time NVD + CISA) ───────────
  async function loadVulnerabilities(forceRefresh = false) {
    if (vulnsLoaded && !forceRefresh) {
      renderVulnerabilities();
      return;
    }

    const feedStatusEl = document.getElementById('feedStatus');
    const loadingEl = document.getElementById('vulnLoading');
    if (feedStatusEl) {
      feedStatusEl.textContent = '⏳ Fetching feeds…';
      feedStatusEl.className = 'feed-status';
    }
    if (loadingEl) loadingEl.style.display = '';

    try {
      const results = await feed.fetchAll({
        nvd: { resultsPerPage: 20, days: 7 },
        cisa: { limit: 30 }
      });

      // Merge and deduplicate by CVE ID
      const nvdAlerts = feed.convertToAlerts(results.nvd);
      const cisaAlerts = feed.convertToAlerts(results.cisa);

      const seen = new Set();
      allVulnerabilities = [];

      // CISA KEV first (higher priority)
      cisaAlerts.forEach(a => {
        if (!seen.has(a.id)) {
          seen.add(a.id);
          allVulnerabilities.push(a);
        }
      });

      // Then NVD entries
      nvdAlerts.forEach(a => {
        if (!seen.has(a.id)) {
          seen.add(a.id);
          allVulnerabilities.push(a);
        }
      });

      // Sort: critical first, then by timestamp
      allVulnerabilities.sort((a, b) => {
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const sevDiff = (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3);
        if (sevDiff !== 0) return sevDiff;
        return (b.timestamp || 0) - (a.timestamp || 0);
      });

      vulnsLoaded = true;

      // Update status
      updateFeedStatus(results);
      renderVulnerabilities();

      // Update badge
      const badge = document.getElementById('vulnsBadge');
      if (badge) badge.textContent = allVulnerabilities.length;

    } catch (error) {
      console.error('[Vulns] Load error:', error);
      if (feedStatusEl) {
        feedStatusEl.textContent = '❌ Feed error';
        feedStatusEl.className = 'feed-status error';
      }
    }
  }

  function updateFeedStatus(results) {
    const feedStatusEl = document.getElementById('feedStatus');
    const nvdDetail = document.getElementById('nvdStatusDetail');
    const cisaDetail = document.getElementById('cisaStatusDetail');
    const nvdCount = document.getElementById('nvdCount');
    const cisaCount = document.getElementById('cisaCount');

    const status = feed.getStatus();

    if (nvdDetail) {
      nvdDetail.textContent = status.nvd.error
        ? `Error: ${status.nvd.error}`
        : `Last fetched: ${status.nvd.lastFetch?.toLocaleTimeString() || 'N/A'} • ${status.nvd.count} CVEs (last 7 days)`;
    }
    if (cisaDetail) {
      cisaDetail.textContent = status.cisa.error
        ? `Error: ${status.cisa.error}`
        : `Last fetched: ${status.cisa.lastFetch?.toLocaleTimeString() || 'N/A'} • Most recent KEV entries`;
    }
    if (nvdCount) nvdCount.textContent = status.nvd.count;
    if (cisaCount) cisaCount.textContent = status.cisa.count;

    if (feedStatusEl) {
      const hasErrors = status.nvd.error || status.cisa.error;
      if (hasErrors) {
        feedStatusEl.textContent = '⚠️ Partial data';
        feedStatusEl.className = 'feed-status error';
      } else {
        feedStatusEl.textContent = '✅ Feeds connected';
        feedStatusEl.className = 'feed-status connected';
      }
    }
  }

  // ── CVSS Scores by Vulnerability Type ───────────────────────
  function renderCvssByType() {
    const grid = document.getElementById('cvssTypeGrid');
    if (!grid) return;

    if (allVulnerabilities.length === 0) {
      grid.innerHTML = '<div class="cvss-type-empty">⏳ No vulnerability data loaded yet.</div>';
      return;
    }

    // Group by attackType
    const typeMap = {};
    allVulnerabilities.forEach(v => {
      const type = v.attackType || 'Security Vulnerability';
      const cvss = v.cvssScore ?? v.analysis?.cvssScore ?? null;

      if (!typeMap[type]) {
        typeMap[type] = { count: 0, scores: [], maxCvss: 0, totalCvss: 0 };
      }
      typeMap[type].count++;
      if (cvss != null) {
        typeMap[type].scores.push(cvss);
        typeMap[type].totalCvss += cvss;
        if (cvss > typeMap[type].maxCvss) typeMap[type].maxCvss = cvss;
      }
    });

    // Convert to array and sort by max CVSS descending
    const entries = Object.entries(typeMap)
      .map(([name, data]) => ({
        name,
        count: data.count,
        avgCvss: data.scores.length > 0 ? (data.totalCvss / data.scores.length) : null,
        maxCvss: data.scores.length > 0 ? data.maxCvss : null,
        scored: data.scores.length
      }))
      .sort((a, b) => (b.maxCvss || 0) - (a.maxCvss || 0));

    const getSevClass = (score) => {
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      return 'low';
    };

    grid.innerHTML = entries.map(e => {
      const avgDisplay = e.avgCvss != null ? e.avgCvss.toFixed(1) : 'N/A';
      const maxDisplay = e.maxCvss != null ? e.maxCvss.toFixed(1) : 'N/A';
      const barPct = e.maxCvss != null ? (e.maxCvss / 10) * 100 : 0;
      const sevClass = e.maxCvss != null ? getSevClass(e.maxCvss) : 'low';

      return `
        <div class="cvss-type-card sev-${sevClass}">
          <div class="cvss-type-top">
            <span class="cvss-type-name">${e.name}</span>
            <span class="cvss-type-count">${e.count} CVE${e.count !== 1 ? 's' : ''}</span>
          </div>
          <div class="cvss-type-scores">
            <div class="cvss-type-stat">
              <span class="cvss-type-stat-label">Avg CVSS</span>
              <span class="cvss-type-stat-value avg">${avgDisplay}</span>
            </div>
            <div class="cvss-type-stat">
              <span class="cvss-type-stat-label">Max CVSS</span>
              <span class="cvss-type-stat-value max val-${sevClass}">${maxDisplay}</span>
            </div>
          </div>
          <div class="cvss-type-bar-track">
            <div class="cvss-type-bar-fill fill-${sevClass}" style="width:${barPct}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderVulnerabilities() {
    renderCvssByType();
    const container = document.getElementById('vulnList');
    const countEl = document.getElementById('vulnsCount');
    const loadingEl = document.getElementById('vulnLoading');

    if (loadingEl) loadingEl.style.display = 'none';
    if (!container) return;

    let filtered = allVulnerabilities;

    // Apply severity filter
    if (vulnFilter !== 'all') {
      filtered = filtered.filter(v => v.severity === vulnFilter);
    }

    // Apply source filter
    if (vulnSourceFilter !== 'all') {
      if (vulnSourceFilter === 'nvd') {
        filtered = filtered.filter(v => !v.isKEV);
      } else if (vulnSourceFilter === 'cisa') {
        filtered = filtered.filter(v => v.isKEV);
      }
    }

    if (countEl) countEl.textContent = `${filtered.length} vulnerabilities`;

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="vuln-empty">
          ${allVulnerabilities.length === 0
            ? '⏳ No vulnerability data loaded yet. Click Refresh to fetch.'
            : '🔍 No vulnerabilities match the current filters.'
          }
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(v => {
      const isKEV = v.isKEV;
      const cvssDisplay = v.cvssScore != null ? v.cvssScore.toFixed(1) : (v.analysis?.cvssScore != null ? v.analysis.cvssScore.toFixed(1) : null);

      // Affected products / target
      const products = isKEV
        ? `<span class="vuln-product-tag">${v.target || 'Unknown'}</span>`
        : (v.target ? `<span class="vuln-product-tag">${v.target}</span>` : '');

      // References
      const refs = (v.references || []).slice(0, 3).map(ref => {
        const label = ref.url.includes('nvd.nist.gov') ? 'NVD'
          : ref.url.includes('github.com') ? 'GitHub'
          : ref.url.includes('cisa.gov') ? 'CISA'
          : 'Ref';
        return `<a href="${ref.url}" target="_blank" rel="noopener" class="vuln-ref-link">${label} ↗</a>`;
      }).join('');

      const nvdLink = `<a href="https://nvd.nist.gov/vuln/detail/${v.id}" target="_blank" rel="noopener" class="vuln-ref-link">NVD ↗</a>`;

      // Time display
      const timeStr = v.timestamp instanceof Date ? v.timestamp.toLocaleDateString() : '';

      // Description
      const desc = v.analysis?.details || v.description || 'No description available.';

      return `
        <div class="vuln-item ${isKEV ? 'kev' : ''}" onclick="window.showVulnDetail('${v.id}')">
          <div class="vuln-item-header">
            <span class="vuln-cve-id">${v.id}</span>
            <span class="vuln-source-badge ${isKEV ? 'cisa' : 'nvd'}">${isKEV ? '🇺🇸 CISA KEV' : '🏛️ NVD'}</span>
            <span class="severity-badge ${v.severity}">${v.severity}</span>
            ${isKEV ? '<span class="vuln-kev-tag">⚠️ Actively Exploited</span>' : ''}
            ${v.attackType ? `<span class="vuln-meta-item"><strong>${v.attackType}</strong></span>` : ''}
            <div class="vuln-cvss">
              ${cvssDisplay ? `<span class="cvss-score ${v.severity}">CVSS ${cvssDisplay}</span>` : ''}
            </div>
          </div>
          <div class="vuln-description">${desc}</div>
          <div class="vuln-meta">
            <span class="vuln-meta-item">📅 ${timeStr}</span>
            ${v.analysis?.mitre ? `<span class="vuln-meta-item">🔗 <strong>${v.analysis.mitre}</strong></span>` : ''}
            ${isKEV && v.remediation?.[1] ? `<span class="vuln-meta-item">⏰ ${v.remediation[1]}</span>` : ''}
            <div class="vuln-products">${products}</div>
          </div>
          <div class="vuln-refs">
            ${nvdLink}
            ${refs}
            ${isKEV ? `<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener" class="vuln-ref-link">CISA Catalog ↗</a>` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  // Vulnerability filter buttons
  document.querySelectorAll('[data-vuln-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      vulnFilter = btn.dataset.vulnFilter;
      document.querySelectorAll('[data-vuln-filter]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderVulnerabilities();
    });
  });

  document.querySelectorAll('[data-vuln-source]').forEach(btn => {
    btn.addEventListener('click', () => {
      vulnSourceFilter = btn.dataset.vulnSource;
      document.querySelectorAll('[data-vuln-source]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderVulnerabilities();
    });
  });

  // Refresh button
  document.getElementById('vulnRefreshBtn')?.addEventListener('click', () => {
    vulnsLoaded = false;
    loadVulnerabilities(true);
  });

  // ── Vulnerability Remediation Panel ──────────────────────
  const vulnDetailOverlay = document.getElementById('vulnDetailOverlay');
  let vulnStepStates = {}; // Track completed steps per CVE
  let vulnVerifyStates = {};

  window.showVulnDetail = function(cveId) {
    const vuln = allVulnerabilities.find(v => v.id === cveId);
    if (!vuln) return;

    // Initialize step tracking for this CVE
    if (!vulnStepStates[cveId]) vulnStepStates[cveId] = {};
    if (!vulnVerifyStates[cveId]) vulnVerifyStates[cveId] = {};

    renderVulnDetail(vuln);
    vulnDetailOverlay.classList.add('active');
  };

  window.closeVulnDetail = function() {
    vulnDetailOverlay.classList.remove('active');
  };

  vulnDetailOverlay?.addEventListener('click', (e) => {
    if (e.target === vulnDetailOverlay) window.closeVulnDetail();
  });

  function renderVulnDetail(vuln) {
    const cveId = vuln.id;
    const isKEV = vuln.isKEV;
    const cwes = vuln.analysis?.mitre?.split(', ').filter(c => c.startsWith('CWE-')) || [];
    const playbook = feed.getRemediationPlaybook(cwes);

    // Header
    document.getElementById('vulnDetailId').textContent = cveId;

    // Info fields
    document.getElementById('vdCveId').textContent = cveId;
    document.getElementById('vdSeverity').innerHTML = `<span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>`;
    const cvss = vuln.cvssScore ?? vuln.analysis?.cvssScore;
    document.getElementById('vdCvss').innerHTML = cvss != null
      ? `<span class="cvss-score ${vuln.severity}">${cvss.toFixed(1)}</span>`
      : 'N/A';
    document.getElementById('vdAttackType').textContent = vuln.attackType || 'Security Vulnerability';
    document.getElementById('vdSource').textContent = isKEV ? '🇺🇸 CISA KEV' : '🏛️ NVD';
    document.getElementById('vdPublished').textContent = vuln.timestamp instanceof Date ? vuln.timestamp.toLocaleDateString() : '--';
    document.getElementById('vdCwe').textContent = cwes.length > 0 ? cwes.join(', ') : 'N/A';
    document.getElementById('vdProduct').textContent = vuln.target || 'Multiple Products';

    // Description
    document.getElementById('vdDescription').textContent = vuln.analysis?.details || 'No description available.';

    // Risk Assessment
    document.getElementById('vdRiskBox').textContent = playbook.risk;

    // CVSS Breakdown
    const cvssSection = document.getElementById('vdCvssSection');
    const cvssBreakdown = document.getElementById('vdCvssBreakdown');
    const vector = vuln.analysis?.cvssVector || '';

    if (vector && vector.includes('/')) {
      cvssSection.style.display = '';
      const metrics = parseCVSSVector(vector);
      cvssBreakdown.innerHTML = metrics.map(m => {
        const pct = m.score * 100;
        const color = pct > 70 ? 'var(--accent-red)' : pct > 40 ? 'var(--accent-orange)' : 'var(--accent-green)';
        return `
          <div class="cvss-metric">
            <span class="cvss-metric-label">${m.label}</span>
            <span class="cvss-metric-value">${m.value}</span>
            <div class="cvss-metric-bar">
              <div class="cvss-metric-bar-fill" style="width:${pct}%;background:${color}"></div>
            </div>
          </div>
        `;
      }).join('');
    } else {
      cvssSection.style.display = 'none';
    }

    // Playbook Title
    document.getElementById('vdPlaybookTitle').textContent = `${playbook.icon} ${playbook.title}`;

    // Remediation Steps
    const remContainer = document.getElementById('vdRemediation');
    remContainer.innerHTML = playbook.steps.map((step, i) => {
      const done = vulnStepStates[cveId]?.[i] || false;
      return `
        <div class="rem-step ${done ? 'completed' : ''}" onclick="window.toggleVulnStep('${cveId}', ${i})">
          <div class="rem-step-check">${done ? '✓' : ''}</div>
          <div class="rem-step-content">
            <div class="rem-step-text">${step.action}</div>
            <div class="rem-step-meta">
              <span class="rem-urgency ${step.urgency}">${step.urgency.replace('-', ' ')}</span>
              <span class="rem-category">${step.category}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');

    updateVulnProgress(cveId, playbook.steps.length);

    // Verification Checklist
    const verifyContainer = document.getElementById('vdVerification');
    verifyContainer.innerHTML = playbook.verification.map((item, i) => {
      const done = vulnVerifyStates[cveId]?.[i] || false;
      return `
        <div class="verify-item ${done ? 'completed' : ''}" onclick="window.toggleVulnVerify('${cveId}', ${i})">
          <div class="verify-check">${done ? '✓' : ''}</div>
          <span>${item}</span>
        </div>
      `;
    }).join('');

    // References
    const refsContainer = document.getElementById('vdReferences');
    const allRefs = [
      ...playbook.references.map(r => ({ text: r, url: null })),
      { text: `View on NVD`, url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
      ...(vuln.references || []).slice(0, 3).map(r => ({
        text: r.url.replace('https://', '').split('/').slice(0, 2).join('/'),
        url: r.url
      }))
    ];

    refsContainer.innerHTML = allRefs.map(ref => {
      if (ref.url) {
        return `<a href="${ref.url}" target="_blank" rel="noopener" class="vuln-detail-ref">🔗 ${ref.text} ↗</a>`;
      }
      return `<div class="vuln-detail-ref"><span class="vuln-detail-ref-text">📄 ${ref.text}</span></div>`;
    }).join('');
  }

  window.toggleVulnStep = function(cveId, stepIndex) {
    if (!vulnStepStates[cveId]) vulnStepStates[cveId] = {};
    vulnStepStates[cveId][stepIndex] = !vulnStepStates[cveId][stepIndex];

    const vuln = allVulnerabilities.find(v => v.id === cveId);
    if (vuln) renderVulnDetail(vuln);
  };

  window.toggleVulnVerify = function(cveId, verifyIndex) {
    if (!vulnVerifyStates[cveId]) vulnVerifyStates[cveId] = {};
    vulnVerifyStates[cveId][verifyIndex] = !vulnVerifyStates[cveId][verifyIndex];

    const vuln = allVulnerabilities.find(v => v.id === cveId);
    if (vuln) renderVulnDetail(vuln);
  };

  function updateVulnProgress(cveId, totalSteps) {
    const states = vulnStepStates[cveId] || {};
    const completed = Object.values(states).filter(Boolean).length;
    const pct = totalSteps > 0 ? (completed / totalSteps) * 100 : 0;

    const fill = document.getElementById('vdProgressFill');
    const text = document.getElementById('vdProgressText');
    if (fill) fill.style.width = `${pct}%`;
    if (text) text.textContent = `${completed} of ${totalSteps} steps completed (${Math.round(pct)}%)`;
  }

  function parseCVSSVector(vector) {
    const metrics = [];
    const parts = vector.split('/');

    const metricLabels = {
      'AV': { label: 'Attack Vector', values: { 'N': ['Network', 1], 'A': ['Adjacent', 0.7], 'L': ['Local', 0.4], 'P': ['Physical', 0.1] }},
      'AC': { label: 'Attack Complexity', values: { 'L': ['Low', 1], 'H': ['High', 0.3] }},
      'PR': { label: 'Privileges Required', values: { 'N': ['None', 1], 'L': ['Low', 0.5], 'H': ['High', 0.1] }},
      'UI': { label: 'User Interaction', values: { 'N': ['None', 1], 'R': ['Required', 0.3] }},
      'S':  { label: 'Scope', values: { 'U': ['Unchanged', 0.3], 'C': ['Changed', 1] }},
      'C':  { label: 'Confidentiality', values: { 'H': ['High', 1], 'L': ['Low', 0.4], 'N': ['None', 0] }},
      'I':  { label: 'Integrity', values: { 'H': ['High', 1], 'L': ['Low', 0.4], 'N': ['None', 0] }},
      'A':  { label: 'Availability', values: { 'H': ['High', 1], 'L': ['Low', 0.4], 'N': ['None', 0] }}
    };

    parts.forEach(part => {
      const [key, val] = part.split(':');
      if (metricLabels[key] && metricLabels[key].values[val]) {
        const [valueName, score] = metricLabels[key].values[val];
        metrics.push({ label: metricLabels[key].label, value: valueName, score });
      }
    });

    return metrics;
  }

  // ── Initial Render ───────────────────────────────────────
  switchView('dashboard');
});
