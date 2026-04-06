// ============================================================
// AI SOC Assistant - Charts & Visualizations (Canvas-based)
// ============================================================

class SOCCharts {
  constructor() {
    this.animationFrames = {};
    this.chartData = {};
  }

  // ── Utility ──────────────────────────────────────────────
  clearCanvas(canvas) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    return ctx;
  }

  resizeCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { width: rect.width, height: rect.height, ctx };
  }

  // ── Animated Ring / Donut Chart ──────────────────────────
  drawThreatScore(canvasId, score, label = 'Threat Score') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) / 2 - 20;
    const lineWidth = 12;

    let currentAngle = 0;
    const targetAngle = (score / 100) * Math.PI * 2;
    const animDuration = 1200;
    const startTime = performance.now();

    const getColor = (s) => {
      if (s >= 80) return '#ff1744';
      if (s >= 60) return '#ff9100';
      if (s >= 40) return '#ffea00';
      return '#00e676';
    };

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / animDuration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
      currentAngle = targetAngle * eased;

      ctx.clearRect(0, 0, width, height);

      // Background ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255,255,255,0.06)';
      ctx.lineWidth = lineWidth;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Score ring
      const gradient = ctx.createLinearGradient(0, 0, width, height);
      const color = getColor(score);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, color + '88');
      ctx.beginPath();
      ctx.arc(cx, cy, radius, -Math.PI / 2, -Math.PI / 2 + currentAngle);
      ctx.strokeStyle = gradient;
      ctx.lineWidth = lineWidth;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Glow effect
      ctx.shadowColor = color;
      ctx.shadowBlur = 15;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, -Math.PI / 2 + currentAngle - 0.05, -Math.PI / 2 + currentAngle);
      ctx.strokeStyle = color;
      ctx.lineWidth = lineWidth;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Score text
      const displayScore = Math.round(score * eased);
      ctx.fillStyle = '#ffffff';
      ctx.font = `bold ${radius * 0.55}px 'Inter', sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(displayScore, cx, cy - 6);

      ctx.fillStyle = 'rgba(255,255,255,0.5)';
      ctx.font = `500 ${radius * 0.18}px 'Inter', sans-serif`;
      ctx.fillText(label, cx, cy + radius * 0.35);

      if (progress < 1) {
        this.animationFrames[canvasId] = requestAnimationFrame(animate);
      }
    };

    if (this.animationFrames[canvasId]) cancelAnimationFrame(this.animationFrames[canvasId]);
    this.animationFrames[canvasId] = requestAnimationFrame(animate);
  }

  // ── Severity Distribution Donut ──────────────────────────
  drawSeverityDonut(canvasId, metrics) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) / 2 - 20;
    const innerRadius = radius * 0.6;

    const data = [
      { label: 'Critical', value: metrics.critical, color: '#ff1744' },
      { label: 'High', value: metrics.high, color: '#ff9100' },
      { label: 'Medium', value: metrics.medium, color: '#ffea00' },
      { label: 'Low', value: metrics.low, color: '#00e676' }
    ];
    const total = data.reduce((s, d) => s + d.value, 0);
    if (total === 0) return;

    const animDuration = 1000;
    const startTime = performance.now();

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / animDuration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);

      ctx.clearRect(0, 0, width, height);

      let startAngle = -Math.PI / 2;
      data.forEach(d => {
        const sliceAngle = (d.value / total) * Math.PI * 2 * eased;
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = d.color;
        ctx.fill();

        // Gap between slices
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.strokeStyle = '#0a0e1a';
        ctx.lineWidth = 2;
        ctx.stroke();

        startAngle += sliceAngle;
      });

      // Center text
      ctx.fillStyle = '#ffffff';
      ctx.font = `bold ${innerRadius * 0.5}px 'Inter', sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(Math.round(total * eased), cx, cy - 4);
      ctx.fillStyle = 'rgba(255,255,255,0.5)';
      ctx.font = `500 ${innerRadius * 0.2}px 'Inter', sans-serif`;
      ctx.fillText('Total Alerts', cx, cy + innerRadius * 0.3);

      if (progress < 1) {
        this.animationFrames[canvasId] = requestAnimationFrame(animate);
      }
    };

    if (this.animationFrames[canvasId]) cancelAnimationFrame(this.animationFrames[canvasId]);
    this.animationFrames[canvasId] = requestAnimationFrame(animate);
  }

  // ── Timeline Bar Chart ───────────────────────────────────
  drawTimeline(canvasId, timeline) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);
    const padding = { top: 20, right: 20, bottom: 35, left: 40 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    const maxVal = Math.max(...timeline.map(t => t.total), 1);
    const barWidth = chartW / timeline.length - 3;

    const animDuration = 800;
    const startTime = performance.now();

    const severityColors = ['#ff1744', '#ff9100', '#ffea00', '#00e676'];

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / animDuration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);

      ctx.clearRect(0, 0, width, height);

      // Grid lines
      ctx.strokeStyle = 'rgba(255,255,255,0.05)';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = padding.top + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();

        ctx.fillStyle = 'rgba(255,255,255,0.3)';
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), padding.left - 8, y + 4);
      }

      // Bars
      timeline.forEach((t, i) => {
        const x = padding.left + i * (chartW / timeline.length) + 1.5;
        const barH = (t.total / maxVal) * chartH * eased;
        const y = padding.top + chartH - barH;

        // Stacked severity bars
        let stackY = padding.top + chartH;
        const segments = [
          { val: t.low, color: '#00e676' },
          { val: t.medium, color: '#ffea00' },
          { val: t.high, color: '#ff9100' },
          { val: t.critical, color: '#ff1744' }
        ];

        segments.forEach(seg => {
          const segH = (seg.val / maxVal) * chartH * eased;
          if (segH > 0) {
            stackY -= segH;
            ctx.fillStyle = seg.color + '99';
            ctx.beginPath();
            const r = Math.min(3, barWidth / 2);
            ctx.roundRect(x, stackY, barWidth, segH, [r, r, 0, 0]);
            ctx.fill();
          }
        });

        // Hour label
        ctx.fillStyle = 'rgba(255,255,255,0.35)';
        ctx.font = '9px Inter, sans-serif';
        ctx.textAlign = 'center';
        if (i % 3 === 0) {
          ctx.fillText(`${t.hour}:00`, x + barWidth / 2, height - 8);
        }
      });

      if (progress < 1) {
        this.animationFrames[canvasId] = requestAnimationFrame(animate);
      }
    };

    if (this.animationFrames[canvasId]) cancelAnimationFrame(this.animationFrames[canvasId]);
    this.animationFrames[canvasId] = requestAnimationFrame(animate);
  }

  // ── Horizontal Bar Chart (Attack Distribution) ──────────
  drawAttackDistribution(canvasId, distribution) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);

    const entries = Object.entries(distribution).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const maxVal = Math.max(...entries.map(e => e[1]), 1);
    const barHeight = Math.min(28, (height - 20) / entries.length - 6);
    const startY = 10;
    const labelWidth = 130;
    const barMaxWidth = width - labelWidth - 60;

    const animDuration = 900;
    const startTime = performance.now();
    const colors = ['#ff1744', '#ff5252', '#ff9100', '#ffab40', '#ffea00', '#69f0ae', '#40c4ff', '#7c4dff'];

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / animDuration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);

      ctx.clearRect(0, 0, width, height);

      entries.forEach(([name, value], i) => {
        const y = startY + i * (barHeight + 6);
        const barW = (value / maxVal) * barMaxWidth * eased;

        // Label
        ctx.fillStyle = 'rgba(255,255,255,0.7)';
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(name, labelWidth - 10, y + barHeight / 2);

        // Bar background
        ctx.fillStyle = 'rgba(255,255,255,0.04)';
        ctx.beginPath();
        ctx.roundRect(labelWidth, y, barMaxWidth, barHeight, 4);
        ctx.fill();

        // Bar
        const gradient = ctx.createLinearGradient(labelWidth, 0, labelWidth + barW, 0);
        gradient.addColorStop(0, colors[i % colors.length] + 'cc');
        gradient.addColorStop(1, colors[i % colors.length] + '44');
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.roundRect(labelWidth, y, Math.max(barW, 0), barHeight, 4);
        ctx.fill();

        // Value
        ctx.fillStyle = 'rgba(255,255,255,0.6)';
        ctx.font = 'bold 11px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(Math.round(value * eased), labelWidth + barW + 8, y + barHeight / 2);
      });

      if (progress < 1) {
        this.animationFrames[canvasId] = requestAnimationFrame(animate);
      }
    };

    if (this.animationFrames[canvasId]) cancelAnimationFrame(this.animationFrames[canvasId]);
    this.animationFrames[canvasId] = requestAnimationFrame(animate);
  }

  // ── Source Distribution Polar Chart ──────────────────────
  drawSourceDistribution(canvasId, distribution) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);

    const entries = Object.entries(distribution).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, e) => s + e[1], 0);
    const cx = width / 2;
    const cy = height / 2;
    const maxRadius = Math.min(width, height) / 2 - 30;

    const animDuration = 1000;
    const startTime = performance.now();
    const colors = ['#40c4ff', '#7c4dff', '#ff4081', '#69f0ae', '#ffab40', '#ff6e40', '#e040fb', '#18ffff', '#ffd740', '#b2ff59'];

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / animDuration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);

      ctx.clearRect(0, 0, width, height);

      // Draw concentric rings
      for (let r = 1; r <= 3; r++) {
        ctx.beginPath();
        ctx.arc(cx, cy, (maxRadius / 3) * r, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      const angleStep = (Math.PI * 2) / entries.length;
      entries.forEach(([name, value], i) => {
        const angle = angleStep * i - Math.PI / 2;
        const radius = (value / (total / entries.length)) * maxRadius * 0.5 * eased;
        const clampedRadius = Math.min(radius, maxRadius);

        const x = cx + Math.cos(angle) * clampedRadius;
        const y = cy + Math.sin(angle) * clampedRadius;

        // Spoke line
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(x, y);
        ctx.strokeStyle = colors[i % colors.length] + '66';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Dot
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = colors[i % colors.length];
        ctx.fill();

        // Glow
        ctx.shadowColor = colors[i % colors.length];
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Label
        const labelRadius = maxRadius + 15;
        const lx = cx + Math.cos(angle) * labelRadius;
        const ly = cy + Math.sin(angle) * labelRadius;
        ctx.fillStyle = 'rgba(255,255,255,0.6)';
        ctx.font = '9px Inter, sans-serif';
        ctx.textAlign = Math.cos(angle) > 0 ? 'left' : 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(name, lx, ly);
      });

      // Draw web
      if (eased > 0.5) {
        ctx.beginPath();
        entries.forEach(([, value], i) => {
          const angle = angleStep * i - Math.PI / 2;
          const radius = Math.min((value / (total / entries.length)) * maxRadius * 0.5 * eased, maxRadius);
          const x = cx + Math.cos(angle) * radius;
          const y = cy + Math.sin(angle) * radius;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.closePath();
        ctx.fillStyle = 'rgba(64, 196, 255, 0.08)';
        ctx.fill();
        ctx.strokeStyle = 'rgba(64, 196, 255, 0.3)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      if (progress < 1) {
        this.animationFrames[canvasId] = requestAnimationFrame(animate);
      }
    };

    if (this.animationFrames[canvasId]) cancelAnimationFrame(this.animationFrames[canvasId]);
    this.animationFrames[canvasId] = requestAnimationFrame(animate);
  }

  // ── Mini Sparkline ───────────────────────────────────────
  drawSparkline(canvasId, data, color = '#40c4ff') {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const { width, height, ctx } = this.resizeCanvas(canvas);

    const max = Math.max(...data, 1);
    const step = width / (data.length - 1);

    // Gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, color + '33');
    gradient.addColorStop(1, color + '00');

    ctx.beginPath();
    ctx.moveTo(0, height);
    data.forEach((v, i) => {
      const x = i * step;
      const y = height - (v / max) * (height - 4);
      if (i === 0) ctx.lineTo(x, y);
      else {
        const prevX = (i - 1) * step;
        const prevY = height - (data[i - 1] / max) * (height - 4);
        const cpx = (prevX + x) / 2;
        ctx.bezierCurveTo(cpx, prevY, cpx, y, x, y);
      }
    });
    ctx.lineTo(width, height);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((v, i) => {
      const x = i * step;
      const y = height - (v / max) * (height - 4);
      if (i === 0) ctx.moveTo(x, y);
      else {
        const prevX = (i - 1) * step;
        const prevY = height - (data[i - 1] / max) * (height - 4);
        const cpx = (prevX + x) / 2;
        ctx.bezierCurveTo(cpx, prevY, cpx, y, x, y);
      }
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();

    // End dot
    const lastX = (data.length - 1) * step;
    const lastY = height - (data[data.length - 1] / max) * (height - 4);
    ctx.beginPath();
    ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.shadowColor = color;
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  destroy() {
    Object.values(this.animationFrames).forEach(id => cancelAnimationFrame(id));
    this.animationFrames = {};
  }
}

window.SOCCharts = SOCCharts;
