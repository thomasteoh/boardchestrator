/* Brand animation: four kanban cards drift and orbit over a soft grid.
 * Plain ES5 (site has no build step; app.js follows the same convention).
 * Reduced-motion users get a static fallback (canvas stays hidden).
 */
(function () {
  var canvas = document.getElementById('brand');
  if (!canvas) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  var ctx = canvas.getContext('2d');
  var W = 0, H = 0, DPR = 1, raf = 0, last = 0;
  var cards = [
    { x: 0.30, y: 0.34, dx: 0.0009, dy: 0.0006, phase: 0.0, size: 0.30, label: 'build' },
    { x: 0.60, y: 0.66, dx: -0.0006, dy: -0.0009, phase: 1.5, size: 0.26, label: 'agents' },
    { x: 0.72, y: 0.28, dx: 0.0005, dy: 0.0008, phase: 3.0, size: 0.22, label: 'wiki' },
    { x: 0.22, y: 0.62, dx: -0.0007, dy: 0.0005, phase: 4.5, size: 0.20, label: 'mcp' }
  ];

  function resize() {
    DPR = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    W = Math.max(rect.width, 1);
    H = Math.max(rect.height, 1);
    canvas.width = Math.round(W * DPR);
    canvas.height = Math.round(H * DPR);
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
  }

  function grid() {
    ctx.save();
    ctx.scale(DPR, DPR);
    ctx.clearRect(0, 0, W, H);
    var cs = getComputedStyle(document.body);
    var border = hexToRgb(cs.getPropertyValue('--border') || '#d8dde4');
    var accent = hexToRgb(cs.getPropertyValue('--accent') || '#2f6fed');
    var step = 42;
    ctx.strokeStyle = 'rgba(' + border + ',0.5)';
    ctx.lineWidth = 1;
    for (var x = 0; x <= W; x += step) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (var y = 0; y <= H; y += step) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
    ctx.restore();
    return accent;
  }

  function hexToRgb(hex) {
    hex = hex.replace('#', '');
    var n = parseInt(hex, 16);
    return (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255);
  }

  function drawCard(c, accent) {
    var cx = c.x * W, cy = c.y * H;
    var s = c.size * Math.min(W, H);
    var bw = s * 1.15, bh = s * 0.7;
    var ox = Math.cos(c.phase) * 4, oy = Math.sin(c.phase) * 4;
    // shadow
    ctx.fillStyle = 'rgba(16,20,26,0.08)';
    roundRect(cx - bw / 2 + 3, cy - bh / 2 + 3, bw, bh, 6);
    ctx.fill();
    // card body
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--surface') || '#ffffff';
    roundRect(cx - bw / 2 + ox, cy - bh / 2 + oy, bw, bh, 6);
    ctx.fill();
    // accent bar
    ctx.fillStyle = 'rgba(' + accent + ',0.9)';
    roundRect(cx - bw / 2 + ox + 6, cy - bh / 2 + oy + 6, bw - 12, 4, 2);
    ctx.fill();
    // label
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted') || '#5b6472';
    ctx.font = Math.max(9, Math.round(s * 0.16)) + 'px ' + (getComputedStyle(document.body).getPropertyValue('--mono') || 'monospace');
    ctx.textAlign = 'center';
    ctx.fillText(c.label, cx + ox, cy + oy + bh * 0.5 + s * 0.10);
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function frame(now) {
    var dt = Math.min((now - last) / 1000, 0.05); last = now;
    var accent = grid();
    for (var i = 0; i < cards.length; i++) {
      var c = cards[i];
      c.phase += dt * 0.5;
      c.x += c.dx; c.y += c.dy;
      if (c.x < 0.12) c.dx = Math.abs(c.dx);
      if (c.x > 0.88) c.dx = -Math.abs(c.dx);
      if (c.y < 0.12) c.dy = Math.abs(c.dy);
      if (c.y > 0.88) c.dy = -Math.abs(c.dy);
      drawCard(c, accent);
    }
    raf = requestAnimationFrame(frame);
  }

  function start() {
    resize();
    canvas.classList.add('ready');
    last = performance.now();
    raf = requestAnimationFrame(frame);
  }
  function stop() {
    cancelAnimationFrame(raf);
    raf = 0;
  }

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) start(); else stop();
    });
  }, { threshold: 0.1 });
  io.observe(canvas);
  window.addEventListener('resize', resize);
})();
