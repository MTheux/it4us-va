// Visual adaptation of Draxen Core's projected 3D mesh. No wiki, memory or engine tools.
import { makeMesh, project, clamp } from './mesh.js';
import { morphAmount, dragonGlyphs, interpolateGlyph } from './dragon-morph.js';
export function mountDraxenCore(canvas, initial = {}) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return { update() {}, dispose() {} };
  const mesh = makeMesh(360);
  let glyphs = [], dragonAspect = .78;
  canvas.setAttribute('aria-label', 'Draxen Core se transformando no dragão ASCII');
  const dragon = new Image();
  dragon.onload = () => {
    if (disposed) return;
    try {
      const sample = document.createElement('canvas');
      sample.width = 120; sample.height = 132;
      const sampler = sample.getContext('2d', {willReadFrequently:true});
      if (!sampler) return;
      sampler.drawImage(dragon, 0, 0, 120, 132);
      const pixels = sampler.getImageData(0, 0, 120, 132).data;
      // Find the actual character bounds, excluding the black portrait margins.
      let left = 120, top = 132, right = 0, bottom = 0;
      for (let y = 0; y < 132; y++) for (let x = 0; x < 120; x++) {
        const i = (y * 120 + x) * 4;
        if (Math.max(pixels[i], pixels[i+1], pixels[i+2]) > 25) {
          left = Math.min(left,x); right = Math.max(right,x); top = Math.min(top,y); bottom = Math.max(bottom,y);
        }
      }
      if (right <= left || bottom <= top) return;
      dragonAspect = (right-left+1) / (bottom-top+1);
      const columns = 56, rows = Math.round(columns / dragonAspect);
      sample.width = columns; sample.height = rows;
      sampler.drawImage(dragon, left / 120 * dragon.width, top / 132 * dragon.height,
        (right-left+1) / 120 * dragon.width, (bottom-top+1) / 132 * dragon.height, 0, 0, columns, rows);
      glyphs = dragonGlyphs(sampler.getImageData(0,0,columns,rows).data,columns,rows);
      refresh();
    } catch { /* Canvas unavailable: keep the existing Core visualization. */ }
  };
  dragon.src = '/brand/draxen-ascii.png';
  let options = { playing: true, active: true, phase: 0, ...initial };
  let width = 0, height = 0, frame = 0, last = 0, clock = 0, visible = true;
  let yaw = 0.3, pointer = 0, disposed = false;
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const animate = () => options.playing && options.active && visible && !document.hidden && !motion.matches;
  function draw(stamp = 0) {
    frame = 0;
    const dt = Math.min((stamp - last) / 1000 || 0, 0.05); last = stamp;
    if (animate()) { clock += dt; yaw += dt * 0.09; }
    ctx.clearRect(0, 0, width, height);
    if (!width || !height) return;
    const scale = Math.min(width * 0.78, height * 0.78);
    const morph = glyphs.length ? morphAmount(clock) : 0;
    const points = mesh.points.map((p, i) => {
      const drift = animate() ? Math.sin(clock * 0.7 + i * 0.73) * 0.005 : 0;
      const q = project({ ...p, x: p.x + drift }, yaw + pointer * 0.08, -0.12, 1);
      return { x: width / 2 + q.x * scale, y: height * 0.49 + q.y * scale, z: q.z };
    });
    const glow = ctx.createRadialGradient(width / 2, height / 2, 0, width / 2, height / 2, scale * 0.55);
    glow.addColorStop(0, options.active ? '#b8152f18' : '#b8152f08'); glow.addColorStop(1, '#b8152f00');
    ctx.fillStyle = glow; ctx.fillRect(0, 0, width, height);
    mesh.edges.forEach(([a, b], index) => {
      const p = points[a], q = points[b];
      const depth = clamp((p.z + 0.4) / 0.8, 0, 1);
      const signal = options.active && mesh.points[a].group === options.phase % 3;
      ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
      ctx.lineWidth = depth > 0.65 ? 0.85 : 0.55;
      ctx.strokeStyle = `rgba(244,45,72,${(0.08 + depth * 0.25 + (signal ? 0.13 : 0)) * (1-morph)})`;
      ctx.stroke();
      if (animate() && morph < .5 && index % 9 === 0) {
        const t = (clock * 0.18 + index * 0.137) % 1;
        ctx.beginPath(); ctx.arc(p.x + (q.x - p.x) * t, p.y + (q.y - p.y) * t, 1.3, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,222,227,${Math.sin(Math.PI * t) * 0.75})`; ctx.fill();
      }
    });
    ctx.globalAlpha = 1 - morph;
    points.map((p, i) => ({ p, i })).sort((a, b) => a.p.z - b.p.z).forEach(({p,i}) => {
      const depth = clamp((p.z + 0.4) / 0.8, 0, 1);
      const bright = i % 11 === 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, 0.8 + depth * (bright ? 1.6 : 0.9), 0, Math.PI * 2);
      ctx.fillStyle = bright ? `rgba(255,228,232,${0.25 + depth * 0.7})` : `rgba(255,44,72,${0.25 + depth * 0.7})`;
      ctx.fill();
    });
    ctx.globalAlpha = 1;
    if (morph > 0) {
      const dragonHeight = Math.min(height * .90, width * .8 / dragonAspect);
      const dragonWidth = dragonHeight * dragonAspect;
      const fontSize = Math.max(2, dragonWidth / 56 * 1.2);
      ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Consolas, monospace`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.globalAlpha = Math.min(1, morph * 2);
      glyphs.forEach((glyph,i) => {
        const origin = points[(i * 137) % points.length];
        // Give the ASCII portrait a shallow curved surface so the silhouette has depth as it turns.
        const relief = Math.max(0, 1 - Math.pow(glyph.x * 2, 2)) * .10;
        const target = project({x:glyph.x * dragonWidth / scale,
          y:glyph.y * dragonHeight / scale, z:relief}, (yaw - .3) * .65,
          -.08 + Math.sin(clock * .25) * .06, 1);
        const position = interpolateGlyph({x:(origin.x-width/2)/scale,y:(origin.y-height*.49)/scale},target,morph,i,clock);
        ctx.fillStyle = glyph.eye ? '#80e9ed' : (i % 7 === 0 ? '#f4ced3' : '#fa536a');
        ctx.fillText(glyph.char, width / 2 + position.x * scale, height * .49 + position.y * scale);
      });
      ctx.globalAlpha = 1;
    }
    if (animate() && !disposed) frame = requestAnimationFrame(draw);
  }
  function refresh() { if (disposed) return; if (frame) cancelAnimationFrame(frame); frame = 0; last = 0; draw(performance.now()); }
  const resize = new ResizeObserver(() => {
    const rect = canvas.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 1.5);
    width = rect.width; height = rect.height;
    canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); refresh();
  });
  resize.observe(canvas);
  const intersection = new IntersectionObserver(entries => { visible = entries[0].isIntersecting; refresh(); });
  intersection.observe(canvas);
  const onPointer = event => { pointer = clamp((event.clientX - canvas.getBoundingClientRect().left) / (width || 1) * 2 - 1, -1, 1); };
  canvas.addEventListener('pointermove', onPointer);
  document.addEventListener('visibilitychange', refresh); motion.addEventListener('change', refresh);
  refresh();
  return {
    update(next) { options = { ...options, ...next }; refresh(); },
    dispose() { disposed = true; dragon.onload = null; cancelAnimationFrame(frame); resize.disconnect(); intersection.disconnect(); canvas.removeEventListener('pointermove', onPointer); document.removeEventListener('visibilitychange', refresh); motion.removeEventListener('change', refresh); }
  };
}
