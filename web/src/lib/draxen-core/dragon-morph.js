// Deterministic visual morph, independent of execution status or engine telemetry.
export function morphAmount(seconds) {
  const phase = ((seconds % 16) + 16) % 16;
  const ease = t => t * t * (3 - 2 * t);
  if (phase < 4 || phase >= 12) return 0;
  if (phase < 6) return ease((phase - 4) / 2);
  if (phase < 10) return 1;
  return 1 - ease((phase - 10) / 2);
}

export function dragonGlyphs(pixels, width, height) {
  const glyphs = [];
  const symbols = '.:+x08#';
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const offset = (y * width + x) * 4;
      const red = pixels[offset], green = pixels[offset + 1], blue = pixels[offset + 2];
      const light = Math.max(red, green, blue);
      if (light < 25 || pixels[offset + 3] < 30) continue;
      glyphs.push({x: (x + .5) / width - .5, y: (y + .5) / height - .5,
        char: symbols[Math.min(symbols.length - 1, Math.floor(light / 256 * symbols.length))],
        eye: green > red * 1.3 && blue > red * 1.3});
    }
  }
  return glyphs;
}

export function interpolateGlyph(origin, target, amount, seed, seconds) {
  // A small arc opens the mesh, then disappears as the dragon becomes stable.
  const arc = Math.sin(amount * Math.PI) * .08;
  return {x: origin.x * (1 - amount) + target.x * amount + Math.sin(seed * 2.399 + seconds * .35) * arc,
    y: origin.y * (1 - amount) + target.y * amount + Math.cos(seed * 1.73 + seconds * .25) * arc};
}
