export const clamp = (n, min, max) => Math.min(max, Math.max(min, n));
const random = (index, salt) => {
  const n = Math.sin(index * 127 + salt * 311) * 43758.5453;
  return n - Math.floor(n);
};
export function makeMesh(count = 360) {
  const points = Array.from({ length: count }, (_, i) => {
    const a = random(i, 1) * Math.PI * 2,
      v = random(i, 2) * 2 - 1,
      r = Math.cbrt(random(i, 3)),
      ring = Math.sqrt(1 - v * v);
    const x = Math.cos(a) * ring * r,
      y = v * r,
      z = Math.sin(a) * ring * r;
    return {
      // Keep the projected cloud close to circular at the neutral camera angle.
      // Small, equal-amplitude distortions preserve an organic outline without
      // turning the cortex into the wide, flattened silhouette it used to have.
      x: x * 0.53 + 0.05 * Math.sin(y * 5 + z * 4),
      y: y * 0.53 + 0.05 * Math.sin(x * 6 - z * 3),
      z: z * 0.42,
      group: Math.floor(random(i, 4) * 3),
    };
  });
  const edges = [];
  for (let i = 0; i < count; i++) {
    const p = points[i];
    const distances = points
      .map((q, j) => ({
        j,
        d: (p.x - q.x) ** 2 + (p.y - q.y) ** 2 + (p.z - q.z) ** 2,
      }))
      .filter((v) => v.j !== i)
      .sort((a, b) => a.d - b.d);
    for (const { j } of distances.slice(0, 5)) if (i < j) edges.push([i, j]);
  }
  for (let i = 0; i < count; i += 17) {
    const j = (i * 73 + 91) % count;
    if (i !== j) edges.push([i, j]);
  }
  return { points, edges };
}
export function project(point, yaw, pitch, zoom) {
  const x = point.x * Math.cos(yaw) + point.z * Math.sin(yaw),
    z = -point.x * Math.sin(yaw) + point.z * Math.cos(yaw);
  const y = point.y * Math.cos(pitch) - z * Math.sin(pitch),
    depth = point.y * Math.sin(pitch) + z * Math.cos(pitch);
  const perspective = 2.7 / (2.7 - depth);
  return { x: x * perspective * zoom, y: y * perspective * zoom, z: depth };
}
export function zoomBy(current, delta) {
  return clamp(
    current * Math.exp(-clamp(delta, -250, 250) * 0.0018),
    0.45,
    2.8,
  );
}
