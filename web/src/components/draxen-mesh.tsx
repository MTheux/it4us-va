// Draxen Core network art — a lightweight, dependency-free SVG port of the
// landing page's 3D "flow" visualization. The mesh is deterministic (seeded),
// so it is computed once at module load and rendered as a static SVG; no 3D,
// no animation libraries, safe for the offline static export.

type Pt = { x: number; y: number; z: number; group: number };

const rand = (index: number, salt: number) => {
  const n = Math.sin(index * 127 + salt * 311) * 43758.5453;
  return n - Math.floor(n);
};

function makeMesh(count: number) {
  const points: Pt[] = Array.from({ length: count }, (_, i) => {
    const a = rand(i, 1) * Math.PI * 2;
    const v = rand(i, 2) * 2 - 1;
    const r = Math.cbrt(rand(i, 3));
    const ring = Math.sqrt(1 - v * v);
    const x = Math.cos(a) * ring * r;
    const y = v * r;
    const z = Math.sin(a) * ring * r;
    return {
      x: x * 0.53 + 0.05 * Math.sin(y * 5 + z * 4),
      y: y * 0.53 + 0.05 * Math.sin(x * 6 - z * 3),
      z: z * 0.42,
      group: Math.floor(rand(i, 4) * 3),
    };
  });
  const edges: Array<[number, number]> = [];
  for (let i = 0; i < count; i++) {
    const p = points[i];
    const nearest = points
      .map((q, j) => ({ j, d: (p.x - q.x) ** 2 + (p.y - q.y) ** 2 + (p.z - q.z) ** 2 }))
      .filter((v) => v.j !== i)
      .sort((x, y) => x.d - y.d);
    for (const { j } of nearest.slice(0, 4)) if (i < j) edges.push([i, j]);
  }
  return { points, edges };
}

function project(point: Pt, yaw: number, pitch: number, zoom: number) {
  const x = point.x * Math.cos(yaw) + point.z * Math.sin(yaw);
  const z = -point.x * Math.sin(yaw) + point.z * Math.cos(yaw);
  const y = point.y * Math.cos(pitch) - z * Math.sin(pitch);
  const depth = point.y * Math.sin(pitch) + z * Math.cos(pitch);
  const perspective = 2.7 / (2.7 - depth);
  return { x: x * perspective * zoom, y: y * perspective * zoom, z: depth };
}

const MESH = makeMesh(132);
const PROJECTED = MESH.points.map((p) => project(p, 0.42, 0.12, 1));

export function DraxenMesh({ className }: { className?: string }) {
  return (
    <svg
      className={className ?? "draxen-mesh"}
      viewBox="-1 -1 2 2"
      role="img"
      aria-label="Visualização do Draxen Core"
    >
      <g className="mesh-edges" fill="none">
        {MESH.edges.map(([a, b], i) => (
          <path key={i} className="mesh-edge" d={`M${PROJECTED[a].x} ${PROJECTED[a].y}L${PROJECTED[b].x} ${PROJECTED[b].y}`} />
        ))}
      </g>
      {PROJECTED.map((p, i) => (
        <circle
          key={i}
          className={MESH.points[i].group === 0 ? "mesh-node-hot" : "mesh-node"}
          cx={p.x}
          cy={p.y}
          r={MESH.points[i].group === 0 ? 0.0075 : 0.0048}
        />
      ))}
    </svg>
  );
}
