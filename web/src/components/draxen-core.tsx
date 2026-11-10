"use client";

// React mount for the Draxen Core canvas visual (projected 3D mesh that morphs
// into the ASCII dragon). The engine is the original vanilla module, mounted on
// a <canvas>; this wrapper only handles its lifecycle. Needs a sized parent —
// the canvas fills it and the engine reads getBoundingClientRect via ResizeObserver.
import { useEffect, useRef } from "react";

export function DraxenCore({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let core: { dispose(): void } | undefined;
    let cancelled = false;
    import("@/lib/draxen-core/draxen-core.js").then(({ mountDraxenCore }) => {
      if (cancelled || !ref.current) return;
      core = mountDraxenCore(ref.current, { active: true, playing: true });
    });
    return () => {
      cancelled = true;
      core?.dispose();
    };
  }, []);

  return <canvas ref={ref} className={className} aria-label="Draxen Core" />;
}
