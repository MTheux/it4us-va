"use client";

// React mount for the IT4US VA Core canvas visual (projected 3D mesh that morphs
// into the ASCII dragon). The engine is the original vanilla module, mounted on
// a <canvas>; this wrapper only handles its lifecycle. Needs a sized parent —
// the canvas fills it and the engine reads getBoundingClientRect via ResizeObserver.
import { useEffect, useRef } from "react";

export function It4usCore({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let core: { dispose(): void } | undefined;
    let cancelled = false;
    import("@/lib/it4us-core/it4us-core.js").then(({ mountIt4usCore }) => {
      if (cancelled || !ref.current) return;
      core = mountIt4usCore(ref.current, { active: true, playing: true });
    });
    return () => {
      cancelled = true;
      core?.dispose();
    };
  }, []);

  return <canvas ref={ref} className={className} aria-label="IT4US VA Core" />;
}
