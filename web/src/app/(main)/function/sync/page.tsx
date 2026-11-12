"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

// Preserve old bookmarks while keeping integration setup in one place.
export default function AssetSyncRedirect() {
  const router = useRouter();
  React.useEffect(() => {
    router.replace("/system/connections");
  }, [router]);
  return (
    <p className="p-6 text-sm text-muted-foreground">
      Abrindo{" "}
      <Link href="/system/connections" className="text-primary underline">
        Conexões
      </Link>
      …
    </p>
  );
}
