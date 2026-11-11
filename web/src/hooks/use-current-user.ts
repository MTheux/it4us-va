"use client";

import { useEffect, useState } from "react";

import { auth, type CurrentUser } from "@/lib/auth";

const FALLBACK: CurrentUser = { id: "1", name: "IT4US SOC", username: "soc", email: "", avatar: "", role: "soc" };

export function useCurrentUser(): CurrentUser {
  const [user, setUser] = useState<CurrentUser>(FALLBACK);

  useEffect(() => {
    const u = auth.getCurrentUser();
    if (u) setUser(u);
  }, []);

  return user;
}
