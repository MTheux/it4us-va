"use client";

import { useState } from "react";

import { KeyRound, LogOut } from "lucide-react";

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { auth } from "@/lib/auth";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { getInitials } from "@/lib/utils";

import { ChangePasswordDialog } from "./change-password-dialog";

export function AccountSwitcher({
  user,
}: {
  readonly user: {
    readonly id: string;
    readonly name: string;
    readonly email: string;
    readonly avatar: string;
    readonly role: string;
  };
}) {
  const [pwOpen, setPwOpen] = useState(false);

  async function handleLogout() {
    try { await api.logout(); } catch { toast.error("Não foi possível encerrar a sessão."); return; }
    auth.clearToken();
    window.location.href = "/login";
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Avatar className="size-8 rounded-lg">
            <AvatarImage src={user.avatar || undefined} alt={user.name} />
            <AvatarFallback>{getInitials(user.name)}</AvatarFallback>
          </Avatar>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="min-w-56 space-y-1 rounded-lg" side="bottom" align="end" sideOffset={4}>
          <div className="px-2 py-1.5 text-sm font-medium">{user.name}</div>
          <DropdownMenuSeparator />
          {!auth.isSSO() && <DropdownMenuItem onClick={() => setPwOpen(true)}>
            <KeyRound />
            Change password
          </DropdownMenuItem>}
          <DropdownMenuItem onClick={() => void handleLogout()} className="text-destructive focus:text-destructive">
            <LogOut />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {!auth.isSSO() && <ChangePasswordDialog open={pwOpen} onOpenChange={setPwOpen} />}
    </>
  );
}
