import {
  Bug,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  PlugZap,
  ScanSearch,
  Sparkles,
  Target,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "Operação VA",
    items: [
      { id: "dashboard", title: "Painel", url: "/dashboard", icon: LayoutDashboard },
      { id: "tasks", title: "Tarefas", url: "/function/tasks", icon: Target },
      { id: "va-runs", title: "Execuções VA", url: "/function/va-runs", icon: ScanSearch },
      { id: "assets", title: "Ativos", url: "/function/assets", icon: Network },
      { id: "findings", title: "Achados", url: "/function/findings", icon: Bug },
      { id: "chat", title: "Chat", url: "/chat", icon: MessageSquare },
      { id: "sync", title: "Sincronização de Ativos", url: "/function/sync", icon: FolderSync },
    ],
  },
  {
    id: 2,
    label: "Conhecimento",
    items: [
      { id: "skills", title: "Skills", url: "/system/skills", icon: Sparkles },
      { id: "connections", title: "Conexões", url: "/system/connections", icon: PlugZap },
    ],
  },
];
