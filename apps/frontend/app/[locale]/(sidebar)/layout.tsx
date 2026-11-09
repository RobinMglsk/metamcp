"use client";

import {
  FileTerminal,
  History,
  Key,
  Link as LinkIcon,
  Package,
  Search,
  SearchCode,
  Server,
  Settings,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { LanguageSwitcher } from "@/components/language-switcher";
import { LogsStatusIndicator } from "@/components/logs-status-indicator";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { type CurrentUser, useCurrentUser } from "@/hooks/useCurrentUser";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { getLocalizedPath, SupportedLocale } from "@/lib/i18n";
import { useLogsStore } from "@/lib/stores/logs-store";

// Menu items function - now takes locale parameter
const getMenuItems = (t: (key: string) => string, locale: SupportedLocale) => [
  {
    title: t("navigation:exploreMcpServers"),
    url: getLocalizedPath("/search", locale),
    icon: Search,
  },
  {
    title: t("navigation:mcpServers"),
    url: getLocalizedPath("/mcp-servers", locale),
    icon: Server,
  },
  {
    title: t("navigation:metamcpNamespaces"),
    url: getLocalizedPath("/namespaces", locale),
    icon: Package,
  },
  {
    title: t("navigation:metamcpEndpoints"),
    url: getLocalizedPath("/endpoints", locale),
    icon: LinkIcon,
  },
  {
    title: t("navigation:mcpInspector"),
    url: getLocalizedPath("/mcp-inspector", locale),
    icon: SearchCode,
  },
  {
    title: t("navigation:apiKeys"),
    url: getLocalizedPath("/api-keys", locale),
    icon: Key,
  },
  {
    title: t("navigation:auditLogs"),
    url: getLocalizedPath("/audit-logs", locale),
    icon: History,
  },
  {
    title: t("navigation:settings"),
    url: getLocalizedPath("/settings", locale),
    icon: Settings,
  },
];

const navIndex = (n: number) => String(n).padStart(2, "0");

function isActivePath(pathname: string, url: string) {
  return pathname === url || pathname.startsWith(`${url}/`);
}

function LiveLogsMenuItem({ index }: { index: number }) {
  const { t, locale } = useTranslations();
  const pathname = usePathname();
  const url = getLocalizedPath("/live-logs", locale);

  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={isActivePath(pathname, url)}>
        <Link href={url}>
          <span className="w-5 font-mono text-[0.68rem] text-muted-foreground">
            {navIndex(index)}
          </span>
          <FileTerminal />
          <span>{t("navigation:liveLogs")}</span>
          <LogsStatusIndicator />
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

function UserInfoFooter({ user }: { user: CurrentUser | null }) {
  const { t } = useTranslations();

  const handleSignOut = async () => {
    await authClient.signOut();
    window.location.href = "/login";
  };

  return (
    <SidebarFooter>
      <div className="flex flex-col gap-3 border-t p-3">
        {user && (
          <div className="flex flex-col gap-0.5 font-mono text-xs">
            <span className="tag-label">session</span>
            <span className="truncate text-sidebar-foreground">
              <span className="text-signal">&gt;</span>{" "}
              {user.name || user.email}
            </span>
            <span className="truncate text-muted-foreground">{user.email}</span>
          </div>
        )}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <ThemeToggle />
          </div>
          <p className="font-mono text-[0.68rem] text-muted-foreground">
            v2.5-ai-dev
          </p>
        </div>
        {user && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleSignOut}
            className="w-full"
          >
            {t("auth:signOut")}
          </Button>
        )}
      </div>
    </SidebarFooter>
  );
}

function Clock() {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <time
      className="hidden font-mono text-xs tabular-nums text-muted-foreground sm:block"
      suppressHydrationWarning
    >
      {now ? now.toLocaleTimeString([], { hour12: false }) : "--:--:--"}
    </time>
  );
}

function PathCrumb({ locale }: { locale: SupportedLocale }) {
  const pathname = usePathname();
  const segments = pathname
    .split("/")
    .filter(Boolean)
    .filter((seg, i) => !(i === 0 && seg === locale));

  return (
    <nav
      aria-label="Breadcrumb"
      className="min-w-0 truncate font-mono text-xs text-muted-foreground"
    >
      <span className="text-signal">~/</span>
      <span>metamcp</span>
      {segments.map((seg, i) => (
        <span key={`${seg}-${i}`}>
          <span className="px-0.5">/</span>
          <span
            className={
              i === segments.length - 1 ? "cursor text-foreground" : undefined
            }
          >
            {seg}
          </span>
        </span>
      ))}
    </nav>
  );
}

export default function SidebarLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { t, locale } = useTranslations();
  const items = getMenuItems(t, locale);
  const { user, isAdmin } = useCurrentUser();
  const pathname = usePathname();

  // Live logs are admin-only: once we know the user is an admin, (re)start the
  // poller, which stays off for everyone else.
  useEffect(() => {
    if (isAdmin) useLogsStore.getState().enableForAdmin();
  }, [isAdmin]);

  return (
    <SidebarProvider>
      <Sidebar>
        <SidebarHeader className="border-b px-4 py-4">
          <Link
            href={getLocalizedPath("/", locale)}
            className="flex items-center gap-3"
          >
            <span
              aria-hidden
              className="grid h-8 w-8 place-items-center border border-signal/60 font-mono text-signal"
            >
              [■]
            </span>
            <span className="cursor font-mono text-lg font-semibold tracking-tight">
              metamcp
            </span>
          </Link>
        </SidebarHeader>

        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel className="tag-label h-auto px-2 py-2">
              {t("navigation:application")}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {items.map((item, i) => (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActivePath(pathname, item.url)}
                    >
                      <Link href={item.url}>
                        <span className="w-5 font-mono text-[0.68rem] text-muted-foreground">
                          {navIndex(i + 1)}
                        </span>
                        <item.icon />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
                {isAdmin && <LiveLogsMenuItem index={items.length + 1} />}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>

        <UserInfoFooter user={user} />
      </Sidebar>
      <SidebarInset>
        <header className="sticky top-0 z-10 flex h-12 shrink-0 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1 cursor-pointer" />
          <Separator orientation="vertical" className="mr-2 h-4" />
          <PathCrumb locale={locale} />
          <div className="ml-auto flex items-center gap-3">
            <Clock />
          </div>
        </header>
        <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  );
}
