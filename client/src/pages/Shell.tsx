import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Activity, AtSign, Bell, BookOpenCheck, ChevronDown, FileClock, FileText, Globe2, LayoutDashboard, Link2, LogOut, Menu, ScanLine, Settings, ShieldAlert, ShieldCheck, Users, X } from "lucide-react";
import { useState } from "react";
import { Link, useLocation } from "wouter";

const userNav = [
  { label: "Workspace", items: [{ href: "/dashboard", label: "Overview", icon: LayoutDashboard }, { href: "/scanner/url", label: "Scan center", icon: ScanLine }] },
  { label: "PROTECTION", items: [{ href: "/history", label: "Scan history", icon: FileClock }, { href: "/tickets", label: "Threat reports", icon: ShieldAlert }, { href: "/notifications", label: "Notifications", icon: Bell }, { href: "/awareness", label: "Safety learning", icon: BookOpenCheck }] },
  { label: "ACCOUNT", items: [{ href: "/profile", label: "Profile", icon: Users }, { href: "/settings", label: "Settings", icon: Settings }] },
];
const adminNav = [
  { label: "OPERATIONS", items: [{ href: "/admin/dashboard", label: "Command center", icon: LayoutDashboard }, { href: "/admin/scans", label: "Scan activity", icon: FileClock }, { href: "/admin/tickets", label: "Threat queue", icon: ShieldAlert }, { href: "/admin/threats", label: "Intelligence", icon: Globe2 }] },
  { label: "OVERSIGHT", items: [{ href: "/admin/users", label: "User management", icon: Users }, { href: "/admin/analytics", label: "Analytics", icon: Activity }, { href: "/admin/logs", label: "Audit log", icon: FileText }] },
];
export default function Shell({ children, admin = false }: { children: React.ReactNode; admin?: boolean }) {
  const { user, logout } = useAuth(); const [location] = useLocation(); const [open, setOpen] = useState(false);
  const { data: notifications = [] } = trpc.notifications.list.useQuery(undefined, { enabled: !!user, refetchInterval: 60_000 });
  const unread = notifications.filter(n => !n.readStatus).length;
  const sections = admin ? adminNav : userNav;
  return <div className={`app-shell ${open ? "nav-open" : ""}`}>
    <aside className="sidebar"><div className="side-brand-row"><Link className="brand" href="/"><span className="brand-mark"><ShieldAlert size={20}/></span><span>CyberShield <b>AI</b></span></Link><button className="icon-btn mobile-close" aria-label="Close menu" onClick={() => setOpen(false)}><X size={18}/></button></div><div className="workspace-badge"><span className={`workspace-dot ${admin ? "admin-dot" : ""}`}/><span>{admin ? "ADMIN CONSOLE" : "PERSONAL WORKSPACE"}</span><ChevronDown size={14}/></div><nav className="side-nav">{sections.map(section => <div className="nav-section" key={section.label}><div className="nav-label">{section.label}</div>{section.items.map(item => <Link key={item.href} href={item.href} onClick={() => setOpen(false)} className={`nav-link ${location === item.href || (item.href === "/scanner/url" && location.startsWith("/scanner/")) ? "active" : ""}`}><item.icon size={17}/><span>{item.label}</span>{item.href === "/notifications" && unread > 0 && <i className="nav-count">{unread}</i>}</Link>)}</div>)}</nav><div className="sidebar-bottom"><div className="sidebar-status"><span className="status-dot"/><span><b>Protection engine</b><small>Ready for analysis</small></span></div><button className="nav-link signout" onClick={() => void logout()}><LogOut size={16}/> Sign out</button></div></aside>
    <div className="shell-backdrop" onClick={() => setOpen(false)}/><main className="workspace-main"><header className="topbar"><button className="icon-btn mobile-open" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={19}/></button><div className="breadcrumb"><span>{admin ? "Administration" : "Workspace"}</span><span>/</span><b>{admin ? (location.split("/").pop() ?? "dashboard").replaceAll("-", " ") : (location.startsWith("/scanner/") ? "Scan center" : location.substring(1).replaceAll("/", " · ").replaceAll("-", " ") || "Overview")}</b></div><div className="topbar-right"><Link className="topbar-bell" href="/notifications" aria-label="Notifications"><Bell size={18}/>{unread > 0 && <i/>}</Link><div className="top-user"><span className="user-avatar">{(user?.name || user?.email || "U").slice(0,1).toUpperCase()}</span><span className="top-user-name">{user?.name || "Account"}<small>{admin ? "Administrator" : "Protected account"}</small></span></div></div></header><div className="page-content">{children}</div></main>
    <div className="mobile-nav-panel" aria-hidden={!open}/>
  </div>;
}
