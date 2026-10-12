import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/_core/hooks/useAuth";
import AdminPage from "@/pages/AdminPage";
import AwarenessPage from "@/pages/AwarenessPage";
import Dashboard from "@/pages/Dashboard";
import HistoryPage from "@/pages/HistoryPage";
import Home from "@/pages/Home";
import NotificationsPage from "@/pages/NotificationsPage";
import ProfilePage from "@/pages/ProfilePage";
import ScannerPage from "@/pages/ScannerPage";
import Shell from "@/pages/Shell";
import NotFound from "@/pages/NotFound";
import { LoaderCircle, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Route, Switch, Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { ThemeProvider } from "./contexts/ThemeContext";
import ErrorBoundary from "./components/ErrorBoundary";

function AuthPage({ admin = false, register = false }: { admin?: boolean; register?: boolean }) {
  const { user, loading } = useAuth();
  const [, navigate] = useLocation();
  const utils = trpc.useUtils();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const login = trpc.auth.login.useMutation({
    onSuccess: async ({ user: account }) => {
      setError("");
      await utils.auth.me.invalidate();
      navigate(account.role === "admin" ? "/admin/dashboard" : "/dashboard");
    },
    onError: result => setError(result.message),
  });
  const createAccount = trpc.auth.register.useMutation({
    onSuccess: async ({ user: account }) => {
      setError("");
      toast.success("Welcome to CyberShield AI", { description: "Your account is ready. Review the evidence behind each scan." });
      await utils.auth.me.invalidate();
      navigate(account.role === "admin" ? "/admin/dashboard" : "/dashboard");
    },
    onError: result => setError(result.message),
  });
  useEffect(() => {
    if (user?.role === "admin") navigate("/admin/dashboard");
    else if (user && !admin) navigate("/dashboard");
    else if (user && admin) setError("This signed-in account does not have administrator access. Sign in with an authorized admin account.");
  }, [user, admin, navigate]);

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    if (register) {
      if (password !== confirmPassword) { setError("Passwords do not match."); return; }
      if (!/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
        setError("Password must contain at least one uppercase letter, one number, and one special character.");
        return;
      }
      createAccount.mutate({ name, email, password, confirmPassword });
    } else {
      login.mutate({ email, password, mode: admin ? "admin" : "user" });
    }
  };
  const busy = login.isPending || createAccount.isPending;

  return <main className="auth-page">
    <Link className="brand" href="/"><span className="brand-mark"><ShieldAlert size={22} /></span><span>CyberShield <b>AI</b></span></Link>
    <section className="auth-card">
      <p className="eyebrow">{register ? "CREATE YOUR ACCOUNT" : admin ? "SECURE ADMIN ACCESS" : "YOUR DIGITAL SAFETY DESK"}</p>
      <h1>{register ? "Create your safety workspace" : admin ? "Administrator sign in" : "Sign in to CyberShield"}</h1>
      <p>{register ? "Create a password-protected profile to save scans and reports." : "Use your email and password. The server checks your account role after authentication."}</p>
      {!register && <div className="auth-mode-switch"><Link href="/login" className={!admin ? "active" : ""}>Login as User</Link><Link href="/admin/login" className={admin ? "active" : ""}>Login as Admin</Link></div>}
      <form className="form-stack auth-form" onSubmit={submit}>
        {register && <div><label className="field-label" htmlFor="signup-name">Full name</label><input className="input" id="signup-name" type="text" autoComplete="name" minLength={2} maxLength={120} value={name} onChange={event => setName(event.target.value)} required /></div>}
        <div><label className="field-label" htmlFor="auth-email">Email</label><input className="input" id="auth-email" type="email" autoComplete="email" maxLength={320} value={email} onChange={event => setEmail(event.target.value)} required /></div>
        <div><label className="field-label" htmlFor="auth-password">Password</label><input className="input" id="auth-password" type="password" autoComplete={register ? "new-password" : "current-password"} maxLength={128} value={password} onChange={event => setPassword(event.target.value)} required />{register && <p className="helper">Must contain at least one uppercase letter (A–Z), one number (0–9), and one special character (e.g. @, #, $, !).</p>}</div>
        {register && <div><label className="field-label" htmlFor="auth-confirm-password">Confirm password</label><input className="input" id="auth-confirm-password" type="password" autoComplete="new-password" maxLength={128} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} required /></div>}
        {error && <div className="notice" role="alert">{error}</div>}
        <button className="button button-primary button-wide" type="submit" disabled={busy || loading}>{busy ? <><LoaderCircle className="spin" size={15} /> Please wait…</> : register ? "Create account" : admin ? "Login as Admin" : "Login as User"}</button>
      </form>
      <div className="auth-note"><ShieldAlert size={16} /><span>Choosing administrator sign-in does not grant privileges. Admin access is verified against the role stored in the database. Everyone else remains a user.</span></div>
      <div className="auth-links">{register ? <span>Already have an account? <Link className="text-link" href="/login">Sign in</Link></span> : <span>New to CyberShield? <Link className="text-link" href="/register">Create an account</Link></span>}<Link className="text-link" href="/">Return home</Link></div>
    </section>
  </main>;
}

function Protected({ children, admin = false }: { children: React.ReactNode; admin?: boolean }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="center-state"><LoaderCircle className="spin" /> Loading secure workspace…</div>;
  if (!user) return <AuthPage admin={admin} />;
  if (admin && user.role !== "admin") return <div className="center-state"><ShieldAlert size={22} /><div><h2>Admin access required</h2><p>Your signed-in account does not have the administrator role.</p><Link className="text-link" href="/dashboard">Return to your dashboard</Link></div></div>;
  return <Shell admin={admin}>{children}</Shell>;
}
function UserRoute({ children }: { children: React.ReactNode }) { return <Protected>{children}</Protected>; }
function AdminRoute({ tab }: { tab: string }) { return <Protected admin><AdminPage tab={tab} /></Protected>; }

function Router() {
  return <Switch>
    <Route path="/" component={Home} />
    <Route path="/login" component={() => <AuthPage />} />
    <Route path="/admin/login" component={() => <AuthPage admin />} />
    <Route path="/register" component={() => <AuthPage register />} />
    <Route path="/dashboard">{() => <UserRoute><Dashboard /></UserRoute>}</Route>
    <Route path="/scanner/:type">{params => <UserRoute><ScannerPage type={params.type} /></UserRoute>}</Route>
    <Route path="/history">{() => <UserRoute><HistoryPage mode="history" /></UserRoute>}</Route>
    <Route path="/reports">{() => <UserRoute><HistoryPage mode="reports" /></UserRoute>}</Route>
    <Route path="/tickets">{() => <UserRoute><HistoryPage mode="tickets" /></UserRoute>}</Route>
    <Route path="/notifications">{() => <UserRoute><NotificationsPage /></UserRoute>}</Route>
    <Route path="/awareness">{() => <UserRoute><AwarenessPage /></UserRoute>}</Route>
    <Route path="/profile">{() => <UserRoute><ProfilePage /></UserRoute>}</Route>
    <Route path="/settings">{() => <UserRoute><ProfilePage settings /></UserRoute>}</Route>
    <Route path="/scan/result/:id">{params => <UserRoute><HistoryPage mode="result" scanId={params.id} /></UserRoute>}</Route>
    <Route path="/admin/dashboard">{() => <AdminRoute tab="dashboard" />}</Route>
    <Route path="/admin/scans">{() => <AdminRoute tab="scans" />}</Route>
    <Route path="/admin/users">{() => <AdminRoute tab="users" />}</Route>
    <Route path="/admin/tickets">{() => <AdminRoute tab="tickets" />}</Route>
    <Route path="/admin/threats">{() => <AdminRoute tab="threats" />}</Route>
    <Route path="/admin/analytics">{() => <AdminRoute tab="analytics" />}</Route>
    <Route path="/admin/logs">{() => <AdminRoute tab="logs" />}</Route>
    <Route path="/404" component={NotFound} />
    <Route component={NotFound} />
  </Switch>;
}

export default function App() {
  return <ErrorBoundary><ThemeProvider defaultTheme="dark"><TooltipProvider><Toaster /><Router /></TooltipProvider></ThemeProvider></ErrorBoundary>;
}
