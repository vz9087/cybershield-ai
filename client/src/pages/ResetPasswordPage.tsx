import { useState } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { ShieldAlert, ShieldCheck, LoaderCircle, ArrowRight } from "lucide-react";

export default function ResetPasswordPage() {
  const params = new URLSearchParams(window.location.search);
  const email = params.get("email") ?? "";
  const token = params.get("token") ?? "";
  const [, navigate] = useLocation();

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");

  const reset = trpc.auth.resetPassword.useMutation({
    onSuccess: () => {
      navigate("/login?reset=success");
    },
    onError: (err: any) => setError(err?.data?.message ?? err.message ?? "Could not reset password."),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) { setError("Passwords do not match."); return; }
    if (!/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword) || !/[^A-Za-z0-9]/.test(newPassword)) {
      setError("Password must contain at least one uppercase letter, one number, and one special character.");
      return;
    }
    reset.mutate({ email, resetToken: token, newPassword, confirmPassword });
  }

  if (!email || !token) {
    return (
      <main className="auth-page">
        <Link className="brand" href="/">
          <span className="brand-mark"><ShieldAlert size={22} /></span>
          <span>CyberShield <b>AI</b></span>
        </Link>
        <section className="auth-card">
          <p className="eyebrow">INVALID LINK</p>
          <h1>Reset session expired</h1>
          <p>Start the password reset process again.</p>
          <Link className="button button-primary button-wide" href="/forgot-password">
            Reset password <ArrowRight size={14} />
          </Link>
        </section>
      </main>
    );
  }

  return (
    <main className="auth-page">
      <Link className="brand" href="/">
        <span className="brand-mark"><ShieldAlert size={22} /></span>
        <span>CyberShield <b>AI</b></span>
      </Link>
      <section className="auth-card">
        <p className="eyebrow">SET NEW PASSWORD</p>
        <h1>Choose a new password</h1>
        <p>Creating a new password for <strong>{email}</strong>.</p>

        <form className="form-stack auth-form" onSubmit={submit}>
          <div>
            <label className="field-label" htmlFor="new-password">New password</label>
            <input
              className="input"
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              maxLength={128}
              required
              autoFocus
            />
            <p className="helper">At least one uppercase letter, one number, one special character.</p>
          </div>
          <div>
            <label className="field-label" htmlFor="confirm-new-password">Confirm password</label>
            <input
              className="input"
              id="confirm-new-password"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              maxLength={128}
              required
            />
          </div>

          {error && <div className="notice" role="alert">{error}</div>}

          <button className="button button-primary button-wide" type="submit" disabled={reset.isPending}>
            {reset.isPending ? <><LoaderCircle className="spin" size={15} /> Resetting…</> : <><ShieldCheck size={15} /> Reset password</>}
          </button>
        </form>

        <div className="auth-links">
          <Link className="text-link" href="/login">Back to sign in</Link>
          <Link className="text-link" href="/">Return home</Link>
        </div>
      </section>
    </main>
  );
}