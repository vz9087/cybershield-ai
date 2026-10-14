import { useState } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { ShieldAlert, LoaderCircle, ArrowRight } from "lucide-react";

export default function ForgotPasswordPage() {
  const [, navigate] = useLocation();
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  const request = trpc.auth.requestPasswordReset.useMutation({
    onSuccess: () => {
      setSent(true);
      setError("");
      setTimeout(() => navigate(`/verify-otp?email=${encodeURIComponent(email)}`), 1500);
    },
    onError: (err: any) => setError(err?.data?.message ?? err.message ?? "Something went wrong."),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!email.trim()) { setError("Enter your email address."); return; }
    request.mutate({ email: email.trim() });
  }

  return (
    <main className="auth-page">
      <Link className="brand" href="/">
        <span className="brand-mark"><ShieldAlert size={22} /></span>
        <span>CyberShield <b>AI</b></span>
      </Link>
      <section className="auth-card">
        <p className="eyebrow">RESET YOUR PASSWORD</p>
        <h1>Forgot password?</h1>
        <p>Enter the email associated with your account. We'll send a 6-digit code to reset your password.</p>

        {sent ? (
          <div className="notice" style={{ marginTop: 16 }}>
            <strong>If this email exists, we've sent a code.</strong>
            <p style={{ marginTop: 8, fontSize: 12 }}>Redirecting to verification…</p>
          </div>
        ) : (
          <form className="form-stack auth-form" onSubmit={submit}>
            <div>
              <label className="field-label" htmlFor="fp-email">Email address</label>
              <input
                className="input"
                id="fp-email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            {error && <div className="notice" role="alert">{error}</div>}
            <button className="button button-primary button-wide" type="submit" disabled={request.isPending}>
              {request.isPending ? <><LoaderCircle className="spin" size={15} /> Sending code…</> : <>Send reset code <ArrowRight size={14} /></>}
            </button>
          </form>
        )}

        <div className="auth-links">
          <Link className="text-link" href="/login">Back to sign in</Link>
          <Link className="text-link" href="/">Return home</Link>
        </div>
      </section>
    </main>
  );
}