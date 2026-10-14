import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { ShieldAlert, LoaderCircle, ArrowRight, RefreshCw } from "lucide-react";

export default function VerifyOtpPage() {
  const [, navigate] = useLocation();
  const params = new URLSearchParams(window.location.search);
  const initialEmail = params.get("email") ?? "";

  const [email] = useState(initialEmail);
  const [otp, setOtp] = useState("");
  const [error, setError] = useState("");
  const [secondsLeft, setSecondsLeft] = useState(120);
  const [resendCooldown, setResendCooldown] = useState(30);
  const [resendCount, setResendCount] = useState(0);

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const t = setInterval(() => setSecondsLeft(s => s - 1), 1000);
    return () => clearInterval(t);
  }, [secondsLeft]);

  useEffect(() => {
    if (resendCooldown <= 0) return;
    const t = setInterval(() => setResendCooldown(s => s - 1), 1000);
    return () => clearInterval(t);
  }, [resendCooldown]);

  const verify = trpc.auth.verifyResetOtp.useMutation({
    onSuccess: (data) => {
      navigate(`/reset-password?email=${encodeURIComponent(email)}&token=${data.resetToken}`);
    },
    onError: (err: any) => setError(err?.data?.message ?? err.message ?? "Invalid code."),
  });

  const resend = trpc.auth.requestPasswordReset.useMutation({
    onSuccess: () => {
      setResendCount(c => c + 1);
      setResendCooldown(30);
      setSecondsLeft(120);
      setError("");
    },
    onError: (err: any) => setError(err?.data?.message ?? err.message ?? "Could not resend."),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!/^\d{6}$/.test(otp)) { setError("Enter the 6-digit code."); return; }
    verify.mutate({ email, otp });
  }

  function handleResend() {
    if (resendCooldown > 0 || resendCount >= 3) return;
    resend.mutate({ email });
  }

  const mm = String(Math.floor(secondsLeft / 60)).padStart(2, "0");
  const ss = String(secondsLeft % 60).padStart(2, "0");

  return (
    <main className="auth-page">
      <Link className="brand" href="/">
        <span className="brand-mark"><ShieldAlert size={22} /></span>
        <span>CyberShield <b>AI</b></span>
      </Link>
      <section className="auth-card">
        <p className="eyebrow">CHECK YOUR EMAIL</p>
        <h1>Enter the 6-digit code</h1>
        <p>We sent a code to <strong>{email}</strong>. It expires in 2 minutes.</p>

        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, color: secondsLeft > 30 ? "#8892b0" : "#e57373", fontSize: 13 }}>
          <span style={{ fontWeight: 700 }}>Expires in {mm}:{ss}</span>
        </div>

        <form className="form-stack auth-form" onSubmit={submit}>
          <div>
            <label className="field-label" htmlFor="otp">Verification code</label>
            <input
              className="input"
              id="otp"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              style={{ fontSize: 24, letterSpacing: 8, textAlign: "center", fontFamily: "monospace" }}
              required
              autoFocus
            />
          </div>

          {error && <div className="notice" role="alert">{error}</div>}

          <button className="button button-primary button-wide" type="submit" disabled={verify.isPending || secondsLeft <= 0}>
            {verify.isPending ? <><LoaderCircle className="spin" size={15} /> Verifying…</> : <>Verify code <ArrowRight size={14} /></>}
          </button>
        </form>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 16 }}>
          <button
            className="button button-quiet button-sm"
            onClick={handleResend}
            disabled={resendCooldown > 0 || resendCount >= 3 || resend.isPending}
          >
            <RefreshCw size={12} />
            {resendCount >= 3
              ? "Resend limit reached"
              : resendCooldown > 0
                ? `Resend in ${resendCooldown}s`
                : "Resend code"}
          </button>
          <span style={{ fontSize: 11, color: "#8892b0" }}>{resendCount}/3 resends used</span>
        </div>

        <div className="auth-links" style={{ marginTop: 16 }}>
          <Link className="text-link" href="/forgot-password">Use a different email</Link>
          <Link className="text-link" href="/login">Back to sign in</Link>
        </div>
      </section>
    </main>
  );
}