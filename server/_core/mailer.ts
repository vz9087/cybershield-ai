import nodemailer, { type Transporter } from "nodemailer";

let _transport: Transporter | null = null;
let _failed = false;

function getTransport(): Transporter | null {
  if (_failed) return null;
  if (_transport) return _transport;

  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : undefined;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = process.env.SMTP_SECURE === "true";

  if (!host || !port || !user || !pass) {
    console.warn("[mailer] SMTP env vars missing — emails will be logged to outbox only.");
    _failed = true;
    return null;
  }

  try {
    _transport = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass },
    });
    console.log("[mailer] SMTP transport configured for", user);
    return _transport;
  } catch (err) {
    console.error("[mailer] failed to configure transport:", err);
    _failed = true;
    return null;
  }
}

export type SendMailInput = {
  to: string | null;
  subject: string;
  text?: string;
  html?: string;
};

export type SendMailResult =
  | { ok: true; messageId: string }
  | { ok: false; reason: string };

export async function sendMail(input: SendMailInput): Promise<SendMailResult> {
  if (!input.to) return { ok: false, reason: "no_recipient" };
  const transport = getTransport();
  if (!transport) return { ok: false, reason: "smtp_not_configured" };

  const from = process.env.SMTP_FROM ?? process.env.SMTP_USER ?? "noreply@cybershield.local";

  try {
    const info = await transport.sendMail({
      from,
      to: input.to,
      subject: input.subject,
      text: input.text,
      html: input.html ?? input.text,
    });
    console.log("[mailer] sent:", input.subject, "→", input.to, "id:", info.messageId);
    return { ok: true, messageId: info.messageId };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error("[mailer] send failed:", reason);
    return { ok: false, reason };
  }
}

export async function verifyMailer(): Promise<boolean> {
  const transport = getTransport();
  if (!transport) return false;
  try {
    await transport.verify();
    return true;
  } catch (err) {
    console.error("[mailer] verify failed:", err);
    return false;
  }
}