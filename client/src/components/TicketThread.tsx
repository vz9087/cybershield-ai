import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { MessageSquare, Send, Paperclip, X, LoaderCircle, ChevronDown, ChevronUp, ShieldCheck } from "lucide-react";

function fileToDataUrl(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(new Error("Could not read file"));
        reader.readAsDataURL(file);
    });
}

export default function TicketThread({ ticket }: { ticket: any }) {
    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState("");
    const [attachmentName, setAttachmentName] = useState<string | null>(null);
    const [attachmentData, setAttachmentData] = useState<string | null>(null);
    const [error, setError] = useState("");
    const utils = trpc.useUtils();

    const responses = trpc.tickets.responses.useQuery(
        { ticketId: ticket.id },
        { enabled: open, refetchOnWindowFocus: false }
    );

    const respond = trpc.tickets.respond.useMutation({
        onSuccess: () => {
            setMessage("");
            setAttachmentName(null);
            setAttachmentData(null);
            setError("");
            void utils.tickets.responses.invalidate({ ticketId: ticket.id });
            void utils.tickets.mine.invalidate();
        },
        onError: (err) => setError(err.message),
    });

    async function handleFile(file?: File) {
        if (!file) return;
        setError("");
        if (file.size > 1024 * 1024) { setError("Attachment must be 1 MB or smaller."); return; }
        const allowed = ["image/png", "image/jpeg", "image/webp", "application/pdf", "text/plain", "text/csv"];
        if (!allowed.includes(file.type)) {
            setError("Allowed: PNG, JPEG, WebP, PDF, TXT, CSV.");
            return;
        }
        try {
            const dataUrl = await fileToDataUrl(file);
            setAttachmentData(dataUrl);
            setAttachmentName(file.name);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to read file.");
        }
    }

    function submit() {
        if (message.trim().length === 0) { setError("Message cannot be empty."); return; }
        respond.mutate({
            ticketId: ticket.id,
            message: message.trim(),
            attachmentData: attachmentData ?? undefined,
            attachmentName: attachmentName ?? undefined,
        });
    }

    return (
        <div style={{ marginTop: 12, borderTop: "1px solid #1e2c33", paddingTop: 12 }}>
            <button
                onClick={() => setOpen(v => !v)}
                className="button button-sm button-outline"
                style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            >
                <MessageSquare size={13} />
                {open ? "Hide conversation" : "View conversation / reply"}
                {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            </button>

            {open && (
                <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
                    {responses.isLoading && (
                        <div className="muted" style={{ fontSize: 12 }}>Loading…</div>
                    )}

                    {responses.data && responses.data.length === 0 && (
                        <div className="muted" style={{ fontSize: 12, fontStyle: "italic" }}>
                            No responses yet. Add one below if the admin requested more info.
                        </div>
                    )}

                    {responses.data?.map(r => (
                        <div
                            key={r.id}
                            style={{
                                padding: 10,
                                borderRadius: 8,
                                background: r.authorRole === "admin" ? "#1a2c33" : "#0e1f1c",
                                border: "1px solid #1e2c33",
                            }}
                        >
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                                <strong style={{ fontSize: 11, color: r.authorRole === "admin" ? "#14b8a6" : "#a3e0c7" }}>
                                    {r.authorRole === "admin" ? "Admin" : "You"}
                                </strong>
                                <span style={{ fontSize: 10, color: "#8892b0" }}>
                                    {new Date(r.createdAt).toLocaleString()}
                                </span>
                            </div>
                            <div style={{ fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
                                {r.message}
                            </div>
                            {r.hasAttachment === 1 && r.attachmentName && (
                                <div style={{ marginTop: 6, fontSize: 11, color: "#8892b0" }}>
                                    <Paperclip size={11} style={{ verticalAlign: -1 }} /> {r.attachmentName}
                                </div>
                            )}
                        </div>
                    ))}

                    {/* Reply box — hidden if resolved */}
                    {ticket.status !== "resolved" && (
                        <div style={{ display: "grid", gap: 8 }}>
                            <textarea
                                className="textarea"
                                value={message}
                                onChange={e => setMessage(e.target.value)}
                                placeholder="Add a response…"
                                maxLength={4000}
                                rows={3}
                                style={{ minHeight: 80 }}
                            />
                            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                                <label className="button button-sm button-outline" style={{ cursor: "pointer" }}>
                                    <Paperclip size={12} /> {attachmentName ?? "Attach (≤1 MB)"}
                                    <input
                                        type="file"
                                        hidden
                                        accept="image/png,image/jpeg,image/webp,application/pdf,text/plain,text/csv"
                                        onChange={e => void handleFile(e.target.files?.[0])}
                                    />
                                </label>
                                {attachmentName && (
                                    <button
                                        className="button button-sm button-quiet"
                                        onClick={() => { setAttachmentName(null); setAttachmentData(null); }}
                                    >
                                        <X size={12} /> Remove
                                    </button>
                                )}
                                <button
                                    className="button button-sm button-primary"
                                    onClick={submit}
                                    disabled={respond.isPending}
                                    style={{ marginLeft: "auto" }}
                                >
                                    {respond.isPending ? <LoaderCircle size={12} className="spin" /> : <Send size={12} />}
                                    {respond.isPending ? "Sending…" : "Send"}
                                </button>
                            </div>
                            {error && <div className="notice" role="alert">{error}</div>}
                        </div>
                    )}

                    {ticket.status === "resolved" && (
                        <div className="notice" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <ShieldCheck size={14} />
                            This ticket is resolved. Start a new report if the issue recurs.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}