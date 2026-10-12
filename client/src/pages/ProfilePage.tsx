import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { useEffect, useState } from "react";
import { ShieldCheck, Palette, UserRound, Settings2, Check, Download, Trash2, Globe, Bell, Mail, Code2, ChevronDown } from "lucide-react";

import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import * as XLSX from "xlsx";

const themes = [
  { id: "midnight-cyan", label: "Cyber Midnight (Dark)", note: "Deep slate cybersecurity surfaces with bright cyan signals." },
  { id: "graphite-violet", label: "Graphite Violet (Dark)", note: "Soft charcoal surfaces with violet threat indicators." },
  { id: "light-teal", label: "Light Teal", note: "Clean white surfaces with deep teal actions." }
];

const tz = Intl.DateTimeFormat().resolvedOptions().timeZone; // "Asia/Kolkata"
const offset = -new Date().getTimezoneOffset() / 60;
const tzAbbr = tz.split("/").pop()?.replace(/_/g, " ") ?? tz; // "Kolkata"
const timezoneLabel = `${tzAbbr} (GMT${offset >= 0 ? "+" : ""}${offset % 1 === 0 ? offset : offset.toFixed(1)})`;
// Result: "Kolkata (GMT+5.5)"

export default function ProfilePage({ settings = false }: { settings?: boolean }) {
  const { user } = useAuth();
  const [theme, setTheme] = useState("midnight-cyan");
  const [exportStatus, setExportStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [deleteStatus, setDeleteStatus] = useState<"idle" | "loading" | "error">("idle");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);

  const [prefs, setPrefs] = useState({
    emailHighRisk: true,
    emailTicketUpdates: true,
    emailAdminAssignments: true,
    emailWeeklySummary: false,
  });

  useEffect(() => {
    try {
      const saved = localStorage.getItem("cybershield-prefs");
      if (saved) setPrefs(JSON.parse(saved));
    } catch { }
  }, []);

  function togglePref(key: keyof typeof prefs) {
    const next = { ...prefs, [key]: !prefs[key] };
    setPrefs(next);
    localStorage.setItem("cybershield-prefs", JSON.stringify(next));
  }

  // Helper: trigger browser download of a Blob
  function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.style.display = "none";
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 200);
  }

  // Helper: convert export data to flat rows for PDF/Excel tables
  function buildExportRows(data: any) {
    const rows: Array<{ section: string; field: string; value: string }> = [];

    // Account
    if (data.account) {
      Object.entries(data.account).forEach(([k, v]) => {
        rows.push({ section: "Account", field: k, value: String(v ?? "—") });
      });
    }

    // Scans
    (data.scans ?? []).forEach((s: any) => {
      rows.push({
        section: "Scan",
        field: `${s.scanType ?? "?"} • ${s.riskLevel ?? "?"}`,
        value: `score=${s.riskScore ?? "?"} | ${s.inputReference ?? ""}`.slice(0, 200),
      });
    });

    // Tickets
    (data.tickets ?? []).forEach((t: any) => {
      rows.push({
        section: "Ticket",
        field: `#${t.id ?? "?"} • ${t.status ?? "?"}`,
        value: `${t.category ?? ""} — ${t.description ?? ""}`.slice(0, 200),
      });
    });

    // Notifications
    (data.notifications ?? []).forEach((n: any) => {
      rows.push({
        section: "Notification",
        field: n.type ?? "info",
        value: `${n.title ?? ""}: ${n.message ?? ""}`.slice(0, 200),
      });
    });

    return rows;
  }

  const exportMutation = trpc.user.exportData.useMutation({
    onSuccess: (data: any, variables) => {
      try {
        const stamp = new Date().toISOString().slice(0, 10);
        const baseName = `cybershield-export-${user?.publicId ?? "me"}-${stamp}`;
        const format = (variables as any)?.format ?? "json";

        if (format === "json") {
          const json = JSON.stringify(data, null, 2);
          downloadBlob(new Blob([json], { type: "application/json;charset=utf-8" }), `${baseName}.json`);
        } else if (format === "pdf") {
          const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
          doc.setFontSize(18);
          doc.text("CyberShield AI — Data Export", 40, 50);
          doc.setFontSize(10);
          doc.setTextColor(100);
          doc.text(`Account: ${user?.publicId ?? "—"} · Exported: ${new Date().toLocaleString()}`, 40, 70);
          doc.text(`Includes last ${data.daysIncluded ?? 10} days of activity`, 40, 84);

          const rows = buildExportRows(data);
          autoTable(doc, {
            startY: 100,
            head: [["Section", "Field", "Value"]],
            body: rows.map(r => [r.section, r.field, r.value]),
            styles: { fontSize: 8, cellPadding: 4, overflow: "linebreak" },
            headStyles: { fillColor: [20, 123, 115], textColor: 255, fontStyle: "bold" },
            alternateRowStyles: { fillColor: [245, 247, 250] },
            columnStyles: { 0: { cellWidth: 70 }, 1: { cellWidth: 130 }, 2: { cellWidth: "auto" } },
            margin: { left: 40, right: 40 },
          });

          doc.save(`${baseName}.pdf`);
        } else if (format === "excel") {
          const rows = buildExportRows(data);
          const ws = XLSX.utils.json_to_sheet(rows);
          ws["!cols"] = [{ wch: 14 }, { wch: 30 }, { wch: 80 }];
          const wb = XLSX.utils.book_new();
          XLSX.utils.book_append_sheet(wb, ws, "Export");

          // Add a metadata sheet
          const meta = [
            { key: "Exported At", value: new Date().toISOString() },
            { key: "Account ID", value: user?.publicId ?? "—" },
            { key: "Name", value: user?.name ?? "—" },
            { key: "Email", value: user?.email ?? "—" },
            { key: "Days Included", value: data.daysIncluded ?? 10 },
            { key: "Total Scans", value: (data.scans ?? []).length },
            { key: "Total Tickets", value: (data.tickets ?? []).length },
            { key: "Total Notifications", value: (data.notifications ?? []).length },
          ];
          const metaWs = XLSX.utils.json_to_sheet(meta);
          metaWs["!cols"] = [{ wch: 20 }, { wch: 50 }];
          XLSX.utils.book_append_sheet(wb, metaWs, "Metadata");

          XLSX.writeFile(wb, `${baseName}.xlsx`);
        }

        setExportStatus("done");
        setTimeout(() => setExportStatus("idle"), 3000);
      } catch (err) {
        console.error("[export] failed", err);
        alert("Download failed: " + (err instanceof Error ? err.message : String(err)));
        setExportStatus("error");
        setTimeout(() => setExportStatus("idle"), 3000);
      }
    },
    onError: (err) => {
      console.error("[export] mutation failed", err);
      alert("Export failed: " + (err.message ?? "Unknown error"));
      setExportStatus("error");
      setTimeout(() => setExportStatus("idle"), 3000);
    },
  });

  function handleExport(format: "json" | "pdf" | "excel") {
    setExportMenuOpen(false);
    setExportStatus("loading");
    exportMutation.mutate({ days: 10, format } as any);
  }

  const deleteMutation = trpc.user.deleteAccount.useMutation({
    onSuccess: () => { window.location.href = "/"; },
    onError: () => { setDeleteStatus("error"); setTimeout(() => setDeleteStatus("idle"), 3000); },
  });

  function handleDelete() {
    if (deleteConfirm !== "DELETE") return;
    setDeleteStatus("loading");
    deleteMutation.mutate({ confirm: "DELETE" });
  }

  useEffect(() => {
    const saved = localStorage.getItem("cybershield-theme") ?? "midnight-cyan";
    setTheme(saved);
    document.documentElement.dataset.theme = saved;
    if (saved === "light-teal") {
      document.documentElement.classList.remove("dark");
    } else {
      document.documentElement.classList.add("dark");
    }
  }, []);

  function choose(id: string) {
    setTheme(id);
    document.documentElement.dataset.theme = id;
    localStorage.setItem("cybershield-theme", id);
    if (id === "light-teal") {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    } else {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    }
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow-small">{settings ? "PREFERENCES" : "ACCOUNT"}</p>
          <h1>{settings ? "Settings" : "Profile"}</h1>
          <p>{settings ? "Manage your preferences and account data." : "Your authenticated account details."}</p>
        </div>
        <span className="stat-icon"><Settings2 size={18} /></span>
      </div>

      <div className="dashboard-grid">
        {/* ============================================================
            PROFILE VIEW — /profile
            Shows ONLY account details. Nothing else.
        ============================================================ */}
        {!settings && (
          <section className="panel">
            <div className="panel-head">
              <div>
                <h2>Account details</h2>
                <p>Authenticated profile verified by CyberShield AI.</p>
              </div>
              <UserRound size={17} color="#147b73" />
            </div>
            <div className="panel-body">
              <div className="profile-row">
                <span className="user-avatar"><UserRound size={17} /></span>
                <div>
                  <strong>{user?.name || "Account"}</strong>
                  <span>Display name</span>
                </div>
              </div>
              <div className="profile-row">
                <span className="stat-icon"><ShieldCheck size={15} /></span>
                <div>
                  <strong>{user?.email || "Email not available"}</strong>
                  <span>Email address</span>
                </div>
              </div>
              <div className="profile-row">
                <span className="stat-icon"><ShieldCheck size={15} /></span>
                <div>
                  <strong>{user?.publicId || "—"}</strong>
                  <span>Account ID (shareable)</span>
                </div>
              </div>
              <div className="profile-row">
                <span className="stat-icon"><Settings2 size={15} /></span>
                <div>
                  <strong>{user?.role === "admin" ? "Administrator" : "User"}</strong>
                  <span>Database-backed application role (RBAC)</span>
                </div>
              </div>
              <div className="profile-row">
                <span className="stat-icon"><Globe size={15} /></span>
                <div>
                  <strong>{timezoneLabel}</strong>
                  <span>Local timezone (auto-detected)</span>
                </div>
              </div>
              <p className="supporting">Credentials are cryptographically salted and hashed using scrypt. Roles and authorization are verified server-side on every request.</p>
            </div>
          </section>
        )}

        {/* ============================================================
            SETTINGS VIEW — /settings
            Shows preferences, notifications, data, support.
            NO account details panel.
        ============================================================ */}
        {settings && (
          <>
            {/* Color theme */}
            <section className="panel">
              <div className="panel-head">
                <div>
                  <h2><Palette size={15} style={{ verticalAlign: "-3px", marginRight: 6 }} />Color theme</h2>
                  <p>Your preference is stored in this browser session.</p>
                </div>
              </div>
              <div className="panel-body form-stack">
                {themes.map(item => (
                  <button key={item.id} className={`theme-option ${theme === item.id ? "selected" : ""}`} onClick={() => choose(item.id)}>
                    <span className={`theme-swatch ${item.id}`}><i /><i /><i /></span>
                    <span className="theme-copy">
                      <strong>{item.label}</strong>
                      <small>{item.note}</small>
                    </span>
                    {theme === item.id && <Check size={16} color="#147b73" />}
                  </button>
                ))}
                <div className="notice">Theme changes affect local browser styling and do not alter backend risk classification or security rules.</div>
              </div>
            </section>

            {/* Notifications */}
            <section className="panel">
              <div className="panel-head">
                <div>
                  <h2><Bell size={15} style={{ verticalAlign: "-3px", marginRight: 6 }} />Notifications</h2>
                  <p>Choose which alerts you want to receive.</p>
                </div>
              </div>
              <div className="panel-body form-stack">
                {[
                  { key: "emailHighRisk", label: "High-risk scan alerts", desc: "Get notified when a scan detects a high or critical threat." },
                  { key: "emailTicketUpdates", label: "Ticket status updates", desc: "Get notified when your report is confirmed, resolved or needs more info." },
                  { key: "emailAdminAssignments", label: "Admin assignments", desc: "For admins: get notified when a ticket is assigned to you." },
                  { key: "emailWeeklySummary", label: "Weekly summary", desc: "Receive a weekly digest of your scan activity." },
                ].map(item => (
                  <div key={item.key} className="profile-row">
                    <span className="stat-icon"><Mail size={15} /></span>
                    <div style={{ flex: 1 }}>
                      <strong>{item.label}</strong>
                      <span>{item.desc}</span>
                    </div>
                    <button
                      onClick={() => togglePref(item.key as keyof typeof prefs)}
                      style={{
                        padding: "6px 14px",
                        borderRadius: 999,
                        border: "none",
                        cursor: "pointer",
                        background: prefs[item.key as keyof typeof prefs] ? "#147b73" : "#333",
                        color: "#fff",
                        minWidth: 60,
                      }}
                    >
                      {prefs[item.key as keyof typeof prefs] ? "ON" : "OFF"}
                    </button>
                  </div>
                ))}
                <div className="notice">Preferences are stored locally in your browser.</div>
              </div>
            </section>

            {/* Your data */}
            {/* Your data */}
            <section className="panel" style={{ gridColumn: "1 / -1" }}>
              <div className="panel-head">
                <div>
                  <h2><Download size={15} style={{ verticalAlign: "-3px", marginRight: 6 }} />Your data</h2>
                  <p>Export or permanently delete your account information.</p>
                </div>
              </div>
              <div style={{ padding: 19 }}>

                {/* Download row */}
                <div style={{
                  display: "flex",
                  flexDirection: "row",
                  alignItems: "center",
                  gap: 14,
                  paddingBottom: 18,
                  borderBottom: "1px solid #1e2c33",
                }}>
                  <div style={{
                    width: 34,
                    height: 34,
                    borderRadius: 8,
                    background: "#147b73",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}>
                    <Download size={16} color="#fff" />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                      Download my data
                    </div>
                    <div style={{ color: "#8892b0", fontSize: 12, lineHeight: 1.5 }}>
                      Get a file with your scans, tickets, notifications and activity from the last 10 days.
                    </div>
                  </div>

                  <div style={{ position: "relative", flexShrink: 0 }}>
                    <button
                      onClick={() => setExportMenuOpen(v => !v)}
                      disabled={exportStatus === "loading"}
                      style={{
                        minWidth: 160,
                        padding: "10px 16px",
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        justifyContent: "center",
                        borderRadius: 9,
                        border: "1px solid #233554",
                        background: "transparent",
                        color: "#e6f1ff",
                        cursor: exportStatus === "loading" ? "not-allowed" : "pointer",
                        fontSize: 13,
                        fontWeight: 700,
                      }}
                    >
                      <Download size={14} />
                      {exportStatus === "loading" ? "Preparing..." : exportStatus === "done" ? "Downloaded ✓" : exportStatus === "error" ? "Failed" : "Download"}
                      <ChevronDown size={14} />
                    </button>

                    {exportMenuOpen && (
                      <>
                        <div onClick={() => setExportMenuOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 10 }} />
                        <div
                          style={{
                            position: "absolute",
                            top: "100%",
                            right: 0,
                            marginTop: 6,
                            background: "#0a192f",
                            border: "1px solid #233554",
                            borderRadius: 8,
                            boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                            minWidth: 200,
                            zIndex: 11,
                            overflow: "hidden",
                          }}
                        >
                          {[
                            { id: "json", label: "Download as JSON", hint: "Raw data for developers" },
                            { id: "pdf", label: "Download as PDF", hint: "Readable report" },
                            { id: "excel", label: "Download as Excel", hint: "Spreadsheet (.xlsx)" },
                          ].map(opt => (
                            <button
                              key={opt.id}
                              onClick={() => handleExport(opt.id as "json" | "pdf" | "excel")}
                              style={{
                                display: "block",
                                width: "100%",
                                textAlign: "left",
                                padding: "10px 14px",
                                background: "transparent",
                                border: "none",
                                color: "#e6f1ff",
                                cursor: "pointer",
                                fontSize: 13,
                              }}
                              onMouseEnter={(e) => (e.currentTarget.style.background = "#147b73")}
                              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                            >
                              <strong style={{ display: "block" }}>{opt.label}</strong>
                              <small style={{ color: "#8892b0" }}>{opt.hint}</small>
                            </button>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                </div>

                {/* Delete row */}
                <div style={{
                  display: "flex",
                  flexDirection: "row",
                  alignItems: "center",
                  gap: 14,
                  paddingTop: 18,
                }}>
                  <div style={{
                    width: 34,
                    height: 34,
                    borderRadius: 8,
                    background: "#3a1e1e",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                  }}>
                    <Trash2 size={16} color="#e57373" />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, color: "#e57373", marginBottom: 4 }}>
                      Permanently delete my data
                    </div>
                    <div style={{ color: "#8892b0", fontSize: 12, lineHeight: 1.5 }}>
                      This will erase your account and all associated scans, tickets and notifications. This action cannot be undone.
                    </div>
                  </div>

                  <button
                    onClick={() => setShowDeleteDialog(true)}
                    style={{
                      minWidth: 120,
                      padding: "10px 20px",
                      borderRadius: 9,
                      border: "1px solid #e57373",
                      background: "transparent",
                      color: "#e57373",
                      cursor: "pointer",
                      fontSize: 13,
                      fontWeight: 700,
                      flexShrink: 0,
                    }}
                  >
                    Delete
                  </button>
                </div>

              </div>
            </section>

            {/* Support */}
            <section className="panel" style={{ gridColumn: "1 / -1" }}>
              <div className="panel-head">
                <div>
                  <h2><Code2 size={15} style={{ verticalAlign: "-3px", marginRight: 6 }} />Support &amp; Contact</h2>
                  <p>Found a bug? Need help? Reach the development team.</p>
                </div>
              </div>
              <div className="panel-body form-stack">
                <div className="profile-row">
                  <span className="stat-icon"><Mail size={15} /></span>
                  <div style={{ flex: 1 }}>
                    <strong>cybershield@jaininstitute.edu</strong>
                    <span>Project support email</span>
                  </div>
                </div>
                <div className="profile-row">
                  <span className="stat-icon"><Code2 size={15} /></span>
                  <div style={{ flex: 1 }}>
                    <strong>github.com/vz9087/impersonai-biz-mp</strong>
                    <span>Source code &amp; issue tracker</span>
                  </div>
                </div>
                <div className="profile-row">
                  <span className="stat-icon"><ShieldCheck size={15} /></span>
                  <div style={{ flex: 1 }}>
                    <strong>CyberShield AI v1.0.0</strong>
                    <span>Built by Vishal VP, Keerthi M G, Pooja N Annigere · Jain Institute of Technology</span>
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </div>

      {/* Delete dialog — full-screen modal, outside the grid */}
      {showDeleteDialog && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999 }}>
          <div className="panel" style={{ maxWidth: 480, padding: 24 }}>
            <h2 style={{ marginTop: 0, color: "#e57373" }}>Delete account?</h2>
            <p style={{ color: "#aaa" }}>This will permanently erase your account and all associated data. This cannot be undone.</p>
            <p style={{ color: "#aaa", fontSize: 13 }}>Type <strong style={{ color: "#fff" }}>DELETE</strong> to confirm:</p>
            <input
              type="text"
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              placeholder="DELETE"
              style={{ width: "100%", padding: 10, borderRadius: 6, border: "1px solid #444", background: "#0a192f", color: "#fff", marginBottom: 16 }}
            />
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button
                onClick={() => { setShowDeleteDialog(false); setDeleteConfirm(""); }}
                style={{
                  padding: "8px 16px",
                  borderRadius: 8,
                  border: "1px solid #444",
                  background: "transparent",
                  color: "#ccc",
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleteConfirm !== "DELETE" || deleteStatus === "loading"}
                style={{
                  padding: "8px 16px",
                  borderRadius: 8,
                  border: "none",
                  background: deleteConfirm === "DELETE" ? "#e57373" : "#333",
                  color: "#fff",
                  cursor: deleteConfirm === "DELETE" ? "pointer" : "not-allowed",
                }}
              >
                {deleteStatus === "loading" ? "Deleting..." : "Delete Forever"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}