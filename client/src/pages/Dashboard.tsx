import { trpc } from "@/lib/trpc";
import { AtSign, ArrowRight, ArrowUpRight, FileSearch, Globe2, Link2, LoaderCircle, LockKeyhole, ShieldAlert, ShieldCheck, Smartphone, ScanLine, Activity, BookOpenCheck } from "lucide-react";
import { Link } from "wouter";

const scanners = [
  { id: "url", title: "Website / URL", note: "Domain, spelling and URL signals", icon: Globe2 },
  { id: "email", title: "Email", note: "Sender, message and link clues", icon: AtSign },
  { id: "sms", title: "SMS / message", note: "Scam, urgency and OTP patterns", icon: Smartphone },
  { id: "link", title: "Link context", note: "Check a link before opening it", icon: Link2 },
  { id: "apk", title: "APK / file", note: "Static-only APK indicator review", icon: FileSearch },
  { id: "api", title: "Authorized API", note: "Passive config review only", icon: LockKeyhole },
];
const cls = (level: string) => level.toLowerCase().replaceAll(" ", "-");
export default function Dashboard() {
  const { data, isLoading, error } = trpc.user.dashboard.useQuery();
  if (isLoading) return <div className="center-state"><LoaderCircle className="spin"/> Loading overview…</div>;
  if (error || !data) return <div className="notice">The dashboard could not load. Check the database connection and refresh.</div>;
  const stats = [
    { label: "Total scans", value: data.totalScans, icon: ScanLine, foot: "Across all scan types" },
    { label: "Lower-risk scans", value: data.safeScans, icon: ShieldCheck, foot: "Very low or low indicators" },
    { label: "Needs review", value: data.riskyScans, icon: ShieldAlert, foot: "Medium risk or above" , tone: "amber" },
    { label: "Reports submitted", value: data.reports, icon: Activity, foot: "Your threat tickets", tone: "red" },
  ];
  return <>
    <div className="page-heading"><div><p className="eyebrow-small">YOUR DIGITAL SAFETY DESK</p><h1>Overview</h1><p>Scan suspicious content, understand the signals and choose your next step.</p></div><Link className="button button-primary" href="/scanner/url">New scan <ArrowRight size={15}/></Link></div>
    <div className="stats-grid">{stats.map(stat => <article className="stat-card" key={stat.label}><div className="stat-top"><span>{stat.label}</span><span className={`stat-icon ${stat.tone ?? ""}`}><stat.icon size={15}/></span></div><div className="stat-value">{stat.value}</div><div className="stat-foot">{stat.foot}</div></article>)}</div>
    <div className="dashboard-grid"><section className="panel"><div className="panel-head"><div><h2>Scan center</h2><p>Choose the type of content you want to review.</p></div><ScanLine size={18} color="#148074"/></div><div className="panel-body"><div className="scan-card-list">{scanners.map(item => <Link className="scan-card" href={`/scanner/${item.id}`} key={item.id}><span className="feature-icon"><item.icon size={16}/></span><span><h3>{item.title}</h3><p>{item.note}</p></span><ArrowUpRight size={14} className="scan-arrow"/></Link>)}</div><p className="supporting" style={{marginTop:13}}>Scores are rule-based indicators—not probabilities or a guarantee of safety. Suspicious destinations are not opened automatically.</p></div></section>
    <section className="panel"><div className="panel-head"><div><h2>Recent scans</h2><p>Your latest saved analysis</p></div><Link className="mini-link" href="/history">All history <ArrowRight size={13}/></Link></div>{data.recentScans.length ? <div className="table-wrap"><table className="scan-table"><thead><tr><th>INPUT</th><th>TYPE</th><th>RISK</th></tr></thead><tbody>{data.recentScans.map(scan => <tr key={scan.id}><td className="scan-input-cell">{scan.inputReference}</td><td>{scan.scanType.toUpperCase()}</td><td><span className={`risk-pill ${cls(scan.riskLevel)}`}>{scan.riskScore}% · {scan.riskLevel}</span></td></tr>)}</tbody></table></div> : <div className="empty-state">Your scan history will appear here after your first scan.</div>}</section></div>
    <div className="dashboard-lower"><section className="panel awareness-card"><div className="score-ring" style={{"--score":`${data.awarenessScore}%`} as React.CSSProperties}><b>{data.awarenessScore}</b></div><div><p className="eyebrow-small">CYBER AWARENESS</p><h2 className="panel-title">{data.awarenessScore ? "Your safety habits are growing" : "Build your safety instincts"}</h2><p className="muted">{data.awarenessScore ? "Latest quiz score. Educational only—not a guarantee of security." : "Take a short quiz and see explanations for each answer."}</p><Link className="mini-link" href="/awareness">{data.awarenessScore ? "Practice again" : "Start awareness quiz"} <ArrowRight size={13}/></Link></div></section><section className="panel awareness-card"><span className="stat-icon"><BookOpenCheck size={20}/></span><div><p className="eyebrow-small">THREAT REPORTING</p><h2 className="panel-title">Help verify a suspicious item</h2><p className="muted">Send a scan to administrator review and track its status.</p><Link className="mini-link" href="/tickets">View my reports <ArrowRight size={13}/></Link></div></section></div>
  </>;
}
