import { AlertTriangle, CheckCircle2, Loader2, ShieldCheck, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { severityTone, statusTone } from "../model/viewModels";

export function Panel({ action, children, icon: Icon, title }: { action?: ReactNode; children: ReactNode; icon: LucideIcon; title: string }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2><Icon size={18} />{title}</h2>
        {action}
      </header>
      {children}
    </section>
  );
}

export function MetricCard({ icon: Icon, label, tone = "neutral", value }: { icon: LucideIcon; label: string; tone?: string; value: number | string }) {
  return (
    <div className={`metric-card ${tone}`}>
      <Icon size={18} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function MiniBlock({ label, value }: { label: string; value: string }) {
  return <div className="mini-block"><span>{label}</span><strong>{value}</strong></div>;
}

export function ResponsiveTable({ children }: { children: ReactNode }) {
  return <div className="table-wrap"><table>{children}</table></div>;
}

export function SeverityPill({ value }: { value: string }) {
  return <span className={`pill severity ${severityTone(value)}`}>{value}</span>;
}

export function StatusPill({ tone, value }: { tone?: string; value: string }) {
  return <span className={`pill ${tone ?? statusTone(value)}`}>{value}</span>;
}

export function EmptyState({ title }: { title: string }) {
  return <div className="empty-state"><ShieldCheck size={18} /><span>{title}</span></div>;
}

export function InlineAlert({ message }: { message: string }) {
  return <div className="inline-alert"><AlertTriangle size={16} />{message}</div>;
}

export function InlineSuccess({ message }: { message: string }) {
  return <div className="inline-success"><CheckCircle2 size={16} />{message}</div>;
}

export function LoadingBlock() {
  return <div className="empty-state"><Loader2 size={18} className="spin" /><span>Loading</span></div>;
}

export function TextInput({ label, onChange, placeholder, value }: { label: string; onChange: (value: string) => void; placeholder?: string; value: string }) {
  const id = `field-${label.toLowerCase().replaceAll(" ", "-")}`;
  return <label htmlFor={id}>{label}<input id={id} placeholder={placeholder} value={value} onChange={(event) => onChange(event.target.value)} /></label>;
}
