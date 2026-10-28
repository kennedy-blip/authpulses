import React from "react";
import { cn } from "../utils/cn";

export function JsonView({ data, compact = false }: { data: any; compact?: boolean }) {
  const renderValue = (value: any, depth: number): React.ReactNode => {
    if (value === null) return <span className="claim-null">null</span>;
    if (typeof value === "string") return <span className="claim-string">"{value}"</span>;
    if (typeof value === "number") return <span className="claim-number">{value}</span>;
    if (typeof value === "boolean") return <span className="claim-bool">{String(value)}</span>;
    if (Array.isArray(value)) {
      if (value.length === 0) return <span className="text-slate-500">[]</span>;
      return (
        <span>
          <span className="text-slate-500">[</span>
          <span className="block">
            {value.map((v, i) => (
              <span key={i} className="block" style={{ paddingLeft: (depth + 1) * 14 }}>
                {renderValue(v, depth + 1)}
                {i < value.length - 1 && <span className="text-slate-500">,</span>}
              </span>
            ))}
          </span>
          <span style={{ paddingLeft: depth * 14 }} className="text-slate-500">]</span>
        </span>
      );
    }
    if (typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 0) return <span className="text-slate-500">{"{}"}</span>;
      return (
        <span>
          <span className="text-slate-500">{"{"}</span>
          <span className="block">
            {keys.map((k, i) => (
              <span key={k} className="block" style={{ paddingLeft: (depth + 1) * 14 }}>
                <span className="claim-key">"{k}"</span>
                <span className="text-slate-500">: </span>
                {renderValue(value[k], depth + 1)}
                {i < keys.length - 1 && <span className="text-slate-500">,</span>}
              </span>
            ))}
          </span>
          <span style={{ paddingLeft: depth * 14 }} className="text-slate-500">{"}"}</span>
        </span>
      );
    }
    return <span>{String(value)}</span>;
  };

  return (
    <pre
      className={cn(
        "font-mono whitespace-pre-wrap break-words leading-relaxed",
        compact ? "text-[11.5px]" : "text-[12.5px]"
      )}
    >
      {renderValue(data, 0)}
    </pre>
  );
}

export function ClaimRow({
  label,
  value,
  mono = true,
  accent,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  accent?: string;
  sub?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-white/[0.05] px-3 py-2 last:border-0 hover:bg-white/[0.02] transition-colors">
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
        {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
      </div>
      <div
        className={`text-right text-[12.5px] break-all max-w-[60%] ${mono ? "font-mono" : ""}`}
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
    </div>
  );
}
