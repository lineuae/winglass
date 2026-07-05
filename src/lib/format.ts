const KIBI = 1024;
const MEBI = 1024 * 1024;
const GIBI = 1024 * 1024 * 1024;

export function fmtBytes(n: number): string {
  if (n >= GIBI) return (n / GIBI).toFixed(2) + " GB";
  if (n >= MEBI) return (n / MEBI).toFixed(1) + " MB";
  if (n >= KIBI) return (n / KIBI).toFixed(1) + " KB";
  return n + " B";
}

export function fmtMbps(bps: number, showZero = false): string {
  const mb = bps / MEBI;
  if (mb < 0.05) return showZero ? "0.0" : "";
  return mb.toFixed(1);
}

export function fmtDuration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
