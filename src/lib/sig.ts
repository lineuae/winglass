// Single source of truth for turning a signature verdict into the bucket the
// UI switches on, and the color that bucket paints. Both the process table and
// the detail panel (row dot, DLL dot, header chip) resolve color through here,
// so widening the "Windows OS" rule or adding a SigStatus variant is one edit.

import type { SigInfo } from "./types";

export type SigKind = "os" | "signed" | "unsigned" | "failed" | "pending";

export function sigKind(sig: SigInfo): SigKind {
  if (sig.status === "valid") return sig.is_ms_windows ? "os" : "signed";
  return sig.status;
}

const SIG_COLOR: Record<SigKind, string> = {
  os: "var(--color-ok)",
  signed: "var(--color-fg-muted)",
  unsigned: "var(--color-danger)",
  failed: "var(--color-warn)",
  pending: "var(--color-fg-dim)",
};

export function sigColor(sig: SigInfo): string {
  return SIG_COLOR[sigKind(sig)];
}
