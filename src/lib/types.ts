// Mirror of Rust types::* — kept in sync manually.

export type SigStatus = "valid" | "unsigned" | "failed" | "pending";

export interface SigInfo {
  status: SigStatus;
  signer?: string;
  is_ms_windows: boolean;
  error_code?: number;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  exe_path: string | null;
  cpu: number;
  mem_mb: number;
  io_bps: number;
  io_read_bps: number;
  io_write_bps: number;
  net_bps: number;
  net_rx_bps: number;
  net_tx_bps: number;
  sig: SigInfo;
}

export interface ParentEntry {
  pid: number;
  name: string;
}

export interface ConnectionInfo {
  proto: string;
  local: string;
  remote: string | null;
  remote_ip: string | null;
  hostname: string | null;
  state: string | null;
}

export interface DllEntry {
  path: string;
  name: string;
  sig: SigInfo;
}

export type DllsResult =
  | { Ok: { entries: DllEntry[]; unsigned_count: number } }
  | { Denied: string };

export interface EnvEntry {
  key: string;
  value: string;
}

export interface ProcessDetail {
  pid: number;
  name: string;
  exe_path: string | null;
  exe_sha256: string | null;
  cmd: string[];
  user: string | null;
  parent_chain: ParentEntry[];
  uptime_seconds: number;
  sig: SigInfo;
  cpu: number;
  mem_mb: number;
  cpu_history: number[];
  mem_history: number[];
  io_read_bps: number;
  io_write_bps: number;
  io_other_bps: number;
  io_read_total: number;
  io_write_total: number;
  io_other_total: number;
  net_rx_bps: number;
  net_tx_bps: number;
  net_rx_total: number;
  net_tx_total: number;
  net_history: number[];
  connections: ConnectionInfo[];
  dlls: DllsResult;
  environ: EnvEntry[];
}
