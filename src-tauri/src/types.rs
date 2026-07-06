use serde::Serialize;

#[derive(Clone, Copy, Default)]
pub struct IoSample {
    pub read: u64,
    pub write: u64,
    pub other: u64,
}

#[derive(Clone, Copy, Default)]
pub struct IoDelta {
    pub read_bps: f64,
    pub write_bps: f64,
    pub other_bps: f64,
}

impl IoDelta {
    pub fn total_bps(&self) -> f64 {
        self.read_bps + self.write_bps + self.other_bps
    }
}

#[derive(Clone, Copy, Default)]
pub struct NetDelta {
    pub rx_bps: f64,
    pub tx_bps: f64,
}

impl NetDelta {
    pub fn total_bps(&self) -> f64 {
        self.rx_bps + self.tx_bps
    }
}

/// Wire representation of a signature verdict — flat and cheap for the
/// frontend to switch on. `status` is one of "valid" | "unsigned" | "failed"
/// | "pending".
#[derive(Serialize, Clone, Debug)]
pub struct SigInfo {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    pub is_ms_windows: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u32>,
}

impl SigInfo {
    pub fn pending() -> Self {
        Self {
            status: "pending",
            signer: None,
            is_ms_windows: false,
            error_code: None,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub cpu: f32,
    pub cpu_history: Vec<f32>, // rolling 60-sample window for the row sparkline
    pub mem_mb: f64,
    pub io_bps: f64,           // total (read + write + other)
    pub io_read_bps: f64,
    pub io_write_bps: f64,
    pub net_bps: f64,          // total (rx + tx)
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub sig: SigInfo,
}

#[derive(Serialize, Clone)]
pub struct ParentEntry {
    pub pid: u32,
    pub name: String,
}

#[derive(Serialize, Clone)]
pub struct ConnectionInfo {
    pub proto: String,
    pub local: String,
    pub remote: Option<String>,
    pub remote_ip: Option<String>,
    pub hostname: Option<String>,
    pub state: Option<&'static str>,
}

#[derive(Serialize, Clone)]
pub struct DllEntry {
    pub path: String,
    pub name: String,
    pub sig: SigInfo,
}

#[derive(Serialize, Clone)]
pub enum DllsResult {
    Ok { entries: Vec<DllEntry>, unsigned_count: usize },
    Denied(String),
}

#[derive(Serialize, Clone)]
pub enum ThreadsResult {
    Ok(Vec<crate::threads::ThreadInfo>),
    Error(String),
}

#[derive(Serialize, Clone)]
pub enum HandlesResult {
    Ok(Vec<crate::handles::HandleInfo>),
    Error(String),
}

#[derive(Serialize, Clone)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Clone)]
pub struct ProcessDetail {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub exe_sha256: Option<String>,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub parent_chain: Vec<ParentEntry>,
    pub uptime_seconds: u64,
    pub sig: SigInfo,

    pub cpu: f32,
    pub mem_mb: f64,
    pub cpu_history: Vec<f32>,
    pub mem_history: Vec<f64>,

    pub io_read_bps: f64,
    pub io_write_bps: f64,
    pub io_other_bps: f64,
    pub io_read_total: u64,
    pub io_write_total: u64,
    pub io_other_total: u64,

    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_history: Vec<f64>,

    pub connections: Vec<ConnectionInfo>,
    pub dlls: DllsResult,
    pub threads: ThreadsResult,
    pub handles: HandlesResult,
    pub environ: Vec<EnvEntry>,
}
