//! Per-process network throughput via ETW.
//!
//! We subscribe to `Microsoft-Windows-Kernel-Network`, a manifest-based
//! provider registered by the transport (Tcpip.sys). Every TCP or UDP
//! send/receive event carries a `size` (bytes on the wire) and a `PID`
//! (socket-owning process). We accumulate into an `Arc<Mutex<HashMap>>` on
//! the ETW processing thread and let the Tauri command thread take cheap
//! snapshots at 1 Hz to compute per-second deltas.
//!
//! Starting a real-time user-mode ETW session requires membership in the
//! Performance Log Users group or admin. `NetMonitor::start` returns an
//! error if that permission check fails, and the app degrades to
//! "no per-process network stats" rather than crashing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, UserTrace};
use ferrisetw::EventRecord;

// {7DD42A49-5329-4832-8DFD-43D979153A88} — Microsoft-Windows-Kernel-Network.
const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

// Event IDs from the Kernel-Network manifest. `send` and `recv` are separate
// events per protocol per address family; we treat all eight as flows into
// two per-PID counters.
const TCP_SEND_V4: u16 = 10;
const TCP_RECV_V4: u16 = 11;
const TCP_SEND_V6: u16 = 26;
const TCP_RECV_V6: u16 = 27;
const UDP_SEND_V4: u16 = 42;
const UDP_RECV_V4: u16 = 43;
const UDP_SEND_V6: u16 = 58;
const UDP_RECV_V6: u16 = 59;

// TRACE_LEVEL_VERBOSE from evntrace.h. The provider emits its send/recv
// events at Informational, but requesting Verbose is a superset and future-proofs
// against manifest revisions that raise a level.
const TRACE_LEVEL_VERBOSE: u8 = 5;
// Enable every keyword so we get TCP + UDP over both v4 and v6.
const KEYWORD_ANY: u64 = u64::MAX;

#[derive(Clone, Copy, Default, Debug)]
pub struct NetBytes {
    pub rx: u64,
    pub tx: u64,
}

pub struct NetMonitor {
    counters: Arc<Mutex<HashMap<u32, NetBytes>>>,
    // Holding the trace here keeps the ETW session alive; on Drop the crate
    // issues ControlTrace(STOP) for us.
    _trace: UserTrace,
}

impl NetMonitor {
    pub fn start() -> Result<Self, String> {
        let counters: Arc<Mutex<HashMap<u32, NetBytes>>> = Arc::new(Mutex::new(HashMap::new()));
        let cb_counters = Arc::clone(&counters);

        let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
            .any(KEYWORD_ANY)
            .level(TRACE_LEVEL_VERBOSE)
            .add_callback(move |record: &EventRecord, sl: &SchemaLocator| {
                if let Some((pid, size, is_send)) = parse_transfer(record, sl) {
                    if pid == 0 {
                        // System Idle. No bucket to attribute this to.
                        return;
                    }
                    let mut table = cb_counters.lock().unwrap();
                    let entry = table.entry(pid).or_default();
                    if is_send {
                        entry.tx = entry.tx.saturating_add(size as u64);
                    } else {
                        entry.rx = entry.rx.saturating_add(size as u64);
                    }
                }
            })
            .build();

        // Session names live in the kernel until stopped or reboot. If a
        // previous winglass run was killed hard, its named session is still
        // there and StartTrace fails with ERROR_ALREADY_EXISTS. Best-effort
        // cleanup before starting our own.
        let session_name = format!("winglass-net-{}", std::process::id());
        let _ = stop_trace_by_name(&session_name);

        let trace = UserTrace::new()
            .named(session_name)
            .enable(provider)
            .start_and_process()
            .map_err(|e| format!("{:?}", e))?;

        Ok(Self { counters, _trace: trace })
    }

    /// Snapshot of per-PID cumulative bytes since this monitor started.
    pub fn snapshot(&self) -> HashMap<u32, NetBytes> {
        self.counters.lock().unwrap().clone()
    }
}

fn parse_transfer(record: &EventRecord, sl: &SchemaLocator) -> Option<(u32, u32, bool)> {
    let id = record.event_id();
    let is_send = matches!(id, TCP_SEND_V4 | TCP_SEND_V6 | UDP_SEND_V4 | UDP_SEND_V6);
    let is_recv = matches!(id, TCP_RECV_V4 | TCP_RECV_V6 | UDP_RECV_V4 | UDP_RECV_V6);
    if !(is_send || is_recv) {
        return None;
    }

    let schema = sl.event_schema(record).ok()?;
    let parser = Parser::create(record, &schema);
    let size: u32 = parser.try_parse("size").ok()?;

    // For send events the header PID and the payload PID agree. For recv
    // events firing in DPC context, the header can report the interrupted
    // thread's process while the payload has the true socket owner — so we
    // prefer the payload and only fall back to the header.
    let pid: u32 = parser
        .try_parse::<u32>("PID")
        .unwrap_or_else(|_| record.process_id());

    Some((pid, size, is_send))
}
