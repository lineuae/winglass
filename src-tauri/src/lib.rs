use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::time::Instant;

use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};
use tauri::{Manager, State};

mod dns;
mod etw;
mod geoip;
mod handles;
mod net;
mod threads;
mod types;
mod verify;
mod win;

use types::{
    ConnectionInfo, DllEntry, DllsResult, EnvEntry, HandlesResult, IoDelta, IoSample, NetDelta,
    ParentEntry, ProcessDetail, ProcessInfo, SigInfo, ThreadsResult,
};
use verify::SigStatus;

const MEBI: f64 = 1024.0 * 1024.0;
const HISTORY_LEN: usize = 60;

pub struct AppState {
    sys: System,
    users: Users,

    io_state: HashMap<u32, (IoSample, Instant)>,
    io_delta: HashMap<u32, IoDelta>,
    io_total: HashMap<u32, IoSample>,

    /// ETW producer of per-PID (rx, tx) cumulative totals. `None` when the
    /// user-mode session couldn't be started (not admin / no perf-log-users
    /// membership); the app runs without net throughput in that case.
    net_monitor: Option<etw::NetMonitor>,
    net_state: HashMap<u32, (etw::NetBytes, Instant)>,
    net_delta: HashMap<u32, NetDelta>,
    net_total: HashMap<u32, etw::NetBytes>,
    net_history: HashMap<u32, VecDeque<f64>>,

    cpu_history: HashMap<u32, VecDeque<f32>>,
    mem_history: HashMap<u32, VecDeque<f64>>,
    exe_path_cache: HashMap<u32, Option<String>>,

    sig_cache: HashMap<String, Option<SigStatus>>,
    sig_tx: Sender<String>,
    sig_rx: Receiver<(String, SigStatus)>,

    dns_cache: HashMap<IpAddr, Option<String>>,
    dns_tx: Sender<IpAddr>,
    dns_rx: Receiver<(IpAddr, Option<String>)>,

    net_snapshot: Vec<net::Connection>,
    geoip: geoip::GeoIp,
    dll_cache: HashMap<u32, Result<Vec<String>, String>>,
    /// Cached per-pid handle enumeration. Same shape as `dll_cache`: `Ok` for
    /// a successful walk (empty vec means "no handles"), `Err` for a
    /// per-process failure. Cleared when the pid dies.
    handles_cache: HashMap<u32, Result<Vec<handles::HandleInfo>, String>>,
    sha_cache: HashMap<String, Option<String>>, // lowercase path -> hex digest
}

impl AppState {
    fn new(geoip_path: Option<std::path::PathBuf>) -> Self {
        let (sig_tx, sig_rx) = verify::start_worker();
        let (dns_tx, dns_rx) = dns::start_worker();
        let net_monitor = match etw::NetMonitor::start() {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("[winglass] ETW network monitor unavailable: {}", e);
                None
            }
        };
        let geoip = match geoip_path {
            Some(p) => geoip::GeoIp::open(&p),
            None => geoip::GeoIp::open(std::path::Path::new("")),
        };
        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
            io_state: HashMap::new(),
            io_delta: HashMap::new(),
            io_total: HashMap::new(),
            net_monitor,
            net_state: HashMap::new(),
            net_delta: HashMap::new(),
            net_total: HashMap::new(),
            net_history: HashMap::new(),
            cpu_history: HashMap::new(),
            mem_history: HashMap::new(),
            exe_path_cache: HashMap::new(),
            sig_cache: HashMap::new(),
            sig_tx,
            sig_rx,
            dns_cache: HashMap::new(),
            dns_tx,
            dns_rx,
            net_snapshot: Vec::new(),
            geoip,
            dll_cache: HashMap::new(),
            handles_cache: HashMap::new(),
            sha_cache: HashMap::new(),
        }
    }

    /// Cheap-ish: 10-100 ms for typical exes, cached forever per path within a
    /// session. Reads the file in 64KB chunks so a hostile giant file doesn't
    /// blow memory.
    fn hash_exe(&mut self, path: &str) -> Option<String> {
        let key = Self::cache_key(path);
        if let Some(cached) = self.sha_cache.get(&key) {
            return cached.clone();
        }
        let hex = compute_sha256(path);
        self.sha_cache.insert(key, hex.clone());
        hex
    }

    fn cache_key(path: &str) -> String {
        path.to_lowercase()
    }

    fn drain_workers(&mut self) {
        while let Ok((path, status)) = self.sig_rx.try_recv() {
            self.sig_cache.insert(Self::cache_key(&path), Some(status));
        }
        while let Ok((ip, name)) = self.dns_rx.try_recv() {
            self.dns_cache.insert(ip, name);
        }
    }

    fn request_verify(&mut self, path: &str) {
        let key = Self::cache_key(path);
        if self.sig_cache.contains_key(&key) {
            return;
        }
        self.sig_cache.insert(key, None);
        let _ = self.sig_tx.send(path.to_string());
    }

    fn sig_status(&self, path: &str) -> Option<SigStatus> {
        self.sig_cache
            .get(&Self::cache_key(path))
            .cloned()
            .flatten()
    }

    fn sig_info_for(&self, path: &Option<String>) -> SigInfo {
        match path.as_ref().and_then(|p| self.sig_status(p)) {
            Some(s) => s.to_info(),
            None => SigInfo::pending(),
        }
    }

    fn request_dns(&mut self, ip: IpAddr) {
        if dns::is_private_or_loopback(ip) || self.dns_cache.contains_key(&ip) {
            return;
        }
        self.dns_cache.insert(ip, None);
        let _ = self.dns_tx.send(ip);
    }

    fn refresh_and_list(&mut self) -> Vec<ProcessInfo> {
        self.drain_workers();

        let kind = ProcessRefreshKind::new()
            .with_cpu()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_environ(UpdateKind::OnlyIfNotSet);
        self.sys
            .refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        self.net_snapshot = net::snapshot();

        // One-shot copy of the ETW counter table. Held briefly and released
        // before we do any per-pid work — the callback thread keeps
        // accumulating in the background.
        let net_totals: HashMap<u32, etw::NetBytes> = self
            .net_monitor
            .as_ref()
            .map(|m| m.snapshot())
            .unwrap_or_default();

        // Collect immutable sysinfo view first so we can freely mutate self below.
        let raw: Vec<(u32, Option<u32>, String, f32, f64, Option<String>)> = self
            .sys
            .processes()
            .values()
            .map(|p| {
                (
                    p.pid().as_u32(),
                    p.parent().map(|pid| pid.as_u32()),
                    p.name().to_string_lossy().into_owned(),
                    p.cpu_usage(),
                    p.memory() as f64 / MEBI,
                    p.exe().map(|e| e.to_string_lossy().into_owned()),
                )
            })
            .collect();

        let now = Instant::now();
        let live: HashSet<u32> = raw.iter().map(|(pid, ..)| *pid).collect();
        self.io_state.retain(|pid, _| live.contains(pid));
        self.io_delta.retain(|pid, _| live.contains(pid));
        self.io_total.retain(|pid, _| live.contains(pid));
        self.net_state.retain(|pid, _| live.contains(pid));
        self.net_delta.retain(|pid, _| live.contains(pid));
        self.net_total.retain(|pid, _| live.contains(pid));
        self.net_history.retain(|pid, _| live.contains(pid));
        self.cpu_history.retain(|pid, _| live.contains(pid));
        self.mem_history.retain(|pid, _| live.contains(pid));
        self.exe_path_cache.retain(|pid, _| live.contains(pid));
        self.dll_cache.retain(|pid, _| live.contains(pid));
        self.handles_cache.retain(|pid, _| live.contains(pid));

        let mut infos = Vec::with_capacity(raw.len());
        for (pid, parent_pid, name, cpu, mem_mb, sys_exe) in raw {
            let exe_path = self.resolve_exe_path(pid, sys_exe);

            let cpu_h = self.cpu_history.entry(pid).or_default();
            if cpu_h.len() >= HISTORY_LEN {
                cpu_h.pop_front();
            }
            cpu_h.push_back(cpu);
            let cpu_history: Vec<f32> = cpu_h.iter().copied().collect();
            let mem_h = self.mem_history.entry(pid).or_default();
            if mem_h.len() >= HISTORY_LEN {
                mem_h.pop_front();
            }
            mem_h.push_back(mem_mb);

            self.sample_io(pid, now);
            let io = self.io_delta.get(&pid).copied().unwrap_or_default();

            let net_cum = net_totals.get(&pid).copied().unwrap_or_default();
            self.sample_net(pid, now, net_cum);
            let net = self.net_delta.get(&pid).copied().unwrap_or_default();

            if let Some(path) = &exe_path {
                self.request_verify(path);
            }
            let sig = self.sig_info_for(&exe_path);

            infos.push(ProcessInfo {
                pid,
                parent_pid,
                name,
                exe_path,
                cpu,
                cpu_history,
                mem_mb,
                io_bps: io.total_bps(),
                io_read_bps: io.read_bps,
                io_write_bps: io.write_bps,
                net_bps: net.total_bps(),
                net_rx_bps: net.rx_bps,
                net_tx_bps: net.tx_bps,
                sig,
            });
        }
        infos
    }

    fn resolve_exe_path(&mut self, pid: u32, sysinfo_exe: Option<String>) -> Option<String> {
        if let Some(cached) = self.exe_path_cache.get(&pid) {
            return cached.clone();
        }
        let resolved = sysinfo_exe
            .or_else(|| win::process_image_path(pid))
            .or_else(|| win::nt_image_path(pid));
        self.exe_path_cache.insert(pid, resolved.clone());
        resolved
    }

    fn sample_io(&mut self, pid: u32, now: Instant) {
        let Some(sample) = win::io_counters(pid) else {
            return;
        };
        self.io_total.insert(pid, sample);
        let delta = match self.io_state.get(&pid) {
            Some((prev, prev_at)) => {
                let dt = now.duration_since(*prev_at).as_secs_f64();
                if dt > 0.0 {
                    IoDelta {
                        read_bps: sample.read.saturating_sub(prev.read) as f64 / dt,
                        write_bps: sample.write.saturating_sub(prev.write) as f64 / dt,
                        other_bps: sample.other.saturating_sub(prev.other) as f64 / dt,
                    }
                } else {
                    IoDelta::default()
                }
            }
            None => IoDelta::default(),
        };
        self.io_state.insert(pid, (sample, now));
        self.io_delta.insert(pid, delta);
    }

    fn sample_net(&mut self, pid: u32, now: Instant, cum: etw::NetBytes) {
        // Every PID present in the process table gets an entry, even if it
        // hasn't transferred any bytes yet — that way the first delta after
        // the process starts sending is real, not "cum - 0" which would spike.
        let delta = match self.net_state.get(&pid) {
            Some((prev, prev_at)) => {
                let dt = now.duration_since(*prev_at).as_secs_f64();
                if dt > 0.0 {
                    NetDelta {
                        rx_bps: cum.rx.saturating_sub(prev.rx) as f64 / dt,
                        tx_bps: cum.tx.saturating_sub(prev.tx) as f64 / dt,
                    }
                } else {
                    NetDelta::default()
                }
            }
            None => NetDelta::default(),
        };
        self.net_state.insert(pid, (cum, now));
        self.net_total.insert(pid, cum);
        self.net_delta.insert(pid, delta);

        let hist = self.net_history.entry(pid).or_default();
        if hist.len() >= HISTORY_LEN {
            hist.pop_front();
        }
        hist.push_back(delta.total_bps());
    }

    fn build_parent_chain(&self, mut ppid: Option<Pid>, max_hops: usize) -> Vec<ParentEntry> {
        let mut out = Vec::new();
        for _ in 0..max_hops {
            let Some(pid) = ppid else { break };
            match self.sys.process(pid) {
                Some(p) => {
                    out.push(ParentEntry {
                        pid: pid.as_u32(),
                        name: p.name().to_string_lossy().into_owned(),
                    });
                    ppid = p.parent();
                }
                None => {
                    out.push(ParentEntry {
                        pid: pid.as_u32(),
                        name: "?".to_string(),
                    });
                    break;
                }
            }
        }
        out
    }

    fn ensure_dlls(&mut self, pid: u32) {
        if self.dll_cache.contains_key(&pid) {
            return;
        }
        let result = win::enum_dlls(pid);
        self.dll_cache.insert(pid, result);
    }

    fn ensure_handles(&mut self, pid: u32) {
        if self.handles_cache.contains_key(&pid) {
            return;
        }
        let result = handles::enum_handles(pid);
        self.handles_cache.insert(pid, result);
    }

    fn build_detail(&mut self, pid: u32) -> Option<ProcessDetail> {
        // Refresh workers so newly-arrived sigs land in the response.
        self.drain_workers();

        let pid_sysinfo = Pid::from_u32(pid);
        let (name, cmd, user, uptime_seconds, parent_pid, sys_exe, environ) = {
            let proc = self.sys.process(pid_sysinfo)?;
            let cmd: Vec<String> = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            let user = proc
                .user_id()
                .and_then(|uid| self.users.get_user_by_id(uid))
                .map(|u| u.name().to_string());
            let environ: Vec<EnvEntry> = proc
                .environ()
                .iter()
                .filter_map(|entry| {
                    let s = entry.to_string_lossy();
                    let (k, v) = s.split_once('=')?;
                    Some(EnvEntry {
                        key: k.to_string(),
                        value: v.to_string(),
                    })
                })
                .collect();
            (
                proc.name().to_string_lossy().into_owned(),
                cmd,
                user,
                proc.run_time(),
                proc.parent(),
                proc.exe().map(|e| e.to_string_lossy().into_owned()),
                environ,
            )
        };

        let parent_chain = self.build_parent_chain(parent_pid, 3);
        let exe_path = self.resolve_exe_path(pid, sys_exe);

        let io_delta = self.io_delta.get(&pid).copied().unwrap_or_default();
        let io_total = self.io_total.get(&pid).copied().unwrap_or_default();
        let net_delta = self.net_delta.get(&pid).copied().unwrap_or_default();
        let net_total = self.net_total.get(&pid).copied().unwrap_or_default();
        let cpu_history: Vec<f32> = self
            .cpu_history
            .get(&pid)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default();
        let mem_history: Vec<f64> = self
            .mem_history
            .get(&pid)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default();
        let net_history: Vec<f64> = self
            .net_history
            .get(&pid)
            .map(|h| h.iter().copied().collect())
            .unwrap_or_default();
        let cpu = cpu_history.last().copied().unwrap_or(0.0);
        let mem_mb = mem_history.last().copied().unwrap_or(0.0);

        if let Some(p) = &exe_path {
            self.request_verify(p);
        }
        let sig = self.sig_info_for(&exe_path);
        let exe_sha256 = exe_path.as_ref().and_then(|p| self.hash_exe(p));

        // Connections + DNS enqueue for public remotes
        let conns_raw: Vec<net::Connection> = self
            .net_snapshot
            .iter()
            .filter(|c| c.pid == pid)
            .cloned()
            .collect();
        for c in &conns_raw {
            if let Some(rem) = c.remote {
                self.request_dns(rem.ip());
            }
        }
        let connections: Vec<ConnectionInfo> = conns_raw
            .iter()
            .map(|c| {
                let hostname = c
                    .remote
                    .and_then(|r| self.dns_cache.get(&r.ip()).cloned().flatten());
                let country = c
                    .remote
                    .filter(|r| !dns::is_private_or_loopback(r.ip()))
                    .and_then(|r| self.geoip.country(r.ip()));
                ConnectionInfo {
                    proto: c.proto.to_string(),
                    local: c.local.to_string(),
                    remote: c.remote.map(|r| r.to_string()),
                    remote_ip: c.remote.map(|r| r.ip().to_string()),
                    hostname,
                    country,
                    state: if c.state == 0 {
                        None
                    } else {
                        Some(net::tcp_state_name(c.state))
                    },
                }
            })
            .collect();

        // DLLs
        self.ensure_dlls(pid);
        let dlls = match self.dll_cache.get(&pid).cloned().unwrap() {
            Ok(paths) => {
                // Request sig on each; get status snapshot
                for path in &paths {
                    self.request_verify(path);
                }
                let entries: Vec<DllEntry> = paths
                    .iter()
                    .map(|path| {
                        let (base, _) = split_path(path);
                        DllEntry {
                            path: path.clone(),
                            name: base,
                            sig: self.sig_info_for(&Some(path.clone())),
                        }
                    })
                    .collect();
                let unsigned_count = entries
                    .iter()
                    .filter(|e| e.sig.status == "unsigned")
                    .count();
                DllsResult::Ok { entries, unsigned_count }
            }
            Err(msg) => DllsResult::Denied(msg),
        };

        Some(ProcessDetail {
            pid,
            name,
            exe_path,
            exe_sha256,
            cmd,
            user,
            parent_chain,
            uptime_seconds,
            sig,
            cpu,
            mem_mb,
            cpu_history,
            mem_history,
            io_read_bps: io_delta.read_bps,
            io_write_bps: io_delta.write_bps,
            io_other_bps: io_delta.other_bps,
            io_read_total: io_total.read,
            io_write_total: io_total.write,
            io_other_total: io_total.other,
            net_rx_bps: net_delta.rx_bps,
            net_tx_bps: net_delta.tx_bps,
            net_rx_total: net_total.rx,
            net_tx_total: net_total.tx,
            net_history,
            connections,
            dlls,
            threads: match threads::enum_threads(pid) {
                Ok(v) => ThreadsResult::Ok(v),
                Err(e) => ThreadsResult::Error(e),
            },
            handles: {
                self.ensure_handles(pid);
                match self.handles_cache.get(&pid).cloned().unwrap() {
                    Ok(v) => HandlesResult::Ok(v),
                    Err(e) => HandlesResult::Error(e),
                }
            },
            environ,
        })
    }

    fn kill(&mut self, pid: u32) -> Result<(), String> {
        match self.sys.process(Pid::from_u32(pid)) {
            Some(p) if p.kill() => Ok(()),
            Some(_) => Err(format!("kill failed for PID {}", pid)),
            None => Err(format!("no such PID {}", pid)),
        }
    }
}

fn split_path(full: &str) -> (String, String) {
    match full.rfind(['\\', '/']) {
        Some(i) => (full[i + 1..].to_string(), full[..i].to_string()),
        None => (full.to_string(), String::new()),
    }
}

fn compute_sha256(path: &str) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    Some(s)
}

// ---------- Tauri commands ----------

type Shared = Mutex<AppState>;

#[tauri::command]
fn list_processes(state: State<'_, Shared>) -> Vec<ProcessInfo> {
    let mut app = state.lock().unwrap();
    app.refresh_and_list()
}

#[tauri::command]
fn get_process_detail(pid: u32, state: State<'_, Shared>) -> Option<ProcessDetail> {
    let mut app = state.lock().unwrap();
    app.build_detail(pid)
}

#[tauri::command]
fn kill_process(pid: u32, state: State<'_, Shared>) -> Result<(), String> {
    let mut app = state.lock().unwrap();
    app.kill(pid)
}

#[tauri::command]
fn net_monitor_active(state: State<'_, Shared>) -> bool {
    state.lock().unwrap().net_monitor.is_some()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let geoip_path = app
                .path()
                .resource_dir()
                .ok()
                .map(|p| p.join("GeoLite2-Country.mmdb"));
            app.manage(Mutex::new(AppState::new(geoip_path)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_processes,
            get_process_detail,
            kill_process,
            net_monitor_active
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
