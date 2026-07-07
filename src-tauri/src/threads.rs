//! Per-process thread enumeration with wait reason resolution.
//!
//! `NtQuerySystemInformation(SystemProcessInformation, 5)` returns a linked
//! list of `SYSTEM_PROCESS_INFORMATION` records; the thread array for each
//! process follows its record inline. We walk the list, find the record for
//! the target PID, and unpack its thread table.
//!
//! The struct layout is stable on x64 Windows 10+/11. Rather than mirror the
//! whole ~40-field NT struct (which shifted subtly between builds), we read
//! the two fields we need — `NumberOfThreads` and `UniqueProcessId` — at
//! their fixed offsets and treat everything else as opaque padding. Threads
//! themselves start at offset 256 within the process record.

use std::ptr;

use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;

const SYSTEM_PROCESS_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(5);

// Offsets within SYSTEM_PROCESS_INFORMATION on x64 (modern layout).
const SPI_NEXT_ENTRY_OFFSET: usize = 0;
const SPI_NUMBER_OF_THREADS: usize = 4;
const SPI_UNIQUE_PROCESS_ID: usize = 80;
const SPI_HEADER_SIZE: usize = 256; // threads follow immediately after

// Offsets within SYSTEM_THREAD_INFORMATION on x64. Size = 80 bytes.
const STI_KERNEL_TIME: usize = 0;
const STI_USER_TIME: usize = 8;
// create_time @ 16, wait_time @ 24, then padding — none of which we surface
const STI_START_ADDRESS: usize = 32;
// client_id @ 40 (unique_process @ 40, unique_thread @ 48)
const STI_UNIQUE_THREAD: usize = 48;
const STI_PRIORITY: usize = 56;
const STI_BASE_PRIORITY: usize = 60;
const STI_CONTEXT_SWITCHES: usize = 64;
const STI_THREAD_STATE: usize = 68;
const STI_WAIT_REASON: usize = 72;
const STI_SIZE: usize = 80;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub state: &'static str,
    pub wait_reason: &'static str,
    pub priority: i32,
    pub base_priority: i32,
    pub context_switches: u32,
    pub user_time_100ns: i64,
    pub kernel_time_100ns: i64,
    pub start_address: u64,
}

pub fn enum_threads(pid: u32) -> Result<Vec<ThreadInfo>, String> {
    let buf = query_spi()?;
    let out = walk_for_pid(&buf, pid);
    if out.is_empty() {
        // We queried the system and the PID wasn't in the snapshot — race
        // between the sysinfo tick and now, or a very short-lived process.
        Err("process not found".to_string())
    } else {
        Ok(out)
    }
}

fn query_spi() -> Result<Vec<u8>, String> {
    // Start at 256 KiB — enough for a few hundred processes without a retry.
    let mut buf = vec![0u8; 256 * 1024];
    for _ in 0..8 {
        let mut ret_len = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut ret_len,
            )
        };
        if status.is_ok() {
            buf.truncate(ret_len as usize);
            return Ok(buf);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // The kernel tells us how much it wanted; double for headroom
            // because processes come and go while we retry.
            let want = ret_len as usize;
            buf.resize(want.saturating_mul(2).max(buf.len() * 2), 0);
            continue;
        }
        return Err(format!("NtQuerySystemInformation failed: 0x{:08X}", status.0));
    }
    Err("NtQuerySystemInformation kept asking for more buffer".to_string())
}

fn walk_for_pid(buf: &[u8], target_pid: u32) -> Vec<ThreadInfo> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset + SPI_HEADER_SIZE > buf.len() {
            return out;
        }
        let record = unsafe { buf.as_ptr().add(offset) };
        let next = unsafe { read_u32(record, SPI_NEXT_ENTRY_OFFSET) };
        let num_threads = unsafe { read_u32(record, SPI_NUMBER_OF_THREADS) };
        let this_pid = unsafe { read_usize(record, SPI_UNIQUE_PROCESS_ID) } as u32;

        if this_pid == target_pid {
            let threads_base = offset + SPI_HEADER_SIZE;
            for i in 0..num_threads as usize {
                let t_off = threads_base + i * STI_SIZE;
                // Bound each read against the buffer the kernel gave us, the
                // same guard collect_for_pid uses — a truncated record or a
                // misread thread count must stop the walk, not read past it.
                if t_off + STI_SIZE > buf.len() {
                    break;
                }
                let t = unsafe { buf.as_ptr().add(t_off) };
                out.push(read_thread(t));
            }
            return out;
        }

        if next == 0 {
            return out;
        }
        offset += next as usize;
    }
}

fn read_thread(t: *const u8) -> ThreadInfo {
    unsafe {
        let state = read_u32(t, STI_THREAD_STATE);
        let wait_reason = read_u32(t, STI_WAIT_REASON);
        ThreadInfo {
            tid: read_usize(t, STI_UNIQUE_THREAD) as u32,
            state: thread_state_name(state),
            wait_reason: wait_reason_name(wait_reason, state),
            priority: read_u32(t, STI_PRIORITY) as i32,
            base_priority: read_u32(t, STI_BASE_PRIORITY) as i32,
            context_switches: read_u32(t, STI_CONTEXT_SWITCHES),
            user_time_100ns: read_u64(t, STI_USER_TIME) as i64,
            kernel_time_100ns: read_u64(t, STI_KERNEL_TIME) as i64,
            start_address: read_u64(t, STI_START_ADDRESS),
        }
    }
}

unsafe fn read_u32(base: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(base.add(off) as *const u32)
}
unsafe fn read_u64(base: *const u8, off: usize) -> u64 {
    ptr::read_unaligned(base.add(off) as *const u64)
}
unsafe fn read_usize(base: *const u8, off: usize) -> usize {
    ptr::read_unaligned(base.add(off) as *const usize)
}

fn thread_state_name(s: u32) -> &'static str {
    match s {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        _ => "?",
    }
}

/// Only meaningful when the state is Waiting (5); returns an empty string
/// otherwise so the UI can skip it cleanly. The wait reason field is left
/// populated by the kernel for non-waiting threads but is stale/misleading.
fn wait_reason_name(r: u32, state: u32) -> &'static str {
    if state != 5 {
        return "";
    }
    match r {
        0 => "Executive",
        1 => "FreePage",
        2 => "PageIn",
        3 => "PoolAllocation",
        4 => "DelayExecution",
        5 => "Suspended",
        6 => "UserRequest",
        7 => "WrExecutive",
        8 => "WrFreePage",
        9 => "WrPageIn",
        10 => "WrPoolAllocation",
        11 => "WrDelayExecution",
        12 => "WrSuspended",
        13 => "WrUserRequest",
        14 => "WrEventPair",
        15 => "WrQueue",
        16 => "WrLpcReceive",
        17 => "WrLpcReply",
        18 => "WrVirtualMemory",
        19 => "WrPageOut",
        20 => "WrRendezvous",
        21 => "WrKeyedEvent",
        22 => "WrTerminated",
        23 => "WrProcessInSwap",
        24 => "WrCpuRateControl",
        25 => "WrCalloutStack",
        26 => "WrKernel",
        27 => "WrResource",
        28 => "WrPushLock",
        29 => "WrMutex",
        30 => "WrQuantumEnd",
        31 => "WrDispatchInt",
        32 => "WrPreempted",
        33 => "WrYieldExecution",
        34 => "WrFastMutex",
        35 => "WrGuardedMutex",
        36 => "WrRundown",
        37 => "WrAlertByThreadId",
        38 => "WrDeferredPreempt",
        _ => "?",
    }
}
