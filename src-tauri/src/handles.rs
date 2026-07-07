//! Per-process open handle enumeration.
//!
//! `NtQuerySystemInformation(SystemExtendedHandleInformation, 64)` returns
//! the entire kernel handle table system-wide. We walk it, keep only the
//! entries owned by the target PID, then resolve each entry's object type
//! name by duplicating one exemplar handle into our own process and calling
//! `NtQueryObject(ObjectTypeInformation)`. Type-name lookup is memoized
//! by `ObjectTypeIndex`, so a process with a thousand File handles only
//! triggers one type query.
//!
//! Object *names* (`ObjectNameInformation`) are resolved on a sacrificial
//! worker thread per handle with a 50 ms per-call timeout and a 2 s
//! total budget. Named pipes and some device objects can trap the query
//! in driver code forever — when that happens we walk away from the
//! thread and record None for that handle. The worker keeps the duplicated
//! handle it was given and closes it when the syscall eventually returns.
//!
//! Handle enumeration itself does not require elevation, but resolving
//! type names on protected processes fails at `OpenProcess(DUP_HANDLE)`.
//! We return whatever we could resolve and leave the rest with an empty
//! type — the UI groups the unknowns under "?".

use std::collections::HashMap;
use std::ptr;
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

use windows::Wdk::Foundation::{NtQueryObject, ObjectTypeInformation, OBJECT_INFORMATION_CLASS};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};

// windows-rs 0.57 exports ObjectTypeInformation but not ObjectNameInformation
// even though both are documented NT info classes. Canonical value = 1.
const OBJECT_NAME_INFORMATION: OBJECT_INFORMATION_CLASS = OBJECT_INFORMATION_CLASS(1);
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, STATUS_INFO_LENGTH_MISMATCH,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

/// Global budget for all name-resolution queries during a single
/// `enum_handles` call. Once this elapses, remaining names come back None
/// so the user still gets the panel before their next 1 Hz refresh.
const NAME_TOTAL_BUDGET: Duration = Duration::from_millis(2000);

/// Per-call timeout on NtQueryObject(ObjectNameInformation). Named pipes
/// and some device objects can block indefinitely inside a driver — after
/// this deadline we abandon the worker thread and record None.
const NAME_PER_CALL_TIMEOUT: Duration = Duration::from_millis(50);

const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(64);

// Offsets within SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX on x64. Size = 40 bytes.
const HTE_UNIQUE_PROCESS_ID: usize = 8;
const HTE_HANDLE_VALUE: usize = 16;
const HTE_GRANTED_ACCESS: usize = 24;
const HTE_OBJECT_TYPE_INDEX: usize = 30;
const HTE_SIZE: usize = 40;

// SYSTEM_HANDLE_INFORMATION_EX header on x64: NumberOfHandles + Reserved = 16 bytes.
const SHI_HEADER: usize = 16;

#[derive(Clone, Debug, serde::Serialize)]
pub struct HandleInfo {
    pub value: u64,
    pub type_name: String,
    pub granted_access: u32,
    /// Resolved object name (file path, key path, section name, …). None
    /// when NtQueryObject didn't respond within the per-call timeout, when
    /// the object simply has no name (many synchronization primitives),
    /// or when the global name-resolution budget was exhausted.
    pub name: Option<String>,
}

pub fn enum_handles(pid: u32) -> Result<Vec<HandleInfo>, String> {
    let buf = query_shi()?;
    let raw = collect_for_pid(&buf, pid);
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    // Open the target once and reuse its handle for every DuplicateHandle call.
    // Failing here is common for protected processes; we still return the raw
    // list, just with empty type_name/name for entries we can't resolve.
    let src = unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }.ok();
    let mut type_cache: HashMap<u16, String> = HashMap::new();
    let name_deadline = Instant::now() + NAME_TOTAL_BUDGET;

    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let dup = src.and_then(|s| duplicate_locally(s, r.handle_value));

        // Only memoize a *successful* lookup. Caching an empty string here
        // would poison the type index: if the first handle of a given type
        // happens to be one we can't duplicate, every later handle of that
        // same type would inherit the blank and never retry.
        let type_name = if let Some(cached) = type_cache.get(&r.type_index) {
            cached.clone()
        } else {
            match dup.and_then(query_type_name) {
                Some(n) => {
                    type_cache.insert(r.type_index, n.clone());
                    n
                }
                None => String::new(),
            }
        };

        // Name resolution takes ownership of `dup`. On success the worker
        // closes it; on timeout the worker is still using it, so we must
        // NOT close it here either — the leaked handle is released when
        // the worker eventually returns (or on process exit).
        let name = match dup {
            Some(d) if Instant::now() < name_deadline => query_name_with_timeout(d),
            Some(d) => {
                unsafe { CloseHandle(d).ok() };
                None
            }
            None => None,
        };

        out.push(HandleInfo {
            value: r.handle_value,
            type_name,
            granted_access: r.granted_access,
            name,
        });
    }

    if let Some(h) = src {
        unsafe { CloseHandle(h).ok() };
    }
    Ok(out)
}

fn query_shi() -> Result<Vec<u8>, String> {
    // Handle table is typically 1-4 MiB. Start at 4 MiB to skip most retries.
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    for _ in 0..8 {
        let mut ret_len = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
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
            let want = ret_len as usize;
            buf.resize(want.saturating_mul(2).max(buf.len() * 2), 0);
            continue;
        }
        return Err(format!("NtQuerySystemInformation failed: 0x{:08X}", status.0));
    }
    Err("NtQuerySystemInformation kept asking for more buffer".to_string())
}

struct RawHandle {
    handle_value: u64,
    granted_access: u32,
    type_index: u16,
}

fn collect_for_pid(buf: &[u8], target_pid: u32) -> Vec<RawHandle> {
    if buf.len() < SHI_HEADER {
        return Vec::new();
    }
    let count = unsafe { ptr::read_unaligned(buf.as_ptr() as *const usize) };
    let mut out = Vec::new();
    for i in 0..count {
        let off = SHI_HEADER + i * HTE_SIZE;
        if off + HTE_SIZE > buf.len() {
            break;
        }
        let base = unsafe { buf.as_ptr().add(off) };
        let pid = unsafe { ptr::read_unaligned(base.add(HTE_UNIQUE_PROCESS_ID) as *const usize) }
            as u32;
        if pid != target_pid {
            continue;
        }
        out.push(RawHandle {
            handle_value: unsafe {
                ptr::read_unaligned(base.add(HTE_HANDLE_VALUE) as *const usize) as u64
            },
            granted_access: unsafe {
                ptr::read_unaligned(base.add(HTE_GRANTED_ACCESS) as *const u32)
            },
            type_index: unsafe { ptr::read_unaligned(base.add(HTE_OBJECT_TYPE_INDEX) as *const u16) },
        });
    }
    out
}

fn duplicate_locally(src: HANDLE, foreign_handle: u64) -> Option<HANDLE> {
    let foreign = HANDLE(foreign_handle as isize);
    let me = unsafe { GetCurrentProcess() };
    let mut dup = HANDLE(0);
    let ok = unsafe {
        DuplicateHandle(
            src,
            foreign,
            me,
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok.is_err() {
        return None;
    }
    Some(dup)
}

fn query_type_name(dup: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut ret = 0u32;
    let status = unsafe {
        NtQueryObject(
            dup,
            ObjectTypeInformation,
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
            Some(&mut ret),
        )
    };
    if status.is_err() {
        return None;
    }
    read_unicode_string(&buf)
}

/// Runs NtQueryObject(ObjectNameInformation) on a sacrificial worker thread
/// and waits up to NAME_PER_CALL_TIMEOUT for a reply. Named pipes and some
/// device objects can trap this call inside a driver forever; when that
/// happens we walk away from the thread — it stays alive and eventually
/// releases `dup` when the syscall returns (or never, if the driver truly
/// hangs, in which case it dies with the process). The worker owns `dup`
/// from the moment we spawn it.
fn query_name_with_timeout(dup: HANDLE) -> Option<String> {
    // HANDLE isn't Send; smuggle it across the thread boundary as a raw
    // integer and rebuild it inside the worker.
    let dup_raw = dup.0 as usize;
    let (tx, rx) = sync_channel::<Option<String>>(1);
    std::thread::spawn(move || {
        let handle = HANDLE(dup_raw as isize);
        let name = query_object_name(handle);
        unsafe { CloseHandle(handle).ok() };
        let _ = tx.send(name);
    });
    rx.recv_timeout(NAME_PER_CALL_TIMEOUT).ok().flatten()
}

fn query_object_name(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let mut ret = 0u32;
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION,
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
            Some(&mut ret),
        )
    };
    if status.is_err() {
        return None;
    }
    read_unicode_string(&buf)
}

/// Decodes a UNICODE_STRING that the kernel wrote at the start of `buf`.
/// Layout on x64: USHORT Length, USHORT MaxLength, ULONG pad, PVOID Buffer.
/// The kernel patched Buffer to point inside `buf`; we sanity-check the
/// range so a malformed reply can't send us reading arbitrary memory.
fn read_unicode_string(buf: &[u8]) -> Option<String> {
    let length = unsafe { ptr::read_unaligned(buf.as_ptr() as *const u16) } as usize;
    let buffer_ptr = unsafe { ptr::read_unaligned(buf.as_ptr().add(8) as *const *const u16) };
    if length == 0 || buffer_ptr.is_null() {
        return None;
    }
    let base = buf.as_ptr() as usize;
    let end = base + buf.len();
    let start = buffer_ptr as usize;
    if start < base || start.saturating_add(length) > end {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(buffer_ptr, length / 2) };
    Some(String::from_utf16_lossy(slice))
}

