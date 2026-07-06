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
//! We deliberately do NOT resolve object *names* (`ObjectNameInformation`).
//! For pipes and some device objects, that call reaches into driver code
//! that can block indefinitely; Process Explorer solves this with a
//! dedicated worker thread that gets terminated on timeout. Adding that
//! plumbing is a follow-up; for now the panel shows type + handle value +
//! access mask, which is enough to see the shape of a process's kernel
//! footprint.
//!
//! Handle enumeration itself does not require elevation, but resolving
//! type names on protected processes fails at `OpenProcess(DUP_HANDLE)`.
//! We return whatever we could resolve and leave the rest with an empty
//! type — the UI groups the unknowns under "?".

use std::collections::HashMap;
use std::ptr;

use windows::Wdk::Foundation::{NtQueryObject, ObjectTypeInformation};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, STATUS_INFO_LENGTH_MISMATCH,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

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
}

pub fn enum_handles(pid: u32) -> Result<Vec<HandleInfo>, String> {
    let buf = query_shi()?;
    let raw = collect_for_pid(&buf, pid);
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    // Open the target once and reuse its handle for every DuplicateHandle call.
    // Failing here is common for protected processes; we still return the raw
    // list, just with empty type_name for entries we can't resolve.
    let src = unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }.ok();
    let mut type_cache: HashMap<u16, String> = HashMap::new();

    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let type_name = if let Some(n) = type_cache.get(&r.type_index) {
            n.clone()
        } else {
            let n = src
                .as_ref()
                .and_then(|src| resolve_type_name(*src, r.handle_value))
                .unwrap_or_default();
            type_cache.insert(r.type_index, n.clone());
            n
        };
        out.push(HandleInfo {
            value: r.handle_value,
            type_name,
            granted_access: r.granted_access,
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

fn resolve_type_name(src: HANDLE, foreign_handle: u64) -> Option<String> {
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

    // 4 KiB is more than enough for OBJECT_TYPE_INFORMATION + the type name.
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
    let _ = unsafe { CloseHandle(dup) };
    if status.is_err() {
        return None;
    }

    // Struct starts with UNICODE_STRING TypeName at offset 0 on x64:
    //   USHORT Length; USHORT MaxLength; ULONG pad; PVOID Buffer;
    let length = unsafe { ptr::read_unaligned(buf.as_ptr() as *const u16) } as usize;
    let buffer_ptr = unsafe { ptr::read_unaligned(buf.as_ptr().add(8) as *const *const u16) };
    if length == 0 || buffer_ptr.is_null() {
        return None;
    }

    // The kernel patched Buffer to point inside our buffer; sanity-check the
    // range so a malformed reply can't send us reading arbitrary memory.
    let base = buf.as_ptr() as usize;
    let end = base + buf.len();
    let start = buffer_ptr as usize;
    if start < base || start.saturating_add(length) > end {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(buffer_ptr, length / 2) };
    Some(String::from_utf16_lossy(slice))
}

