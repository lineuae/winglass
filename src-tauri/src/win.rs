use std::ffi::c_void;
use std::sync::OnceLock;

use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HMODULE};
use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{
    GetProcessIoCounters, OpenProcess, QueryFullProcessImageNameW, IO_COUNTERS,
    PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

use crate::types::IoSample;

const SYSTEM_PROCESS_ID_INFORMATION: i32 = 88;

#[repr(C)]
struct UnicodeString {
    length: u16,
    max_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct SystemProcessIdInfo {
    process_id: usize,
    image_name: UnicodeString,
}

pub fn nt_image_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u16; 32768];
    let mut info = SystemProcessIdInfo {
        process_id: pid as usize,
        image_name: UnicodeString {
            length: 0,
            max_length: (buf.len() * 2) as u16,
            buffer: buf.as_mut_ptr(),
        },
    };
    let mut returned: u32 = 0;
    let status = unsafe {
        NtQuerySystemInformation(
            windows::Wdk::System::SystemInformation::SYSTEM_INFORMATION_CLASS(
                SYSTEM_PROCESS_ID_INFORMATION,
            ),
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<SystemProcessIdInfo>() as u32,
            &mut returned,
        )
    };
    if status.is_err() {
        return None;
    }
    let chars = info.image_name.length as usize / 2;
    if chars == 0 {
        return None;
    }
    let nt_path = String::from_utf16_lossy(&buf[..chars]);
    nt_to_win32_path(&nt_path)
}

fn nt_to_win32_path(nt_path: &str) -> Option<String> {
    let map = drive_map();
    map.iter()
        .find(|(nt_prefix, _)| nt_path.starts_with(nt_prefix.as_str()))
        .map(|(nt_prefix, letter)| format!("{}{}", letter, &nt_path[nt_prefix.len()..]))
}

fn drive_map() -> &'static Vec<(String, String)> {
    static CELL: OnceLock<Vec<(String, String)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut buf = [0u16; 512];
        let len = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) };
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        let mut entries: Vec<(String, String)> = s
            .split('\0')
            .filter(|s| !s.is_empty())
            .filter_map(|drive| {
                let letter: String = drive.chars().take(2).collect();
                let mut dev_buf = [0u16; 512];
                let letter_wide: Vec<u16> =
                    letter.encode_utf16().chain(std::iter::once(0)).collect();
                let n =
                    unsafe { QueryDosDeviceW(PCWSTR(letter_wide.as_ptr()), Some(&mut dev_buf)) };
                if n == 0 {
                    return None;
                }
                let end = dev_buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
                let nt_dev = String::from_utf16_lossy(&dev_buf[..end]);
                Some((nt_dev, letter))
            })
            .collect();
        entries.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
        entries
    })
}

pub fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 32768];
        let mut size = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

pub fn enum_dlls(pid: u32) -> Result<Vec<String>, String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(
            |e| match nt_process_protection(pid) {
                Some(p) if p.is_protected() => format!("protected process ({})", p.label()),
                _ => format!("access denied ({})", e.code().0),
            },
        )?;

        let mut modules = vec![HMODULE::default(); 1024];
        let mut needed: u32 = 0;
        let size = (modules.len() * std::mem::size_of::<HMODULE>()) as u32;

        let res = EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            size,
            &mut needed,
            LIST_MODULES_ALL,
        );
        if let Err(e) = res {
            let _ = CloseHandle(handle);
            return Err(format!("EnumProcessModulesEx failed ({})", e.code().0));
        }

        let count = ((needed as usize) / std::mem::size_of::<HMODULE>()).min(modules.len());
        let mut paths = Vec::with_capacity(count);
        let mut buf = [0u16; 32768];
        for i in 0..count {
            let len = GetModuleFileNameExW(handle, modules[i], &mut buf);
            if len > 0 {
                paths.push(String::from_utf16_lossy(&buf[..len as usize]));
            }
        }
        let _ = CloseHandle(handle);
        Ok(paths)
    }
}

pub struct ProcessProtection {
    pub protection_type: u8,
    pub signer_type: u8,
}

impl ProcessProtection {
    pub fn is_protected(&self) -> bool {
        self.protection_type > 0
    }

    pub fn label(&self) -> String {
        let ptype = match self.protection_type {
            1 => "PP",
            2 => "PPL",
            _ => return "unprotected".to_string(),
        };
        let signer = match self.signer_type {
            1 => "Authenticode",
            2 => "CodeGen",
            3 => "Antimalware",
            4 => "Lsa",
            5 => "Windows",
            6 => "WinTcb",
            7 => "WinSystem",
            8 => "App",
            _ => "Unknown",
        };
        format!("{}, {}", ptype, signer)
    }
}

const PROCESS_PROTECTION_INFO_CLASS: i32 = 61;

pub fn io_counters(pid: u32) -> Option<IoSample> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut c: IO_COUNTERS = std::mem::zeroed();
        let ok = GetProcessIoCounters(h, &mut c);
        let _ = CloseHandle(h);
        ok.ok()?;
        Some(IoSample {
            read: c.ReadTransferCount,
            write: c.WriteTransferCount,
            other: c.OtherTransferCount,
        })
    }
}

pub fn nt_process_protection(pid: u32) -> Option<ProcessProtection> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut byte: u8 = 0;
        let mut returned: u32 = 0;
        let status = NtQueryInformationProcess(
            handle,
            PROCESSINFOCLASS(PROCESS_PROTECTION_INFO_CLASS),
            &mut byte as *mut _ as *mut c_void,
            1,
            &mut returned,
        );
        let _ = CloseHandle(handle);
        if status.is_err() {
            return None;
        }
        Some(ProcessProtection {
            protection_type: byte & 0x7,
            signer_type: (byte >> 3) & 0xF,
        })
    }
}
