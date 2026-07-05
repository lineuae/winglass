use std::ffi::c_void;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_DATA_STATE_ACTION,
    WINTRUST_DATA_UICHOICE, WINTRUST_DATA_UICONTEXT, WINTRUST_DATA_UNION_CHOICE, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
};

use crate::types::SigInfo;

const NO_SIGNATURE: i32 = 0x800B0100u32 as i32;

#[derive(Clone, Debug)]
pub enum SigStatus {
    Valid { signer: String, is_ms_windows: bool },
    Unsigned,
    Failed(u32),
}

impl SigStatus {
    pub fn to_info(&self) -> SigInfo {
        match self {
            SigStatus::Valid { signer, is_ms_windows } => SigInfo {
                status: "valid",
                signer: Some(signer.clone()),
                is_ms_windows: *is_ms_windows,
                error_code: None,
            },
            SigStatus::Unsigned => SigInfo {
                status: "unsigned",
                signer: None,
                is_ms_windows: false,
                error_code: None,
            },
            SigStatus::Failed(code) => SigInfo {
                status: "failed",
                signer: None,
                is_ms_windows: false,
                error_code: Some(*code),
            },
        }
    }
}

struct RawResult {
    rc: i32,
    signer: Option<String>,
}

fn make_valid(signer: Option<String>) -> SigStatus {
    let signer = signer.unwrap_or_else(|| "(unknown signer)".to_string());
    let is_ms_windows = signer.starts_with("Microsoft Windows");
    SigStatus::Valid { signer, is_ms_windows }
}

pub fn start_worker() -> (Sender<String>, Receiver<(String, SigStatus)>) {
    let (req_tx, req_rx) = channel::<String>();
    let (res_tx, res_rx) = channel();
    thread::spawn(move || {
        while let Ok(path) = req_rx.recv() {
            let status = unsafe { verify(&path) };
            if res_tx.send((path, status)).is_err() {
                break;
            }
        }
    });
    (req_tx, res_rx)
}

unsafe fn verify(path: &str) -> SigStatus {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let direct = verify_pe_file(&wide);
    if direct.rc == 0 {
        return make_valid(direct.signer);
    }
    if direct.rc == NO_SIGNATURE {
        if let Some(cat) = verify_via_catalog(&wide) {
            if cat.rc == 0 {
                return make_valid(cat.signer);
            }
        }
        return SigStatus::Unsigned;
    }
    SigStatus::Failed(direct.rc as u32)
}

unsafe fn verify_pe_file(wide: &[u16]) -> RawResult {
    let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
    file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = PCWSTR(wide.as_ptr());
    file_info.hFile = HANDLE::default();

    let mut trust_data: WINTRUST_DATA = std::mem::zeroed();
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WINTRUST_DATA_UICHOICE(WTD_UI_NONE.0);
    trust_data.fdwRevocationChecks = WINTRUST_DATA_REVOCATION_CHECKS(WTD_REVOKE_NONE.0);
    trust_data.dwUnionChoice = WINTRUST_DATA_UNION_CHOICE(WTD_CHOICE_FILE.0);
    trust_data.Anonymous = WINTRUST_DATA_0 {
        pFile: &mut file_info as *mut _,
    };
    trust_data.dwStateAction = WINTRUST_DATA_STATE_ACTION(WTD_STATEACTION_VERIFY.0);
    trust_data.hWVTStateData = HANDLE::default();
    trust_data.pwszURLReference = PWSTR(std::ptr::null_mut());
    trust_data.dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS(0);
    trust_data.dwUIContext = WINTRUST_DATA_UICONTEXT(0);

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hwnd = HWND(0);
    let rc = WinVerifyTrust(hwnd, &mut action, &mut trust_data as *mut _ as *mut c_void);

    let signer = if rc == 0 {
        extract_signer(trust_data.hWVTStateData)
    } else {
        None
    };

    trust_data.dwStateAction = WINTRUST_DATA_STATE_ACTION(WTD_STATEACTION_CLOSE.0);
    let _ = WinVerifyTrust(hwnd, &mut action, &mut trust_data as *mut _ as *mut c_void);
    RawResult { rc, signer }
}

unsafe fn extract_signer(state: HANDLE) -> Option<String> {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
    if sgnr.is_null() {
        return None;
    }
    let cert = WTHelperGetProvCertFromChain(sgnr, 0);
    if cert.is_null() {
        return None;
    }
    let cert_ctx = (*cert).pCert;
    if cert_ctx.is_null() {
        return None;
    }

    let mut buf = [0u16; 256];
    let len = CertGetNameStringW(
        cert_ctx,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        None,
        Some(&mut buf),
    );
    if len <= 1 {
        return None;
    }
    let end = (len as usize).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..end]))
}

unsafe fn verify_via_catalog(wide: &[u16]) -> Option<RawResult> {
    let mut h_admin: isize = 0;
    if CryptCATAdminAcquireContext2(&mut h_admin, None, w!("SHA256"), None, 0).is_err() {
        return None;
    }

    let h_file = CreateFileW(
        PCWSTR(wide.as_ptr()),
        FILE_GENERIC_READ.0,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        HANDLE::default(),
    );
    let Ok(h_file) = h_file else {
        let _ = CryptCATAdminReleaseContext(h_admin, 0);
        return None;
    };

    let mut hash_size: u32 = 0;
    let _ = CryptCATAdminCalcHashFromFileHandle2(h_admin, h_file, &mut hash_size, None, 0);
    if hash_size == 0 {
        let _ = CloseHandle(h_file);
        let _ = CryptCATAdminReleaseContext(h_admin, 0);
        return None;
    }
    let mut hash = vec![0u8; hash_size as usize];
    if CryptCATAdminCalcHashFromFileHandle2(
        h_admin,
        h_file,
        &mut hash_size,
        Some(hash.as_mut_ptr()),
        0,
    )
    .is_err()
    {
        let _ = CloseHandle(h_file);
        let _ = CryptCATAdminReleaseContext(h_admin, 0);
        return None;
    }

    let h_cat_info = CryptCATAdminEnumCatalogFromHash(h_admin, &hash, 0, None);
    if h_cat_info == 0 {
        let _ = CloseHandle(h_file);
        let _ = CryptCATAdminReleaseContext(h_admin, 0);
        return None;
    }

    let mut cat_info: CATALOG_INFO = std::mem::zeroed();
    cat_info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
    let ok = CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info, 0);

    let result = if ok.is_ok() {
        let cat_len = cat_info
            .wszCatalogFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(cat_info.wszCatalogFile.len());
        let cat_wide: Vec<u16> = cat_info.wszCatalogFile[..cat_len]
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect();
        Some(verify_pe_file(&cat_wide))
    } else {
        None
    };

    let _ = CryptCATAdminReleaseCatalogContext(h_admin, h_cat_info, 0);
    let _ = CloseHandle(h_file);
    let _ = CryptCATAdminReleaseContext(h_admin, 0);
    result
}
