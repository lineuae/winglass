use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Once;
use std::thread;

use windows::Win32::Networking::WinSock::{
    socklen_t, GetNameInfoW, WSAStartup, AF_INET, AF_INET6, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, WSADATA,
};

fn init_winsock() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let mut wsa: MaybeUninit<WSADATA> = MaybeUninit::uninit();
        let _ = WSAStartup(0x0202, wsa.as_mut_ptr());
    });
}

pub fn start_worker() -> (Sender<IpAddr>, Receiver<(IpAddr, Option<String>)>) {
    init_winsock();
    let (req_tx, req_rx) = channel::<IpAddr>();
    let (res_tx, res_rx) = channel();
    thread::spawn(move || {
        while let Ok(ip) = req_rx.recv() {
            let name = unsafe { resolve(ip) };
            if res_tx.send((ip, name)).is_err() {
                break;
            }
        }
    });
    (req_tx, res_rx)
}

unsafe fn resolve(ip: IpAddr) -> Option<String> {
    // Sockaddr MUST outlive GetNameInfoW; keeping both variants at function
    // scope ensures the pointer stays valid across the call.
    let mut sa4: SOCKADDR_IN = std::mem::zeroed();
    let mut sa6: SOCKADDR_IN6 = std::mem::zeroed();
    let (sockaddr, len) = match ip {
        IpAddr::V4(v4) => {
            sa4.sin_family = AF_INET;
            sa4.sin_port = 0;
            sa4.sin_addr.S_un.S_addr = u32::from(v4).to_be();
            (
                &sa4 as *const _ as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            )
        }
        IpAddr::V6(v6) => {
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = 0;
            sa6.sin6_addr.u.Byte = v6.octets();
            (
                &sa6 as *const _ as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_IN6>() as i32,
            )
        }
    };

    let mut host = [0u16; 256];
    let rc = GetNameInfoW(
        sockaddr,
        socklen_t(len),
        Some(&mut host),
        None,
        NI_NAMEREQD as i32,
    );
    if rc != 0 {
        return None;
    }
    let n = host.iter().position(|&c| c == 0).unwrap_or(host.len());
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&host[..n]))
}

pub fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        || (v6.segments()[0] & 0xffc0) == 0xfe80
}
