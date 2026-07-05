use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone, Debug)]
pub struct Connection {
    pub pid: u32,
    pub proto: &'static str,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: u32,
}

pub fn snapshot() -> Vec<Connection> {
    let mut out = Vec::new();
    unsafe {
        collect_tcp4(&mut out);
        collect_tcp6(&mut out);
        collect_udp4(&mut out);
        collect_udp6(&mut out);
    }
    out
}

pub fn tcp_state_name(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "?",
    }
}

fn port_from_dword(dw: u32) -> u16 {
    (dw as u16).swap_bytes()
}

fn ipv4_from_dword(dw: u32) -> Ipv4Addr {
    let b = dw.to_le_bytes();
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

unsafe fn get_table<F: Fn(Option<*mut c_void>, *mut u32) -> u32>(call: F) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    let _ = call(None, &mut size);
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = call(Some(buf.as_mut_ptr() as *mut c_void), &mut size);
    if rc != NO_ERROR.0 {
        return None;
    }
    Some(buf)
}

unsafe fn collect_tcp4(out: &mut Vec<Connection>) {
    let Some(buf) = get_table(|ptr, size| {
        GetExtendedTcpTable(ptr, size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return;
    };
    let count = *(buf.as_ptr() as *const u32) as usize;
    let rows_ptr = buf.as_ptr().add(std::mem::size_of::<u32>()) as *const MIB_TCPROW_OWNER_PID;
    for i in 0..count {
        let r = &*rows_ptr.add(i);
        let local = SocketAddr::new(
            IpAddr::V4(ipv4_from_dword(r.dwLocalAddr)),
            port_from_dword(r.dwLocalPort),
        );
        let remote_addr = ipv4_from_dword(r.dwRemoteAddr);
        let remote_port = port_from_dword(r.dwRemotePort);
        let remote = if remote_addr.is_unspecified() && remote_port == 0 {
            None
        } else {
            Some(SocketAddr::new(IpAddr::V4(remote_addr), remote_port))
        };
        out.push(Connection {
            pid: r.dwOwningPid,
            proto: "TCP",
            local,
            remote,
            state: r.dwState,
        });
    }
}

unsafe fn collect_tcp6(out: &mut Vec<Connection>) {
    let Some(buf) = get_table(|ptr, size| {
        GetExtendedTcpTable(ptr, size, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return;
    };
    let count = *(buf.as_ptr() as *const u32) as usize;
    let rows_ptr = buf.as_ptr().add(std::mem::size_of::<u32>()) as *const MIB_TCP6ROW_OWNER_PID;
    for i in 0..count {
        let r = &*rows_ptr.add(i);
        let local = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
            port_from_dword(r.dwLocalPort),
        );
        let remote_addr = Ipv6Addr::from(r.ucRemoteAddr);
        let remote_port = port_from_dword(r.dwRemotePort);
        let remote = if remote_addr.is_unspecified() && remote_port == 0 {
            None
        } else {
            Some(SocketAddr::new(IpAddr::V6(remote_addr), remote_port))
        };
        out.push(Connection {
            pid: r.dwOwningPid,
            proto: "TCP6",
            local,
            remote,
            state: r.dwState,
        });
    }
}

unsafe fn collect_udp4(out: &mut Vec<Connection>) {
    let Some(buf) = get_table(|ptr, size| {
        GetExtendedUdpTable(ptr, size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return;
    };
    let count = *(buf.as_ptr() as *const u32) as usize;
    let rows_ptr = buf.as_ptr().add(std::mem::size_of::<u32>()) as *const MIB_UDPROW_OWNER_PID;
    for i in 0..count {
        let r = &*rows_ptr.add(i);
        let local = SocketAddr::new(
            IpAddr::V4(ipv4_from_dword(r.dwLocalAddr)),
            port_from_dword(r.dwLocalPort),
        );
        out.push(Connection {
            pid: r.dwOwningPid,
            proto: "UDP",
            local,
            remote: None,
            state: 0,
        });
    }
}

unsafe fn collect_udp6(out: &mut Vec<Connection>) {
    let Some(buf) = get_table(|ptr, size| {
        GetExtendedUdpTable(ptr, size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return;
    };
    let count = *(buf.as_ptr() as *const u32) as usize;
    let rows_ptr = buf.as_ptr().add(std::mem::size_of::<u32>()) as *const MIB_UDP6ROW_OWNER_PID;
    for i in 0..count {
        let r = &*rows_ptr.add(i);
        let local = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
            port_from_dword(r.dwLocalPort),
        );
        out.push(Connection {
            pid: r.dwOwningPid,
            proto: "UDP6",
            local,
            remote: None,
            state: 0,
        });
    }
}
