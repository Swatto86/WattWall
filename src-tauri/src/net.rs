//! Which programs currently have a TCP or UDP endpoint, and closing the TCP
//! connections of a program that was just blocked.
//!
//! Adding a firewall rule does not cut a connection Windows has already
//! allowed. IPv4 connections are closed with the documented SetTcpEntry.
//! IPv6 has no documented equivalent; the close uses NsiSetAllParameters in
//! nsi.dll, which is the call SetTcpEntry makes. No driver is loaded.

use std::collections::BTreeSet;
use std::fs;

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH,
    MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_LISTEN, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::programs::path_for_pid;

const CONNECTIONS: &str = "fake-connections.json";

pub enum Connections {
    Live,
    Fake(std::path::PathBuf),
}

impl Connections {
    pub fn snapshot(&self) -> Result<Vec<String>, String> {
        match self {
            Self::Live => live_snapshot(),
            Self::Fake(dir) => {
                let path = dir.join(CONNECTIONS);
                if !path.exists() {
                    return Ok(Vec::new());
                }
                let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
                serde_json::from_str(&text).map_err(|err| err.to_string())
            }
        }
    }

    /// Close TCP connections whose owning program is `path`. Returns how many
    /// were closed. UDP has no connection to cut; the firewall rule stops the
    /// next datagram.
    pub fn close_tcp(&self, path: &str) -> Result<u32, String> {
        match self {
            Self::Live => live_close(path),
            Self::Fake(_) => Ok(0),
        }
    }
}

fn live_snapshot() -> Result<Vec<String>, String> {
    let mut pids = BTreeSet::new();
    collect_pids(&mut pids)?;
    let mut paths = BTreeSet::new();
    for pid in pids {
        if let Some(path) = path_for_pid(pid) {
            paths.insert(path);
        }
    }
    Ok(paths.into_iter().collect())
}

fn collect_pids(pids: &mut BTreeSet<u32>) -> Result<(), String> {
    row_pids::<MIB_TCPROW_OWNER_PID>(AF_INET.0 as u32, true, pids)?;
    row_pids::<MIB_TCP6ROW_OWNER_PID>(AF_INET6.0 as u32, true, pids)?;
    row_pids::<MIB_UDPROW_OWNER_PID>(AF_INET.0 as u32, false, pids)?;
    row_pids::<MIB_UDP6ROW_OWNER_PID>(AF_INET6.0 as u32, false, pids)?;
    Ok(())
}

fn row_pids<T: Copy>(family: u32, tcp: bool, pids: &mut BTreeSet<u32>) -> Result<(), String> {
    let rows = table(family, tcp)?;
    let size = std::mem::size_of::<T>();
    if rows.len() < 4 {
        return Ok(());
    }
    let count = u32::from_ne_bytes(rows[0..4].try_into().unwrap_or([0; 4])) as usize;
    for index in 0..count {
        let start = 4 + index * size;
        let end = start + size;
        if end > rows.len() {
            break;
        }
        let pid_offset = size - 4;
        let pid = u32::from_ne_bytes(
            rows[start + pid_offset..start + pid_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if pid > 0 {
            pids.insert(pid);
        }
    }
    Ok(())
}

fn table(family: u32, tcp: bool) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    let first = unsafe {
        if tcp {
            GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
        }
    };
    // 122 is ERROR_INSUFFICIENT_BUFFER, which is the expected first answer.
    if first != 0 && first != 122 {
        return Err(format!("Could not read the connection table ({first})."));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; size as usize + 64];
    let mut size = buf.len() as u32;
    let second = unsafe {
        if tcp {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        } else {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut size,
                false,
                family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    };
    if second != 0 {
        return Err(format!("Could not read the connection table ({second})."));
    }
    buf.truncate(size as usize);
    Ok(buf)
}

fn live_close(path: &str) -> Result<u32, String> {
    let want = path.to_ascii_lowercase();
    let mut closed = 0u32;
    closed += close_v4(&want)?;
    closed += close_v6(&want)?;
    Ok(closed)
}

fn close_v4(want: &str) -> Result<u32, String> {
    let rows = table(AF_INET.0 as u32, true)?;
    let size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    if rows.len() < 4 {
        return Ok(0);
    }
    let count = u32::from_ne_bytes(rows[0..4].try_into().unwrap_or([0; 4]));
    let mut closed = 0u32;
    for index in 0..count as usize {
        let start = 4 + index * size;
        if start + size > rows.len() {
            break;
        }
        let row = unsafe {
            rows[start..]
                .as_ptr()
                .cast::<MIB_TCPROW_OWNER_PID>()
                .read_unaligned()
        };
        if row.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || row.dwOwningPid == 0 {
            continue;
        }
        let Some(owner) = path_for_pid(row.dwOwningPid) else {
            continue;
        };
        if owner.to_ascii_lowercase() != want {
            continue;
        }
        let delete = MIB_TCPROW_LH {
            Anonymous: windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_LH_0 {
                dwState: MIB_TCP_STATE_DELETE_TCB.0 as u32,
            },
            dwLocalAddr: row.dwLocalAddr,
            dwLocalPort: row.dwLocalPort,
            dwRemoteAddr: row.dwRemoteAddr,
            dwRemotePort: row.dwRemotePort,
        };
        let result = unsafe { SetTcpEntry(&delete) };
        if result == 0 {
            closed += 1;
        }
    }
    Ok(closed)
}

fn close_v6(want: &str) -> Result<u32, String> {
    let rows = table(AF_INET6.0 as u32, true)?;
    let size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    if rows.len() < 4 {
        return Ok(0);
    }
    let count = u32::from_ne_bytes(rows[0..4].try_into().unwrap_or([0; 4]));
    let mut closed = 0u32;
    for index in 0..count as usize {
        let start = 4 + index * size;
        if start + size > rows.len() {
            break;
        }
        let row = unsafe {
            rows[start..]
                .as_ptr()
                .cast::<MIB_TCP6ROW_OWNER_PID>()
                .read_unaligned()
        };
        if row.dwState == MIB_TCP_STATE_LISTEN.0 as u32 || row.dwOwningPid == 0 {
            continue;
        }
        let Some(owner) = path_for_pid(row.dwOwningPid) else {
            continue;
        };
        if owner.to_ascii_lowercase() != want {
            continue;
        }
        if nsi_kill_v6(&row) {
            closed += 1;
        }
    }
    Ok(closed)
}

/// Layout taken from the same call SetTcpEntry makes, extended to IPv6.
/// `NPI_MS_TCP_MODULEID` is the published TCP module id (eb004a03-9b1a-11d4-9123-0050047759bc).
fn nsi_kill_v6(row: &MIB_TCP6ROW_OWNER_PID) -> bool {
    #[repr(C)]
    struct KillV6 {
        local_family: u16,
        local_port: u16,
        reserved1: [u8; 4],
        local_addr: [u8; 16],
        local_scope: u32,
        remote_family: u16,
        remote_port: u16,
        reserved2: [u8; 4],
        remote_addr: [u8; 16],
        remote_scope: u32,
    }
    // NPI_MODULEID: length 24, type GUID (1), then the TCP module GUID.
    let module: [u8; 24] = [
        0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4,
        0x11, 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC,
    ];
    let kill = KillV6 {
        local_family: AF_INET6.0,
        local_port: row.dwLocalPort as u16,
        reserved1: [0; 4],
        local_addr: row.ucLocalAddr,
        local_scope: row.dwLocalScopeId,
        remote_family: AF_INET6.0,
        remote_port: row.dwRemotePort as u16,
        reserved2: [0; 4],
        remote_addr: row.ucRemoteAddr,
        remote_scope: row.dwRemoteScopeId,
    };
    type SetFn =
        unsafe extern "system" fn(u32, u32, *const u8, u32, *const u8, u32, *const u8, u32) -> u32;
    let handle = unsafe {
        windows::Win32::System::LibraryLoader::LoadLibraryW(windows::core::w!("nsi.dll"))
    };
    let Ok(handle) = handle else { return false };
    let proc = unsafe {
        windows::Win32::System::LibraryLoader::GetProcAddress(
            handle,
            windows::core::s!("NsiSetAllParameters"),
        )
    };
    let Some(proc) = proc else { return false };
    let set: SetFn = unsafe { std::mem::transmute(proc) };
    let code = unsafe {
        set(
            1,
            2,
            module.as_ptr(),
            16,
            (&raw const kill).cast(),
            std::mem::size_of::<KillV6>() as u32,
            std::ptr::null(),
            0,
        )
    };
    code == 0
}
