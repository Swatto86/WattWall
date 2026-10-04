//! The raw TCP and UDP tables, as Windows lays them out: a row count, then
//! fixed-size rows. `net.rs` reads them to list programs and to close
//! connections, `sockets.rs` for the Connections view.

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

/// ERROR_INSUFFICIENT_BUFFER: the answer to a size query, and what a table
/// that grew between the size query and the read gets.
const INSUFFICIENT_BUFFER: u32 = 122;

/// How many times a table is read again after it grew under the reader.
const TABLE_ATTEMPTS: usize = 4;

/// One raw call. `buf` is None to ask how big the table is.
fn read_table(family: u32, tcp: bool, buf: Option<&mut [u8]>, size: &mut u32) -> u32 {
    let ptr = buf.map(|buf| buf.as_mut_ptr().cast());
    unsafe {
        if tcp {
            GetExtendedTcpTable(ptr, size, false, family, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(ptr, size, false, family, UDP_TABLE_OWNER_PID, 0)
        }
    }
}

/// The table as Windows lays it out: a row count, then the rows.
pub(crate) fn table(family: u32, tcp: bool) -> Result<Vec<u8>, String> {
    read_whole(|buf, size| read_table(family, tcp, buf, size))
}

/// Read a table with `read`, which behaves as `GetExtendedTcpTable` does:
/// given no buffer it says how big the table is, given one it fills it in. A
/// table that grows between the size query and the read is read again, since
/// a busy PC opens connections all the time.
fn read_whole(mut read: impl FnMut(Option<&mut [u8]>, &mut u32) -> u32) -> Result<Vec<u8>, String> {
    for _ in 0..TABLE_ATTEMPTS {
        let mut size = 0u32;
        let first = read(None, &mut size);
        if first != 0 && first != INSUFFICIENT_BUFFER {
            return Err(format!("Could not read the connection table ({first})."));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        // Room for a quarter more rows than there are now.
        let mut buf = vec![0u8; size as usize + size as usize / 4 + 256];
        let mut size = u32::try_from(buf.len())
            .map_err(|_| "The connection table is too large to read.".to_string())?;
        match read(Some(&mut buf), &mut size) {
            0 => {
                buf.truncate(size as usize);
                return Ok(buf);
            }
            INSUFFICIENT_BUFFER => continue,
            code => return Err(format!("Could not read the connection table ({code}).")),
        }
    }
    Err("The connection table kept changing while it was read.".to_string())
}

#[cfg(test)]
mod tests {
    use super::{read_whole, INSUFFICIENT_BUFFER, TABLE_ATTEMPTS};

    #[test]
    fn a_table_that_grows_between_the_calls_is_read_again() {
        let mut calls = 0;
        let table = read_whole(|buf, size| {
            calls += 1;
            match (calls, buf) {
                (1 | 3, None) => {
                    *size = if calls == 1 { 100 } else { 400 };
                    INSUFFICIENT_BUFFER
                }
                // The first read finds the table grown past the room it was given.
                (2, Some(_)) => INSUFFICIENT_BUFFER,
                (4, Some(buf)) => {
                    buf[..8].copy_from_slice(&[1, 0, 0, 0, 9, 9, 9, 9]);
                    *size = 8;
                    0
                }
                other => panic!("unexpected call {other:?}"),
            }
        })
        .unwrap();
        assert_eq!(table, vec![1, 0, 0, 0, 9, 9, 9, 9]);
        assert_eq!(calls, 4);
    }

    #[test]
    fn a_table_that_never_stops_growing_is_given_up_on() {
        let mut calls = 0;
        let result = read_whole(|buf, size| {
            calls += 1;
            if buf.is_none() {
                *size = 100;
            }
            INSUFFICIENT_BUFFER
        });
        assert!(result.unwrap_err().contains("kept changing"));
        assert_eq!(calls, 2 * TABLE_ATTEMPTS);
    }

    #[test]
    fn any_other_error_is_reported_at_once_with_its_number() {
        let mut calls = 0;
        let result = read_whole(|_, _| {
            calls += 1;
            5
        });
        assert!(result.unwrap_err().contains("(5)"));
        assert_eq!(calls, 1);

        let result = read_whole(|buf, size| {
            if buf.is_none() {
                *size = 24;
                INSUFFICIENT_BUFFER
            } else {
                87
            }
        });
        assert!(result.unwrap_err().contains("(87)"));
    }

    #[test]
    fn an_empty_table_is_empty() {
        assert_eq!(read_whole(|_, _| 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_buffer_leaves_room_to_grow_and_windows_is_told_its_real_size() {
        let mut offered = 0;
        let table = read_whole(|buf, size| match buf {
            None => {
                *size = 1000;
                INSUFFICIENT_BUFFER
            }
            Some(buf) => {
                offered = buf.len();
                assert_eq!(*size as usize, buf.len());
                *size = 8;
                0
            }
        })
        .unwrap();
        assert!(offered >= 1000 + 250, "{offered}");
        assert_eq!(table.len(), 8);
    }
}
