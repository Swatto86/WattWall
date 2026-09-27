//! Byte counters of this PC's network adapters, read once a second for the
//! tray meter. Only hardware adapters count, so traffic through a VPN adapter
//! is not counted twice, and the filter rows Windows lists beside each
//! adapter are skipped because they repeat its counters.

use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

use wattwall_core::Counters;

const HARDWARE_INTERFACE: u8 = 1;
const FILTER_INTERFACE: u8 = 2;

/// Received and sent octets per adapter that is up, or None when Windows
/// would not give the table.
pub fn counters() -> Option<Counters> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) }.is_err() || table.is_null() {
        return None;
    }
    let mut out = Counters::new();
    // SAFETY: GetIfTable2 succeeded, so `table` points at NumEntries rows
    // that stay valid until FreeMibTable.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows {
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            if flags & HARDWARE_INTERFACE == 0
                || flags & FILTER_INTERFACE != 0
                || row.OperStatus != IfOperStatusUp
            {
                continue;
            }
            out.insert(row.InterfaceLuid.Value, (row.InOctets, row.OutOctets));
        }
        FreeMibTable(table.cast());
    }
    Some(out)
}
