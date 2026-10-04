//! What answers a question for one address: this PC's DNS client, or, in the
//! debug build's test mode, a table in a file. The client is asked for the
//! PTR record under `in-addr.arpa` or `ip6.arpa`, and only DNS is asked:
//! NetBIOS and multicast lookups are switched off, because through them a
//! lookup of an internet address would send a probe to that address. The test
//! mode answers from `fake-dns.json`, notes each question in
//! `fake-dns-calls.log` and touches no network.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use wattwall_core::monitor::{clean_name, reverse_name, Failure};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    DNS_ERROR_RCODE_NAME_ERROR, DNS_ERROR_RECORD_DOES_NOT_EXIST, DNS_INFO_NO_RECORDS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_NO_MULTICAST, DNS_QUERY_NO_NETBT,
    DNS_QUERY_OPTIONS, DNS_QUERY_TREAT_AS_FQDN, DNS_RECORDW, DNS_TYPE_PTR,
};

pub(crate) const FAKE_NAMES: &str = "fake-dns.json";
pub(crate) const FAKE_CALLS: &str = "fake-dns-calls.log";
/// Only DNS: no NetBIOS node-status probe, no multicast, and the name is
/// already complete, so no search suffixes are tried.
const ONLY_DNS: DNS_QUERY_OPTIONS =
    DNS_QUERY_OPTIONS(DNS_QUERY_NO_NETBT.0 | DNS_QUERY_NO_MULTICAST.0 | DNS_QUERY_TREAT_AS_FQDN.0);
/// The answer "this name has no such record".
const NO_RECORDS: WIN32_ERROR = WIN32_ERROR(DNS_INFO_NO_RECORDS.cast_unsigned());

pub enum Resolver {
    Live,
    /// The test mode, with the folder its files are in.
    Fake(PathBuf),
}

impl Resolver {
    pub fn resolve(&self, address: IpAddr) -> Result<String, Failure> {
        match self {
            Self::Live => reverse(address),
            Self::Fake(dir) => fake(dir, address),
        }
    }
}

/// Ask the DNS client for the PTR record of an address.
fn reverse(address: IpAddr) -> Result<String, Failure> {
    let name: Vec<u16> = reverse_name(address)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut records: *mut DNS_RECORDW = std::ptr::null_mut();
    // SAFETY: `name` ends in a NUL and outlives the call. On success Windows
    // fills `records` with a list it allocated, which is freed below.
    let status = unsafe {
        DnsQuery_W(
            PCWSTR(name.as_ptr()),
            DNS_TYPE_PTR,
            ONLY_DNS,
            None,
            (&raw mut records).cast(),
            None,
        )
    };
    let found = if status == WIN32_ERROR(0) {
        // SAFETY: `records` is the list that call returned.
        unsafe { first_ptr(records) }
    } else {
        None
    };
    if !records.is_null() {
        // SAFETY: `records` came from DnsQuery_W and is not used again.
        unsafe { DnsFree(Some(records.cast()), DnsFreeRecordList) };
    }
    if status == WIN32_ERROR(0) {
        return found
            .and_then(|name| clean_name(&name))
            .ok_or(Failure::NotFound);
    }
    if status == DNS_ERROR_RCODE_NAME_ERROR
        || status == NO_RECORDS
        || status == DNS_ERROR_RECORD_DOES_NOT_EXIST
    {
        Err(Failure::NotFound)
    } else {
        Err(Failure::Temporary)
    }
}

/// The host name in the first PTR record of a list the DNS client returned.
/// An answer may start with a CNAME or two (a reverse zone handed on to
/// someone else), so every record is looked at.
///
/// # Safety
/// `records` is null or the head of a list DnsQuery_W returned, not yet freed.
unsafe fn first_ptr(records: *mut DNS_RECORDW) -> Option<String> {
    let mut at = records;
    while !at.is_null() {
        // SAFETY: the caller promises every `pNext` leads to a record or null.
        let record = unsafe { &*at };
        if record.wType == DNS_TYPE_PTR.0 {
            // SAFETY: a PTR record's data is its host name.
            let host = unsafe { record.Data.PTR.pNameHost };
            if !host.is_null() {
                // SAFETY: Windows gives a NUL-terminated string.
                return unsafe { host.to_string() }.ok();
            }
        }
        at = record.pNext;
    }
    None
}

fn fake(dir: &Path, address: IpAddr) -> Result<String, Failure> {
    if let Ok(mut log) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(FAKE_CALLS))
    {
        let _ = writeln!(log, "{address}");
    }
    let text = fs::read_to_string(dir.join(FAKE_NAMES)).map_err(|_| Failure::NotFound)?;
    let names: HashMap<String, String> =
        serde_json::from_str(&text).map_err(|_| Failure::Temporary)?;
    names
        .get(&address.to_string())
        .and_then(|name| clean_name(name))
        .ok_or(Failure::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::Dns::{
        DNS_PTR_DATAW, DNS_RECORDW_1, DNS_TYPE, DNS_TYPE_A, DNS_TYPE_CNAME,
    };

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn record(kind: DNS_TYPE, host: *mut u16, next: *mut DNS_RECORDW) -> DNS_RECORDW {
        DNS_RECORDW {
            pNext: next,
            wType: kind.0,
            Data: DNS_RECORDW_1 {
                PTR: DNS_PTR_DATAW {
                    pNameHost: PWSTR(host),
                },
            },
            ..DNS_RECORDW::default()
        }
    }

    #[test]
    fn the_first_ptr_record_of_an_answer_gives_the_name_even_after_other_records() {
        let mut alias = wide("alias.example");
        let mut host = wide("host.example");
        let mut other = wide("not-this.example");
        let mut last = record(DNS_TYPE_PTR, other.as_mut_ptr(), std::ptr::null_mut());
        let mut ptr = record(DNS_TYPE_PTR, host.as_mut_ptr(), &raw mut last);
        let mut cname = record(DNS_TYPE_CNAME, alias.as_mut_ptr(), &raw mut ptr);
        let name = unsafe { first_ptr(&raw mut cname) };
        assert_eq!(name.as_deref(), Some("host.example"));
    }
    #[test]
    fn an_answer_with_no_ptr_record_or_no_name_gives_nothing() {
        assert_eq!(unsafe { first_ptr(std::ptr::null_mut()) }, None);
        let mut alias = wide("alias.example");
        let mut address = record(DNS_TYPE_A, alias.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(unsafe { first_ptr(&raw mut address) }, None);
        // A PTR record with no name is skipped, and the next one is used.
        let mut host = wide("host.example");
        let mut named = record(DNS_TYPE_PTR, host.as_mut_ptr(), std::ptr::null_mut());
        let mut nameless = record(DNS_TYPE_PTR, std::ptr::null_mut(), &raw mut named);
        assert_eq!(
            unsafe { first_ptr(&raw mut nameless) }.as_deref(),
            Some("host.example")
        );
    }
    /// Asks Windows' own resolver, so it is run on purpose:
    /// `cargo test -p wattwall-desktop live_ -- --ignored`.
    #[test]
    #[ignore = "asks Windows' resolver, and for the second address a DNS server"]
    fn live_reverse_lookup_gives_an_answer_not_an_error() {
        // This PC may or may not have a name for itself; either is an answer.
        // Anything else means the call itself was wrong.
        let loopback = reverse(ip("127.0.0.1"));
        assert!(
            matches!(loopback, Ok(_) | Err(Failure::NotFound)),
            "{loopback:?}"
        );
        let public = reverse(ip("1.1.1.1"));
        assert!(public.is_ok(), "{public:?}");
        let v6 = reverse(ip("2606:4700:4700::1111"));
        assert!(matches!(v6, Ok(_) | Err(Failure::NotFound)), "{v6:?}");
    }
}
