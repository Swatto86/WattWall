//! Program path, icon and publisher. Failures become an empty icon or no
//! publisher; the list still shows the program.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
    BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, HGDIOBJ,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
    FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, SHGetFileInfoW, SHGetKnownFolderPath, SHFILEINFOW, SHGFI_ICON,
    SHGFI_SMALLICON,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, DrawIconEx, GetIconInfo, DI_NORMAL, ICONINFO,
};

use wattwall_core::plain_path;

use crate::com::win_err;

pub fn path_for_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if pid == 4 {
        return Some("System".to_string());
    }
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = [0u16; 1024];
        let mut len = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(process);
        ok.ok()?;
        let text = String::from_utf16_lossy(&buffer[..len as usize]);
        if text.is_empty() {
            return None;
        }
        Some(plain_path(Path::new(&text)).to_string_lossy().to_string())
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = windows::Win32::Security::TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some((&raw mut elevation).cast::<core::ffi::c_void>()),
            std::mem::size_of_val(&elevation) as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

pub fn current_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    final_path(&exe).or(Ok(plain_path(&exe)))
}

pub fn program_files() -> Result<PathBuf, String> {
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, Default::default(), None) }
        .map_err(win_err)?;
    let text = unsafe { raw.to_string() }.unwrap_or_default();
    unsafe { CoTaskMemFree(Some(raw.0.cast())) };
    final_path(Path::new(&text)).or(Ok(PathBuf::from(text)))
}

pub fn final_path(path: &Path) -> Result<PathBuf, String> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let handle = CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        .map_err(win_err)?;
        let mut buffer = [0u16; 1024];
        let len = GetFinalPathNameByHandleW(handle, &mut buffer, Default::default());
        let _ = CloseHandle(handle);
        if len == 0 || len as usize >= buffer.len() {
            return Err("Could not resolve the program path.".to_string());
        }
        let text = String::from_utf16_lossy(&buffer[..len as usize]);
        Ok(plain_path(Path::new(&text)))
    }
}

pub fn publisher(path: &str) -> Option<String> {
    let wide: Vec<u16> = Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        let mut action = windows::Win32::Security::WinTrust::WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            (&raw mut data).cast(),
        );
        let name = if status == 0 {
            signer_name(data.hWVTStateData)
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            (&raw mut data).cast(),
        );
        name
    }
}

unsafe fn signer_name(state: HANDLE) -> Option<String> {
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return None;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null()
        || unsafe { (*signer).csCertChain } == 0
        || unsafe { (*signer).pasCertChain }.is_null()
    {
        return None;
    }
    let cert = unsafe { (*(*signer).pasCertChain).pCert };
    if cert.is_null() {
        return None;
    }
    let mut buffer = [0u16; 256];
    let wrote = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        )
    };
    if wrote <= 1 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..wrote as usize - 1]))
}

pub fn icon_data_url(path: &str) -> Option<String> {
    let wide: Vec<u16> = Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut info = SHFILEINFOW::default();
        let got = SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            Default::default(),
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_SMALLICON,
        );
        if got == 0 || info.hIcon.is_invalid() {
            return None;
        }
        let url = icon_png_url(info.hIcon);
        let _ = DestroyIcon(info.hIcon);
        url
    }
}

unsafe fn icon_png_url(icon: windows::Win32::UI::WindowsAndMessaging::HICON) -> Option<String> {
    let mut icon_info = ICONINFO::default();
    if unsafe { GetIconInfo(icon, &mut icon_info) }.is_err() {
        return None;
    }
    if !icon_info.hbmColor.is_invalid() {
        let _ = unsafe { DeleteObject(HGDIOBJ(icon_info.hbmColor.0)) };
    }
    if !icon_info.hbmMask.is_invalid() {
        let _ = unsafe { DeleteObject(HGDIOBJ(icon_info.hbmMask.0)) };
    }
    let screen = unsafe { GetDC(None) };
    let memory = unsafe { CreateCompatibleDC(Some(screen)) };
    let header = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: 32,
        biHeight: -32,
        biPlanes: 1,
        biBitCount: 32,
        ..Default::default()
    };
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let info = BITMAPINFO {
        bmiHeader: header,
        bmiColors: [Default::default()],
    };
    let dib = unsafe { CreateDIBSection(Some(memory), &info, DIB_RGB_COLORS, &mut bits, None, 0) }
        .ok()?;
    if bits.is_null() {
        let _ = unsafe { DeleteObject(HGDIOBJ(dib.0)) };
        let _ = unsafe { DeleteDC(memory) };
        unsafe { ReleaseDC(None, screen) };
        return None;
    }
    let previous = unsafe { SelectObject(memory, HGDIOBJ(dib.0)) };
    let _ = unsafe { DrawIconEx(memory, 0, 0, icon, 32, 32, 0, None, DI_NORMAL) };
    let pixels = std::slice::from_raw_parts(bits.cast::<u8>(), 32 * 32 * 4).to_vec();
    unsafe {
        SelectObject(memory, previous);
        let _ = DeleteObject(HGDIOBJ(dib.0));
        let _ = DeleteDC(memory);
        ReleaseDC(None, screen);
    }
    Some(format!("data:image/bmp;base64,{}", base64(&bmp(&pixels))))
}

fn bmp(pixels: &[u8]) -> Vec<u8> {
    let pixel_bytes = 32 * 32 * 4;
    let offset = 54u32;
    let size = offset + pixel_bytes as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&32i32.to_le_bytes());
    out.extend_from_slice(&(-32i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&[0; 24]);
    out.extend_from_slice(pixels);
    out
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut n = (chunk[0] as u32) << 16;
        if chunk.len() > 1 {
            n |= (chunk[1] as u32) << 8;
        }
        if chunk.len() > 2 {
            n |= chunk[2] as u32;
        }
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
