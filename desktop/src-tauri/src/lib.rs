//! 緊急セキュリティ速報 デスクトップ — Rust 側。
//! やること：winget の実行（一覧・更新）・レジストリの読み取り（入っている物・OS のビルド）・トレイ・通知。
//! 🚨 PC の中身は外に出さない。通信するのは webview 側の fetch（公開フィード）と winget（Microsoft のソース）だけ。

use serde::Serialize;
use std::process::Command;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};
use tauri_plugin_notification::NotificationExt;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize)]
pub struct CmdOut {
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn run_cmd(prog: &str, args: &[&str]) -> CmdOut {
    let mut c = Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    match c.output() {
        Ok(o) => CmdOut {
            ok: o.status.success(),
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => CmdOut { ok: false, code: -1, stdout: String::new(), stderr: format!("spawn failed: {e}") },
    }
}

/// `winget list` の生の表を返す（解析は webview 側・固定応答でテストしている）
#[tauri::command]
fn winget_list() -> CmdOut {
    run_cmd("winget", &["list", "--accept-source-agreements", "--disable-interactivity"])
}

/// 1つの ID を更新する。ID は英数字と . + _ - だけ（コマンド注入を防ぐ）
#[tauri::command]
fn winget_upgrade(id: String) -> CmdOut {
    let re = regex::Regex::new(r"^[A-Za-z0-9.+_-]{2,120}$").unwrap();
    if !re.is_match(&id) {
        return CmdOut { ok: false, code: -2, stdout: String::new(), stderr: "invalid id".into() };
    }
    run_cmd(
        "winget",
        &["upgrade", "--id", &id, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"],
    )
}

#[derive(Serialize)]
pub struct RegApp {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub available: Option<String>,
}

/// レジストリの Uninstall 一覧（winget が拾えない物の保険）。表示名と版数だけ読む
#[tauri::command]
fn registry_apps() -> Vec<RegApp> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        let roots = [
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Machine\\X64"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Machine\\X86"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "User\\X64"),
        ];
        for (hive, path, scope) in roots {
            let Ok(key) = RegKey::predef(hive).open_subkey(path) else { continue };
            for name in key.enum_keys().flatten() {
                let Ok(sub) = key.open_subkey(&name) else { continue };
                let display: String = sub.get_value("DisplayName").unwrap_or_default();
                if display.trim().is_empty() { continue; }
                let version: Option<String> = sub.get_value("DisplayVersion").ok();
                out.push(RegApp { kind: "arp".into(), id: format!("ARP\\{scope}\\{name}"), name: display, version, available: None });
            }
        }
    }
    out
}

#[derive(Serialize)]
pub struct OsInfo {
    pub product: String,
    pub display_version: String,
    pub build: String,
    pub ubr: String,
}

/// Windows のビルド（CurrentBuild.UBR）。判定には使わず、表示と「Windows Update を開く」の材料
#[tauri::command]
fn os_info() -> OsInfo {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
            let ubr: u32 = k.get_value("UBR").unwrap_or(0);
            return OsInfo {
                product: k.get_value("ProductName").unwrap_or_default(),
                display_version: k.get_value("DisplayVersion").unwrap_or_default(),
                build: k.get_value("CurrentBuild").unwrap_or_default(),
                ubr: ubr.to_string(),
            };
        }
    }
    OsInfo { product: String::new(), display_version: String::new(), build: String::new(), ubr: String::new() }
}

/// OS の通知（要対応のときだけ呼ばれる。1件1回の制御は webview 側）
#[tauri::command]
fn notify(app: AppHandle, title: String, body: String) -> Result<(), String> {
    app.notification().builder().title(title).body(body).show().map_err(|e| e.to_string())
}

/// 設定画面（Windows Update・ストアの更新）や一次情報のリンクを開く。許すのは https と ms-settings／ms-windows-store だけ
#[tauri::command]
fn open_external(app: AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let allowed = url.starts_with("https://") || url.starts_with("ms-settings:") || url.starts_with("ms-windows-store:");
    if !allowed { return Err("url not allowed".into()); }
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let m = app.autolaunch();
    if enabled { m.enable().map_err(|e| e.to_string())?; } else { m.disable().map_err(|e| e.to_string())?; }
    m.is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_autostart(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// トレイのバッジ代わり：タイトル（ツールチップ）を状態に合わせて変える
#[tauri::command]
fn set_tray_tooltip(app: AppHandle, text: String) -> Result<(), String> {
    if let Some(t) = app.tray_by_id("main") {
        t.set_tooltip(Some(text)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .invoke_handler(tauri::generate_handler![
            winget_list, winget_upgrade, registry_apps, os_info, notify, open_external, set_autostart, get_autostart, set_tray_tooltip
        ])
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "開く", true, None::<&str>)?;
            let check = MenuItem::with_id(app, "check", "今すぐ確認", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "終了", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &check, &quit])?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("緊急セキュリティ速報")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "check" => { show_main(app); let _ = app.emit("check-now", ()); }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            // --minimized（自動起動）のときは窓を出さずトレイだけ
            let minimized = std::env::args().any(|a| a == "--minimized");
            if minimized {
                if let Some(w) = app.get_webview_window("main") { let _ = w.hide(); }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 閉じる＝隠す（常駐）。終了はトレイの「終了」から
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
