//! 緊急セキュリティ速報 デスクトップ — Rust 側。
//! やること：winget の実行（一覧・更新）・レジストリの読み取り（入っている物・OS のビルド）・トレイ・通知。
//! 🚨 PC の中身は外に出さない。通信するのは webview 側の fetch（公開フィード）と winget（Microsoft のソース）だけ。
//! 🚨 winget の待ちはメインスレッドから外し、時間切れで止める（監査R1/R3：UAC 待ちで窓もトレイも固まった）。

use serde::Serialize;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
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

/// 更新は同時に1つだけ（二重実行の防止）
static UPGRADE_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Clone)]
pub struct CmdOut {
    pub ok: bool,
    pub code: i32,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

/// 子プロセスを時間切れつきで実行する（時間切れなら kill）。呼び出しは spawn_blocking の中で行う
fn run_cmd_timeout(prog: &str, args: &[&str], timeout: Duration) -> CmdOut {
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    c.creation_flags(CREATE_NO_WINDOW);
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => return CmdOut { ok: false, code: -1, timed_out: false, stdout: String::new(), stderr: format!("spawn failed: {e}") },
    };
    // 出力は別スレッドで読み続ける（パイプが詰まって止まらないように）
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let th_out = std::thread::spawn(move || { let mut s = Vec::new(); if let Some(o) = out.as_mut() { let _ = std::io::Read::read_to_end(o, &mut s); } s });
    let th_err = std::thread::spawn(move || { let mut s = Vec::new(); if let Some(o) = err.as_mut() { let _ = std::io::Read::read_to_end(o, &mut s); } s });
    #[allow(unused_variables)]
    let start = Instant::now();
    let mut timed_out = false;
    let pid = child.id();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if start.elapsed() > timeout {
                    // 子孫（インストーラー等）ごと止める。kill() は直接の子だけなので taskkill /T を使う（監査R4-M3）
                    #[cfg(windows)]
                    {
                        let mut k = Command::new("taskkill");
                        k.args(["/PID", &pid.to_string(), "/T", "/F"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
                        k.creation_flags(CREATE_NO_WINDOW);
                        let _ = k.status();
                    }
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(_) => break None,
        }
    };
    // 読み取りスレッドは待ち過ぎない（子孫がパイプを握ったままだと EOF が来ない）。5秒で諦めて取れた分だけ返す
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { let o = th_out.join().unwrap_or_default(); let e = th_err.join().unwrap_or_default(); let _ = tx.send((o, e)); });
    let (o, e) = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| (b"(output not available: pipe held by a child process)".to_vec(), Vec::new()));
    let stdout = String::from_utf8_lossy(&o).to_string();
    let stderr = String::from_utf8_lossy(&e).to_string();
    let code = status.and_then(|s| s.code()).unwrap_or(-1);
    CmdOut { ok: !timed_out && code == 0, code, timed_out, stdout, stderr: if timed_out { format!("timed out after {}s\n{stderr}", timeout.as_secs()) } else { stderr } }
}

/// `winget list` の生の表を返す（解析は webview 側・固定応答でテストしている）。3分で時間切れ
#[tauri::command]
async fn winget_list() -> CmdOut {
    tauri::async_runtime::spawn_blocking(|| run_cmd_timeout("winget", &["list", "--accept-source-agreements", "--disable-interactivity"], Duration::from_secs(180)))
        .await
        .unwrap_or_else(|e| CmdOut { ok: false, code: -1, timed_out: false, stdout: String::new(), stderr: format!("join failed: {e}") })
}

/// 1つの ID を更新する。ID は英数字と . + _ - だけ（コマンド注入を防ぐ）。15分で時間切れ（UAC を放置した等）
#[tauri::command]
async fn winget_upgrade(id: String) -> CmdOut {
    let re = regex::Regex::new(r"^[A-Za-z0-9.+_-]{2,120}$").unwrap();
    if !re.is_match(&id) {
        return CmdOut { ok: false, code: -2, timed_out: false, stdout: String::new(), stderr: "invalid id".into() };
    }
    if UPGRADE_RUNNING.swap(true, Ordering::SeqCst) {
        return CmdOut { ok: false, code: -3, timed_out: false, stdout: String::new(), stderr: "another upgrade is running".into() };
    }
    let r = tauri::async_runtime::spawn_blocking(move || {
        run_cmd_timeout(
            "winget",
            &["upgrade", "--id", &id, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"],
            Duration::from_secs(15 * 60),
        )
    })
    .await
    .unwrap_or_else(|e| CmdOut { ok: false, code: -1, timed_out: false, stdout: String::new(), stderr: format!("join failed: {e}") });
    UPGRADE_RUNNING.store(false, Ordering::SeqCst);
    r
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
