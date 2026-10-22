// Windows では本番ビルドでコンソール窓を出さない
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    security_sokuho_desktop_lib::run()
}
