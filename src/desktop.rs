//! Windows shell integration. CLI and non-Windows GUI do not register anything.

use anyhow::Result;
use eframe::egui::{Context, ViewportCommand};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

#[cfg(windows)]
static WINDOW_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static FORCE_EXIT: AtomicBool = AtomicBool::new(false);

pub fn show_window(ctx: &Context) {
    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(ViewportCommand::Focus);
    ctx.request_repaint();
}

#[derive(Clone, Copy)]
pub enum Action {
    Show,
    Hide,
    Exit,
}

#[cfg(windows)]
pub fn remember_window(frame: &eframe::Frame) {
    use raw_window_handle::{HasWindowHandle as _, RawWindowHandle};

    if let Ok(handle) = frame.window_handle()
        && let RawWindowHandle::Win32(handle) = handle.as_raw()
    {
        WINDOW_HWND.store(handle.hwnd.get(), Ordering::Relaxed);
    }
}

#[cfg(not(windows))]
pub fn remember_window(_frame: &eframe::Frame) {}

#[cfg(windows)]
pub fn force_exit_requested() -> bool {
    FORCE_EXIT.load(Ordering::Relaxed)
}

#[cfg(not(windows))]
pub fn force_exit_requested() -> bool {
    false
}

// Windows command-line quoting, including paths ending with a backslash.
#[cfg(any(windows, test))]
fn quote_argument(value: &str) -> String {
    let mut result = String::from("\"");
    let mut backslashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(
            '\\',
            if ch == '"' {
                backslashes * 2 + 1
            } else {
                backslashes
            },
        ));
        backslashes = 0;
        result.push(ch);
    }
    result.extend(std::iter::repeat_n('\\', backslashes * 2));
    result.push('"');
    result
}

#[cfg(any(windows, test))]
fn startup_command(executable: &str, data_dir: &str) -> String {
    format!(
        "{} gui --start-in-tray --data-dir {}",
        quote_argument(executable),
        quote_argument(data_dir)
    )
}

#[cfg(windows)]
mod platform {
    use super::*;
    use anyhow::Context as _;
    use std::sync::mpsc::{self, Receiver};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        PostMessageW, SW_RESTORE, SetForegroundWindow, ShowWindow, WM_CLOSE,
    };
    use winreg::{RegKey, enums::*};

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE_NAME: &str = "OZ";

    pub struct Desktop {
        _tray: TrayIcon,
        events: Receiver<Action>,
    }

    fn native_show_window() {
        let hwnd = WINDOW_HWND.load(Ordering::Relaxed);
        if hwnd != 0 {
            // The tray callback can run while egui is not repainting a hidden viewport.
            unsafe {
                ShowWindow(hwnd as _, SW_RESTORE);
                SetForegroundWindow(hwnd as _);
            }
        }
    }

    fn native_request_exit() {
        FORCE_EXIT.store(true, Ordering::Relaxed);
        let hwnd = WINDOW_HWND.load(Ordering::Relaxed);
        if hwnd != 0 {
            unsafe {
                PostMessageW(hwnd as _, WM_CLOSE, 0, 0);
            }
        }
    }

    impl Desktop {
        pub fn new(ctx: &Context) -> Result<Self> {
            let menu = Menu::new();
            let show = MenuItem::new("Открыть ОЗ", true, None);
            let hide = MenuItem::new("Скрыть в трей", true, None);
            let exit = MenuItem::new("Выход", true, None);
            menu.append_items(&[&show, &hide, &exit])?;
            // A small opaque icon, generated locally; no external asset needed.
            let mut rgba = Vec::with_capacity(32 * 32 * 4);
            for y in 0..32 {
                for x in 0..32 {
                    let ring = (6..14).contains(&x)
                        && (7..25).contains(&y)
                        && (!(8..12).contains(&x) || !(10..22).contains(&y));
                    let three = (18..27).contains(&x)
                        && (7..25).contains(&y)
                        && (x >= 24 || (7..10).contains(&y) || (14..18).contains(&y) || y >= 22);
                    rgba.extend_from_slice(if ring || three {
                        &[255, 255, 255, 255]
                    } else {
                        &[0, 120, 212, 255]
                    });
                }
            }
            let tray = TrayIconBuilder::new()
                .with_tooltip("ОЗ — отслеживание заявок")
                .with_icon(Icon::from_rgba(rgba, 32, 32)?)
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .build()
                .context("создание значка в системном трее")?;
            let (tx, events) = mpsc::channel();
            let menu_ctx = ctx.clone();
            let menu_tx = tx.clone();
            let show_id = show.id().clone();
            let hide_id = hide.id().clone();
            let exit_id = exit.id().clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let action = if event.id == show_id {
                    Action::Show
                } else if event.id == hide_id {
                    Action::Hide
                } else if event.id == exit_id {
                    Action::Exit
                } else {
                    return;
                };
                match action {
                    Action::Show => native_show_window(),
                    Action::Exit => native_request_exit(),
                    Action::Hide => {}
                }
                let _ = menu_tx.send(action);
                // Wake the GUI even when its native window is hidden/minimized.
                if matches!(action, Action::Show | Action::Exit) {
                    show_window(&menu_ctx);
                }
                menu_ctx.request_repaint();
            }));
            let tray_ctx = ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    native_show_window();
                    let _ = tx.send(Action::Show);
                    show_window(&tray_ctx);
                }
            }));
            Ok(Self {
                _tray: tray,
                events,
            })
        }

        pub fn next_action(&self) -> Option<Action> {
            self.events.try_recv().ok()
        }
    }

    pub fn autostart_enabled() -> Result<bool> {
        let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        match key.get_value::<String, _>(VALUE_NAME) {
            Ok(value) => Ok(!value.is_empty()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn set_autostart(enabled: bool) -> Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(RUN_KEY)
            .context("доступ к автозапуску текущего пользователя")?;
        if enabled {
            let exe = std::env::current_exe()?;
            let dir = std::env::current_dir()?;
            let command = startup_command(
                exe.to_str().context("путь программы не является Unicode")?,
                dir.to_str().context("путь настроек не является Unicode")?,
            );
            key.set_value(VALUE_NAME, &command)
                .context("включение автозапуска ОЗ")?;
        } else if let Err(error) = key.delete_value(VALUE_NAME)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error).context("отключение автозапуска ОЗ");
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub struct Desktop;
    impl Desktop {
        pub fn new(_ctx: &Context) -> Result<Self> {
            anyhow::bail!("системный трей доступен в Windows-сборке")
        }
        pub fn next_action(&self) -> Option<Action> {
            None
        }
    }
    pub fn autostart_enabled() -> Result<bool> {
        Ok(false)
    }
    pub fn set_autostart(_enabled: bool) -> Result<()> {
        anyhow::bail!("автозапуск доступен в Windows-сборке")
    }
}

pub use platform::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_keeps_paths_with_spaces_and_unicode_separate() {
        assert_eq!(
            startup_command(r"C:\Программы\OZ App\oz.exe", r"D:\Данные ОЗ"),
            "\"C:\\Программы\\OZ App\\oz.exe\" gui --start-in-tray --data-dir \"D:\\Данные ОЗ\""
        );
    }

    #[test]
    fn quoting_handles_root_directory_and_embedded_quotes() {
        assert_eq!(quote_argument("C:\\"), "\"C:\\\\\"");
        assert_eq!(quote_argument("a\"b"), "\"a\\\"b\"");
    }
}
