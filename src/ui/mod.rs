use std::sync::Arc;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::proxy::STATS;

#[derive(Default)]
pub struct GuiState {
    pub window_open: bool,
}

pub struct ProxyApp {
    state: Arc<Mutex<GuiState>>,
}

impl ProxyApp {
    pub fn new(state: Arc<Mutex<GuiState>>) -> Self {
        Self { state }
    }
}

impl eframe::App for ProxyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let mut open = self.state.lock().window_open;

        egui::Window::new("TG WS Proxy")
            .open(&mut open)
            .default_size([380.0, 260.0])
            .resizable(false)
            .show(ui, |ui| {
                use std::sync::atomic::Ordering;
                ui.heading("TG WS Proxy");
                ui.separator();

                let active = STATS.connections_active.load(Ordering::Relaxed);
                let total = STATS.connections_total.load(Ordering::Relaxed);
                ui.label(format!("Active connections: {active}"));
                ui.label(format!("Total connections:  {total}"));
                ui.label(format!("Summary:           {}", STATS.summary()));
            });

        self.state.lock().window_open = open;
    }
}

pub fn start_tray(shutdown: watch::Receiver<bool>, gui_state: Arc<Mutex<GuiState>>) {
    std::thread::spawn(move || {
        use tray_icon::menu::{Menu, MenuEvent, MenuItem};
        use tray_icon::{TrayIconBuilder, TrayIconEvent};

        let menu = Menu::new();
        let status = MenuItem::new("TG WS Proxy", false, None);
        status.set_enabled(false);
        let open_item = MenuItem::new("Open", true, None);
        let quit = MenuItem::new("Quit", true, None);
        menu.append_items(&[&status, &open_item, &quit]).ok();

        let _tray = match TrayIconBuilder::new()
            .with_tooltip("TG WS Proxy")
            .with_menu(Box::new(menu))
            .build()
        {
            Ok(t) => t,
            Err(_) => return,
        };

        let menu_rx = MenuEvent::receiver();
        let tray_rx = TrayIconEvent::receiver();

        loop {
            if *shutdown.borrow() {
                break;
            }
            if let Ok(event) = menu_rx.try_recv() {
                if event.id == quit.id() {
                    break;
                }
                if event.id == open_item.id() && !gui_state.lock().window_open {
                    gui_state.lock().window_open = true;
                    let state = gui_state.clone();
                    std::thread::spawn(move || {
                        let options = eframe::NativeOptions {
                            viewport: egui::ViewportBuilder::default()
                                .with_inner_size([380.0, 260.0]),
                            ..Default::default()
                        };
                        let app = ProxyApp::new(state);
                        let _ = eframe::run_native(
                            "TG WS Proxy",
                            options,
                            Box::new(|_cc| Ok(Box::new(app))),
                        );
                    });
                }
            }
            let _ = tray_rx.try_recv();
            std::thread::sleep(Duration::from_millis(200));
        }
    });
}
