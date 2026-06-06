use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::proxy::config::{self, ConfigFile, PROXY_CONFIG};
use crate::proxy::STATS;
use crate::utils::update_check::check_for_update;

#[derive(Default)]
pub struct GuiState {
    pub window_open: bool,
    pub settings_open: bool,
    pub wizard_open: bool,
    pub update_available: Option<String>,
    pub link_host: String,
    pub link_port: u16,
    pub link_secret: String,
    pub link_domain_hex: String,
    pub log_path: Option<String>,
    pub config_path: String,
}

pub struct ProxyApp {
    state: Arc<Mutex<GuiState>>,
    settings: SettingsState,
}

#[derive(Default)]
struct SettingsState {
    host: String,
    port: String,
    secret: String,
    fake_tls_domain: String,
    proxy_protocol: bool,
    no_cfproxy: bool,
    pool_size: String,
    buf_kb: String,
    cfproxy_domain: String,
    cfproxy_worker_domain: String,
    dc_entries: Vec<(String, String)>,
    log_file: String,
    log_max_mb: String,
    log_backups: String,
    autostart: bool,
}

impl ProxyApp {
    pub fn new(state: Arc<Mutex<GuiState>>) -> Self {
        let s = Self::load_settings_from_config();
        Self { state, settings: s }
    }

    fn load_settings_from_config() -> SettingsState {
        let cfg = PROXY_CONFIG.read().expect("config poisoned");
        let dc: Vec<_> = cfg.dc_redirects.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        SettingsState {
            host: cfg.host.clone(),
            port: cfg.port.to_string(),
            secret: cfg.secret.clone(),
            fake_tls_domain: cfg.fake_tls_domain.clone(),
            proxy_protocol: cfg.proxy_protocol,
            no_cfproxy: !cfg.fallback_cfproxy,
            pool_size: cfg.pool_size.to_string(),
            buf_kb: (cfg.buffer_size / 1024).to_string(),
            cfproxy_domain: cfg.cfproxy_user_domains.join(", "),
            cfproxy_worker_domain: cfg.cfproxy_worker_domains.join(", "),
            dc_entries: dc,
            log_file: cfg.log_file.clone().unwrap_or_default(),
            log_max_mb: cfg.log_max_mb.to_string(),
            log_backups: cfg.log_backups.to_string(),
            autostart: cfg.autostart,
        }
    }

    fn build_config_file(&self) -> ConfigFile {
        let s = &self.settings;
        let dc_map: std::collections::HashMap<u32, String> = s.dc_entries.iter().filter_map(|(k, v)| {
            let dc: u32 = k.parse().ok()?;
            if v.is_empty() { None } else { Some((dc, v.clone())) }
        }).collect();
        ConfigFile {
            host: Some(s.host.clone()),
            port: s.port.parse().ok(),
            secret: Some(s.secret.clone()),
            fake_tls_domain: Some(s.fake_tls_domain.clone()),
            proxy_protocol: Some(s.proxy_protocol),
            no_cfproxy: Some(s.no_cfproxy),
            pool_size: s.pool_size.parse().ok(),
            buf_kb: s.buf_kb.parse().ok(),
            cfproxy_domain: if s.cfproxy_domain.is_empty() { None } else { Some(vec![s.cfproxy_domain.clone()]) },
            cfproxy_worker_domain: if s.cfproxy_worker_domain.is_empty() { None } else { Some(vec![s.cfproxy_worker_domain.clone()]) },
            dc_ip: if dc_map.is_empty() { None } else { Some(dc_map) },
            log_file: if s.log_file.is_empty() { None } else { Some(s.log_file.clone()) },
            log_max_mb: s.log_max_mb.parse().ok(),
            log_backups: s.log_backups.parse().ok(),
            autostart: Some(s.autostart),
        }
    }
}

impl eframe::App for ProxyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let update_available = self.state.lock().update_available.clone();
        let config_path = self.state.lock().config_path.clone();

        let mut open = self.state.lock().window_open;
        let mut settings_open = self.state.lock().settings_open;
        let mut wizard_open = self.state.lock().wizard_open;

        egui::Window::new("TG WS Proxy")
            .open(&mut open)
            .default_size([400.0, 300.0])
            .show(ui, |ui| {
                ui.heading("TG WS Proxy");
                ui.separator();

                let active = STATS.connections_active.load(Ordering::Relaxed);
                let total = STATS.connections_total.load(Ordering::Relaxed);
                ui.label(format!("Active connections: {active}"));
                ui.label(format!("Total connections:  {total}"));
                ui.label(format!("Summary:           {}", STATS.summary()));

                ui.separator();
                if let Some(ver) = &update_available {
                    ui.colored_label(egui::Color32::GREEN, format!("Update available: v{ver}"));
                }
            });

        let cp = config_path.clone();
        egui::Window::new("Settings")
            .open(&mut settings_open)
            .default_size([460.0, 500.0])
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.heading("Server");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Host:");
                        ui.text_edit_singleline(&mut self.settings.host);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut self.settings.port);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Secret (hex):");
                        ui.text_edit_singleline(&mut self.settings.secret);
                    });

                    ui.add_space(8.0);
                    ui.heading("Fake TLS");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Domain:");
                        ui.text_edit_singleline(&mut self.settings.fake_tls_domain);
                    });

                    ui.add_space(8.0);
                    ui.heading("Cloudflare");
                    ui.separator();
                    ui.checkbox(&mut self.settings.no_cfproxy, "Disable CF proxy");
                    ui.horizontal(|ui| {
                        ui.label("CF domains (comma):");
                        ui.text_edit_singleline(&mut self.settings.cfproxy_domain);
                    });
                    ui.horizontal(|ui| {
                        ui.label("CF worker domains:");
                        ui.text_edit_singleline(&mut self.settings.cfproxy_worker_domain);
                    });

                    ui.add_space(8.0);
                    ui.heading("Performance");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Pool size:");
                        ui.text_edit_singleline(&mut self.settings.pool_size);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Buffer (KB):");
                        ui.text_edit_singleline(&mut self.settings.buf_kb);
                    });

                    ui.add_space(8.0);
                    ui.heading("DC IP Mappings");
                    ui.separator();
                    let mut remove_idx = None;
                    for (i, (dc, ip)) in self.settings.dc_entries.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(format!("DC{}", i + 1));
                            ui.text_edit_singleline(dc);
                            ui.label("→");
                            ui.text_edit_singleline(ip);
                            if ui.button("✕").clicked() {
                                remove_idx = Some(i);
                            }
                        });
                    }
                    if let Some(idx) = remove_idx {
                        self.settings.dc_entries.remove(idx);
                    }
                    if ui.button("+ Add DC").clicked() {
                        self.settings.dc_entries.push((String::new(), String::new()));
                    }

                    ui.add_space(8.0);
                    ui.heading("Logging");
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Log file:");
                        ui.text_edit_singleline(&mut self.settings.log_file);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Max MB:");
                        ui.text_edit_singleline(&mut self.settings.log_max_mb);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Backups:");
                        ui.text_edit_singleline(&mut self.settings.log_backups);
                    });

                    ui.add_space(8.0);
                    ui.checkbox(&mut self.settings.autostart, "Autostart with Windows");

                    ui.add_space(12.0);
                    if ui.button("Save && Restart").clicked() {
                        let cf = self.build_config_file();
                        let _ = config::save_config(&cp, &cf);
                        std::process::Command::new(std::env::current_exe().unwrap())
                            .args(["--config", &cp])
                            .spawn()
                            .ok();
                        std::process::exit(0);
                    }
                });
            });

        if wizard_open {
            let link = link_text(&self.state.lock());
            egui::Window::new("Welcome to TG WS Proxy")
                .open(&mut wizard_open)
                .default_size([400.0, 250.0])
                .resizable(false)
                .show(ui, |ui| {
                    ui.heading("Setup Complete!");
                    ui.separator();
                    ui.label("Configure Telegram Desktop to use this proxy:");
                    ui.add_space(8.0);
                    ui.label(&link);
                    ui.add_space(8.0);
                    if ui.button("Open in Telegram").clicked() {
                        let _ = webbrowser::open(&link);
                    }
                    if ui.button("Copy Link").clicked() {
                        let _ = arboard::Clipboard::new().and_then(|mut cb| cb.set_text(link));
                    }
                });
        }

        self.state.lock().window_open = open;
        self.state.lock().settings_open = settings_open;
        self.state.lock().wizard_open = wizard_open;
    }
}

fn link_text(state: &GuiState) -> String {
    if state.link_domain_hex.is_empty() {
        format!("tg://proxy?server={}&port={}&secret=dd{}",
            state.link_host, state.link_port, state.link_secret)
    } else {
        format!("tg://proxy?server={}&port={}&secret=ee{}{}",
            state.link_host, state.link_port, state.link_secret, state.link_domain_hex)
    }
}

pub fn start_tray(
    shutdown: watch::Receiver<bool>,
    gui_state: Arc<Mutex<GuiState>>,
) {
    std::thread::spawn(move || {
        use tray_icon::menu::{Menu, MenuEvent, MenuItem};
        use tray_icon::{TrayIconBuilder, TrayIconEvent};

        let menu = Menu::new();
        let status = MenuItem::new("TG WS Proxy", false, None);
        status.set_enabled(false);

        let open_item = MenuItem::new("Open", true, None);
        let settings_item = MenuItem::new("Settings...", true, None);
        let sep1 = MenuItem::new("", false, None);
        let open_tg = MenuItem::new("Open in Telegram", true, None);
        let copy_link = MenuItem::new("Copy Link", true, None);
        let sep2 = MenuItem::new("", false, None);
        let open_logs = MenuItem::new("Open Logs", true, None);
        let restart_item = MenuItem::new("Restart Proxy", true, None);
        let sep3 = MenuItem::new("", false, None);
        let check_upd = MenuItem::new("Check for Updates...", true, None);
        let sep4 = MenuItem::new("", false, None);
        let quit = MenuItem::new("Quit", true, None);

        menu.append_items(&[
            &status, &open_item, &settings_item, &sep1, &open_tg, &copy_link,
            &sep2, &open_logs, &restart_item, &sep3, &check_upd, &sep4, &quit,
        ]).ok();

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
                let id = event.id;
                if id == quit.id() { break; }

                if id == open_item.id() {
                    gui_state.lock().window_open = true;
                    let state = gui_state.clone();
                    std::thread::spawn(move || {
                        let options = eframe::NativeOptions {
                            viewport: egui::ViewportBuilder::default()
                                .with_inner_size([460.0, 500.0]),
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

                if id == settings_item.id() {
                    gui_state.lock().settings_open = true;
                    let state = gui_state.clone();
                    std::thread::spawn(move || {
                        let options = eframe::NativeOptions {
                            viewport: egui::ViewportBuilder::default()
                                .with_inner_size([460.0, 500.0]),
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

                if id == open_tg.id() {
                    let s = gui_state.lock();
                    let link = link_text(&s);
                    let _ = webbrowser::open(&link);
                }

                if id == copy_link.id() {
                    let s = gui_state.lock();
                    let link = link_text(&s);
                    let _ = arboard::Clipboard::new().and_then(|mut cb| cb.set_text(link));
                }

                if id == open_logs.id() {
                    let s = gui_state.lock();
                    if let Some(path) = &s.log_path {
                        let _ = webbrowser::open(&format!("file://{}", path.replace('\\', "/")));
                    }
                }

                if id == restart_item.id() {
                    let path = gui_state.lock().config_path.clone();
                    let _ = std::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--config", &path])
                        .spawn();
                    std::process::exit(0);
                }

                if id == check_upd.id() {
                    let s = gui_state.clone();
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new();
                        if let Ok(rt) = rt
                            && let Ok(info) = rt.block_on(check_for_update("1.7.2"))
                            && info.has_update
                        {
                            s.lock().update_available = Some(info.latest);
                        }
                    });
                }
            }
            let _ = tray_rx.try_recv();
            std::thread::sleep(Duration::from_millis(200));
        }
    });
}
