
use tracing::{info, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::{non_blocking, rolling::{self}};
use pnet::datalink::{self, interfaces, Channel, NetworkInterface};

fn get_wifi_devices() -> Vec<NetworkInterface> {
 let interfaces = interfaces();
    let mut wifi_devices = Vec::new();

    info!("Available WiFi network devices:");
    for interface in interfaces {
        // 根据操作系统调整过滤条件
        if interface.name.contains("wlx") || interface.name.contains("wlan1") {
            info!("Name: {}, MAC: {:?}", interface.name, interface.mac);
            wifi_devices.push(interface);
        }
    }
    wifi_devices
}

fn start_simulator() {
    let wifi_devices = get_wifi_devices();
    if wifi_devices.is_empty() {
        error!("No WiFi devices found");
        return;
    }
}

fn main() {
    let file_appender = rolling::daily("logs", "capture.log");
    let (non_blocking_appender, _guard) = non_blocking(file_appender);
    let file_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking_appender);

    let console_subscriber = fmt::layer().with_writer(std::io::stdout);

    tracing_subscriber::registry().with(console_subscriber).with(file_layer).init();
    info!("rid simulator start");
    start_simulator();
}
