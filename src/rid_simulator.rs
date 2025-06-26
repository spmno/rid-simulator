use pnet::datalink::{interfaces, Channel, NetworkInterface};
use libwifi::{FrameProtocolVersion, FrameType, FrameSubType};
use libwifi::frame::Beacon;
use libwifi::frame::components::{ManagementHeader, FrameControl, MacAddress, SequenceControl, StationInfo, SupportedRate, VendorSpecificInfo};
use tracing::{info, error};
pub struct RidSimulator {
    wifi_devices: Vec<NetworkInterface>,
}

impl RidSimulator {
    pub fn new() -> Self {
        RidSimulator {
            wifi_devices: Vec::new(),
        }
    }

    pub fn get_wifi_devices(&mut self) {
        let interfaces = interfaces();

        info!("Available WiFi network devices:");
        for interface in interfaces {
            // 根据操作系统调整过滤条件
            if interface.name.contains("wlx") || interface.name.contains("wlan1") {
                info!("Name: {}, MAC: {:?}", interface.name, interface.mac);
                self.wifi_devices.push(interface);
            } else {
                info!("no wifi device: Name: {}, MAC: {:?}", interface.name, interface.mac);
            }
        }
    }

    pub fn start_simulator(&mut self) {
        self.get_wifi_devices();
        if self.wifi_devices.is_empty() {
            panic!("No WiFi devices found");
        }
    }

    pub fn build_and_send_rid(&self, data: Vec<u8>) -> String {
        let beacon_frame = self.build_beacon_with_rid(data);
        self.send_beacon(&beacon_frame);
        return "OK".to_string();
    }

    pub fn build_beacon_with_rid(&self, data: Vec<u8>) -> Vec<u8> {
    // 1. 构建 ManagementHeader
        let header = ManagementHeader {
            frame_control: FrameControl {
                protocol_version: FrameProtocolVersion::PV0,
                frame_type: FrameType::Management,
                frame_subtype: FrameSubType::Beacon,
                flags: 0, // 无标志位
            },
            duration: [0, 0], // Beacon 帧通常为 0
            address_1: MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), // 广播地址
            address_2: MacAddress([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]), // 发送端 MAC (无人机)
            address_3: MacAddress([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]), // BSSID (同发送端)
            sequence_control: SequenceControl {
                fragment_number: 0,
                sequence_number: 0, // 序列号可动态生成
            },
        };

        // 2. 构建 StationInfo
        let mut station_info = StationInfo {
            supported_rates: vec![
                SupportedRate { mandatory: true, rate: 1.0 }, // 1 Mbps (必选)
                SupportedRate { mandatory: false, rate: 6.0 }, // 6 Mbps
            ],
            extended_supported_rates: None,
            ssid: Some("".to_string()), // 空 SSID
            ssid_length: Some(0),
            ds_parameter_set: Some(6), // 信道 6
            vendor_specific: vec![],
            ..StationInfo::default() // 其他字段用默认值
        };

        // 3. 嵌入 RID 到 Vendor-Specific IE
        let rid_ie = VendorSpecificInfo {
            element_id: 221, // Vendor-Specific IE 类型
            length: data.len() as u8 + 4, // 总长度 = RID长度 + OUI(3) + OUI类型(1)
            oui: [0x12, 0x34, 0x56], // 自定义 OUI (替换为无人机厂商ID)
            oui_type: 0x0d, // 标识 RID 数据类型
            data: data,
        };
        station_info.vendor_specific.push(rid_ie);

        // 4. 构建完整 Beacon 帧
        let beacon = Beacon {
            header,
            timestamp: 0, // 可置0或动态生成
            beacon_interval: 100, // 102.4ms ≈ 10Hz
            capability_info: 0, // 开放网络
            station_info,
        };

        // 5. 序列化为字节流
        beacon.encode()
    }

    pub fn send_beacon(&self, beacon_data: &[u8]) {
        match pnet::datalink::channel(&self.wifi_devices[0], Default::default()) {
            Ok(Channel::Ethernet(mut tx, _rx)) => {
                tx.send_to(beacon_data, None);
            },
            Ok(_) => {
                error!("Unsupported channel type");
                return;
            }
            Err(e) => {
                error!("Failed to create channel: {}", e);
                return;
            }
        };
        
    }

}

