use actix_web::{post, web, HttpResponse, Responder};
use crate::message::{message::Message, packet_message::PacketMessage};
use tracing::info;
use std::sync::Mutex;
use crate::RidSimulator;

pub struct AppState {
    pub simulator: Mutex<RidSimulator>,
}

#[post("/simulator")]
async fn simulator(appdata:web::Data<AppState>, message: web::Json<PacketMessage>) -> impl Responder {
    info!("receive simulator request: {:?}.", message);
    let simulator = appdata.simulator.lock().unwrap();
    match simulator.build_and_send_rid(&message.get_ssid(), message.encode()) {
        Ok(_) => HttpResponse::Ok().body("success."),
        Err(e) => HttpResponse::InternalServerError().body(format!("发送失败: {}", e))
    }
}
