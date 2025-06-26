
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender::{non_blocking, rolling::{self}};
use actix_web::{web, App, HttpServer};
use std::sync::Mutex;


pub mod message;
pub mod rid_simulator;
pub mod web_service;

use rid_simulator::RidSimulator;
use web_service::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let file_appender = rolling::daily("logs", "capture.log");
    let (non_blocking_appender, _guard) = non_blocking(file_appender);
    let file_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(non_blocking_appender);

    let console_subscriber = fmt::layer().with_writer(std::io::stdout);

    tracing_subscriber::registry().with(console_subscriber).with(file_layer).init();
    info!("rid simulator start");
    let appstate:web::Data<AppState> = web::Data::new(AppState {
        simulator: Mutex::new(RidSimulator::new())
    });
    appstate.simulator.lock().unwrap().start_simulator();
    HttpServer::new(move || {
        App::new()
            .app_data(appstate.clone())
            .service(web_service::simulator)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
