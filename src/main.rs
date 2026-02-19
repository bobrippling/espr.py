use std::time::{Duration, Instant};
use std::io::{self, Write};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::thread::sleep;

use anyhow::{Result, anyhow};
use btleplug::api::{Central, Peripheral, Manager as _, WriteType, Characteristic, UUID};
use btleplug::platform::Manager;
use serde_json::Value;
use log::{info, warn, error, debug};

fn main() -> Result<()> {
    env_logger::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return Ok(());
    }
    match args[1].as_str() {
        "interact" => interact(&args[2])?,
        // Add other commands here...
        _ => usage(),
    }
    Ok(())
}

fn usage() {
    eprintln!("Usage:");
    eprintln!("  espr interact <address>");
    // Add other usage lines...
}

fn interact(addr: &str) -> Result<()> {
    let mut conn = Connection::connect(addr)?;
    loop {
        print!("js> ");
        io::stdout().flush()?;
        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break;
        }
        let input = input.trim();
        if input.is_empty() { continue; }
        let result = conn.eval(input)?;
        println!("{}", result);
    }
    Ok(())
}

struct Connection {
    peripheral: btleplug::platform::Peripheral,
    nuart_tx: Characteristic,
    nuart_rx: Characteristic,
}

impl Connection {
    fn connect(addr: &str) -> Result<Self> {
        let manager = Manager::new()?;
        let adapters = manager.adapters()?;
        let central = adapters.into_iter().next().ok_or(anyhow!("No BLE adapter found"))?;
        info!("Scanning for device...");
        central.start_scan(Default::default())?;
        sleep(Duration::from_secs(2));
        let peripherals = central.peripherals()?;
        let peripheral = peripherals.into_iter()
            .find(|p| p.properties().unwrap().address.to_string() == addr)
            .ok_or(anyhow!("Device not found"))?;
        peripheral.connect()?;
        peripheral.discover_services()?;
        // Find UART characteristics by UUID
        let nuart_service = peripheral.services().iter()
            .find(|s| s.uuid == UUID::B128([0x6E,0x40,0x00,0x01,0xB5,0xA3,0xF3,0x93,0xE0,0xA9,0xE5,0x0E,0x24,0xDC,0xCA,0x9E]))
            .ok_or(anyhow!("UART service not found"))?;
        let nuart_tx = nuart_service.characteristics.iter()
            .find(|c| c.uuid == UUID::B128([0x6E,0x40,0x00,0x02,0xB5,0xA3,0xF3,0x93,0xE0,0xA9,0xE5,0x0E,0x24,0xDC,0xCA,0x9E]))
            .ok_or(anyhow!("UART TX characteristic not found"))?.clone();
        let nuart_rx = nuart_service.characteristics.iter()
            .find(|c| c.uuid == UUID::B128([0x6E,0x40,0x00,0x03,0xB5,0xA3,0xF3,0x93,0xE0,0xA9,0xE5,0x0E,0x24,0xDC,0xCA,0x9E]))
            .ok_or(anyhow!("UART RX characteristic not found"))?.clone();
        Ok(Connection { peripheral, nuart_tx, nuart_rx })
    }

    fn eval(&mut self, js: &str) -> Result<String> {
        let cmd = format!("\x03\x10print({})\n", js);
        self.send_bytes(cmd.as_bytes())?;
        // Wait for response (simplified)
        sleep(Duration::from_millis(200));
        let notifications = self.peripheral.notifications().collect::<Vec<_>>();
        let mut buf = Vec::new();
        for notif in notifications {
            buf.extend_from_slice(&notif.value);
        }
        let s = String::from_utf8_lossy(&buf);
        Ok(s.trim().to_string())
    }

    fn send_bytes(&self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let end = std::cmp::min(offset + 20, data.len());
            self.peripheral.write(&self.nuart_tx, &data[offset..end], WriteType::WithResponse)?;
            offset = end;
        }
        Ok(())
    }
}
