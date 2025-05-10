mod config;
mod firewall;
mod rules;
mod logger;

use anyhow::Result;
use clap::{Parser, ArgAction};
use log::{info, error};
use simplelog::{TermLogger, WriteLogger, CombinedLogger, Config, LevelFilter, TerminalMode, ColorChoice};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use config::AppConfig;
use firewall::Firewall;

#[derive(Parser, Debug)]
#[command(name = "rustguard", about = "A minimalist user-mode application firewall", version)]
struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config_file: PathBuf,
    
    #[arg(short, long, value_name = "FILE", default_value = "rustguard.log")]
    log_file: PathBuf,
    
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,
}

fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logging system
    init_logger(&cli.log_file, cli.verbose)?;
    
    info!("Starting RustGuard firewall v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = AppConfig::load(&cli.config_file)?;
    info!("Configuration loaded from {}", cli.config_file.display());
    
    // Initialize firewall
    let firewall = Arc::new(Mutex::new(Firewall::new(config)?));
    info!("Firewall initialized successfully");
    
    // Set up graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        info!("Shutdown signal received");
        r.store(false, Ordering::SeqCst);
    })?;
    
    // Start the firewall
    let fw = firewall.clone();
    let handle = thread::spawn(move || {
        let mut fw = fw.lock().unwrap();
        if let Err(e) = fw.run() {
            error!("Firewall error: {}", e);
        }
    });
    
    // Wait for Ctrl+C signal
    info!("RustGuard is running. Press Ctrl+C to stop.");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
    
    // Stop the firewall
    {
        let mut fw = firewall.lock().unwrap();
        fw.stop()?;
    }
    
    handle.join().unwrap();
    info!("RustGuard stopped successfully");
    
    Ok(())
}

fn init_logger(log_file: &PathBuf, verbose: bool) -> Result<()> {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    
    CombinedLogger::init(vec![
        TermLogger::new(level, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
        WriteLogger::new(LevelFilter::Info, Config::default(), File::create(log_file)?),
    ])?;
    
    Ok(())
}
Réduire
message.txt
3 Ko
demande a ton gpt un commit simple pour ce push
fait en 1 push tkt, remplace le code du main deja présent et push ça
luv_guill — Hier à 19:15
oublie pas de git pull d'abord pck j'ai tout merge dans le main
﻿
mod config;
mod firewall;
mod rules;
mod logger;

use anyhow::Result;
use clap::{Parser, ArgAction};
use log::{info, error};
use simplelog::{TermLogger, WriteLogger, CombinedLogger, Config, LevelFilter, TerminalMode, ColorChoice};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use config::AppConfig;
use firewall::Firewall;

#[derive(Parser, Debug)]
#[command(name = "rustguard", about = "A minimalist user-mode application firewall", version)]
struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config_file: PathBuf,
    
    #[arg(short, long, value_name = "FILE", default_value = "rustguard.log")]
    log_file: PathBuf,
    
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,
}

fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logging system
    init_logger(&cli.log_file, cli.verbose)?;
    
    info!("Starting RustGuard firewall v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = AppConfig::load(&cli.config_file)?;
    info!("Configuration loaded from {}", cli.config_file.display());
    
    // Initialize firewall
    let firewall = Arc::new(Mutex::new(Firewall::new(config)?));
    info!("Firewall initialized successfully");
    
    // Set up graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        info!("Shutdown signal received");
        r.store(false, Ordering::SeqCst);
    })?;
    
    // Start the firewall
    let fw = firewall.clone();
    let handle = thread::spawn(move || {
        let mut fw = fw.lock().unwrap();
        if let Err(e) = fw.run() {
            error!("Firewall error: {}", e);
        }
    });
    
    // Wait for Ctrl+C signal
    info!("RustGuard is running. Press Ctrl+C to stop.");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
    
    // Stop the firewall
    {
        let mut fw = firewall.lock().unwrap();
        fw.stop()?;
    }
    
    handle.join().unwrap();
    info!("RustGuard stopped successfully");
    
    Ok(())
}

fn init_logger(log_file: &PathBuf, verbose: bool) -> Result<()> {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    
    CombinedLogger::init(vec![
        TermLogger::new(level, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
        WriteLogger::new(LevelFilter::Info, Config::default(), File::create(log_file)?),
    ])?;
    
    Ok(())
}
