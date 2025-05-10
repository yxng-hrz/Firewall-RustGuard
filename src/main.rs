younessP
younesskush
Ne pas déranger
Projet RUST

younessP — 29/04/2025 17:25
Pareil
luv_guill — 29/04/2025 17:25
Ok manque juste @ZekioSs
diablo200k — 02/05/2025 13:59
C’est n fait ça quand ?
luv_guill — 07/05/2025 14:45
@ZekioSs mec c'est bon ou pas ?
ta tout push ?
pck je veux bien merge sur le main se soir, comme ça apres je fais une dernière branche se soir et je rajoute un petit bonus dans le code
@diablo200k dimanche je finis les plus grosse partie du pa la les nouvelles features
juste d'abord je veux finir tout le rust, pck apres ya une video à faire
diablo200k — 07/05/2025 15:09
T travaille sur le scanne général nn ?
luv_guill — 07/05/2025 15:30
Tout ce qu'on s'était dit
Jfais un max pour avant lundi
diablo200k — 07/05/2025 15:30
Carré
ZekioSs — 07/05/2025 17:15
Vas-y
Je fais ça en rentrant
ZekioSs — 07/05/2025 19:25
@luv_guill C'est bob
bon *
luv_guill — 07/05/2025 19:36
Carré
luv_guill — 07/05/2025 20:21
@ZekioSs
tu peux push aussi le readme.md dans la branche theo-documentation stpp
oublie pas de git pull
tu régales
pck ta 2 branches
comme ça je mets tout le code en mode propre juste apres
luv_guill — 07/05/2025 21:34
@ZekioSs faut que tu me drop ton mail qui est relié a ton compte github pour push a ta place sur le projet de assembleur chef
ZekioSs — 07/05/2025 21:38
Claude il a la doc ? @luv_guill
luv_guill — 07/05/2025 21:38
oui
yavais dedans
ZekioSs — 07/05/2025 21:39
ok je le fais
luv_guill — 07/05/2025 21:39
faut juste le trouver
bvvvv
bebou
ZekioSs — 07/05/2025 21:39
martinsvaz.theo@gmail.com
luv_guill — 07/05/2025 21:39
bvvvv
ZekioSs — 07/05/2025 21:39
ZekioSs — 07/05/2025 21:41
@luv_guill pour assembleur
@luv_guill le dernier read il a rien dedans
ZekioSs — 07/05/2025 21:52
Copie le lien de claude
luv_guill — 07/05/2025 21:53
https://claude.ai/public/artifacts/a3b2218a-7429-4f57-a780-08ae4dfd55e9
tien
fait en 2 commit stp espacé de 30min
t un bon
@ZekioSs
dans ton autre branche
luv_guill — 07/05/2025 22:01
pour lassembleur demain c'est fini
luv_guill — Hier à 19:07
@younessP
j'ai besoin que tu push ça chef dans la branche main des que tu peux comme ça je fais les derniers push
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
