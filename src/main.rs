use std::process;
use std::path::Path;
use log::{info, error, warn};
use simplelog::*;
use std::fs::File;
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

mod config;
mod rules;
mod logger;
mod simple_geo;

use crate::config::{AppConfig, Direction, Protocol, Action};
use crate::rules::RuleEngine;
use crate::logger::Logger;
use crate::simple_geo::SimpleGeoFirewall;

// Structure de paquet simplifiée pour les tests
#[derive(Debug)]
pub struct TestPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub size: usize,
}

impl TestPacket {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
            size,
        }
    }
    
    pub fn is_outbound(&self) -> bool {
        self.direction == Direction::Outbound
    }
    
    pub fn is_inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }
}

fn main() {
    // Initialiser le logger
    let log_file = File::create("./rustguard.log").expect("Impossible de créer le fichier de log");
    WriteLogger::init(
        LevelFilter::Debug,
        Config::default(),
        log_file,
    ).expect("Erreur d'initialisation du logger");

    println!("🔥 RustGuard: Pare-feu Applicatif - MODE TEST WSL");
    println!("===============================================");
    info!("RustGuard: Démarrage en mode test WSL (sans capture réseau)");
    println!("Version 0.1.0 - MODE TEST WSL/Linux");
    println!("Développé par Guillaume, Theo et Mohamed");

    println!("\n📋 Initialisation...");
    info!("Phase d'initialisation du pare-feu (mode test WSL)");

    // Charger la configuration
    let config_path = Path::new("./config.toml");
    let config = match AppConfig::load(config_path) {
        Ok(config) => {
            info!("Configuration chargée avec succès");
            println!("✅ Configuration chargée avec succès");
            config
        },
        Err(e) => {
            error!("Erreur lors du chargement de la configuration: {}", e);
            println!("⚠️ Création d'une configuration par défaut...");
            
            match AppConfig::create_default(config_path) {
                Ok(default_config) => {
                    info!("Configuration par défaut créée avec succès");
                    println!("✅ Configuration par défaut créée");
                    default_config
                },
                Err(e) => {
                    error!("Erreur lors de la création de la configuration par défaut: {}", e);
                    println!("❌ Erreur fatale: Impossible de créer une configuration par défaut.");
                    process::exit(1);
                }
            }
        }
    };

    // Afficher la configuration
    display_config(&config);
    
    // Initialiser les composants
    let rule_engine = RuleEngine::new(config.rules.clone());
    let logger = Logger::new();
    let geo_firewall = SimpleGeoFirewall::new(
        config.geo_firewall.blocked_countries.clone(),
        config.geo_firewall.enabled
    );

    println!("\n🧪 TESTS DES COMPOSANTS");
    println!("======================");
    
    // Test des règles
    test_rules(&rule_engine, &logger, &config);
    
    // Test du géo-firewall
    test_geo_firewall(&geo_firewall);
    
    // Simulation de trafic réseau
    println!("\n🌐 SIMULATION DE TRAFIC RÉSEAU");
    println!("=============================");
    simulate_network_traffic(&rule_engine, &logger, &geo_firewall, &config);
    
    println!("\n✅ Tests terminés avec succès !");
    println!("📝 Consultez rustguard.log pour les détails complets");
    println!("\n⚠️  Note: Mode test WSL - capture réseau désactivée");
    println!("Pour la version complète sur Windows :");
    println!("   1. Installez Npcap depuis https://npcap.com/#download");
    println!("   2. Utilisez PowerShell avec privilèges administrateur");
    
    info!("Tests de simulation WSL terminés avec succès");
}

fn display_config(config: &AppConfig) {
    println!("\n📊 CONFIGURATION ACTIVE");
    println!("=======================");
    println!("   Interface : {}", config.general.interface);
    println!("   Action par défaut : {:?}", config.general.default_action);
    println!("   Nombre de règles : {}", config.rules.len());
    println!("   Blocklist activée : {}", config.blocklist.enabled);
    println!("   Auto-block après : {} tentatives", config.blocklist.auto_block_threshold);
    println!("   Géo-firewall activé : {}", config.geo_firewall.enabled);
    
    if config.geo_firewall.enabled {
        println!("   Pays bloqués : {:?}", config.geo_firewall.blocked_countries);
    }
    
    println!("\n📋 Règles actives :");
    for (i, rule) in config.rules.iter().enumerate() {
        let status = if rule.enabled { "✅" } else { "❌" };
        println!("   {}. {} {} - {:?} {:?} port {:?}", 
                 i+1, status, rule.name, rule.action, rule.protocol, rule.dst_port);
    }
    
    info!("Configuration affichée - {} règles, géo-firewall: {}", 
          config.rules.len(), config.geo_firewall.enabled);
}

fn test_rules(rule_engine: &RuleEngine, logger: &Logger, config: &AppConfig) {
    println!("\n🔧 Test du moteur de règles...");
    
    // Test 1: HTTP autorisé (port 80)
    let http_packet = TestPacket::new(
        "192.168.1.100".parse().unwrap(),
        "93.184.216.34".parse().unwrap(),
        Some(45234),
        Some(80),
        Protocol::TCP,
        Direction::Outbound,
        1024,
    );
    
    test_packet(&http_packet, rule_engine, logger, config, "HTTP vers port 80");
    
    // Test 2: HTTPS bloqué (port 443)
    let https_packet = TestPacket::new(
        "192.168.1.100".parse().unwrap(),
        "93.184.216.34".parse().unwrap(),
        Some(45235),
        Some(443),
        Protocol::TCP,
        Direction::Outbound,
        1024,
    );
    
    test_packet(&https_packet, rule_engine, logger, config, "HTTPS vers port 443");
    
    // Test 3: SSH bloqué (port 22)
    let ssh_packet = TestPacket::new(
        "192.168.1.100".parse().unwrap(),
        "192.168.1.50".parse().unwrap(),
        Some(45236),
        Some(22),
        Protocol::TCP,
        Direction::Outbound,
        512,
    );
    
    test_packet(&ssh_packet, rule_engine, logger, config, "SSH vers port 22");
    
    // Test 4: DNS autorisé (port 53)
    let dns_packet = TestPacket::new(
        "192.168.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(53241),
        Some(53),
        Protocol::UDP,
        Direction::Outbound,
        256,
    );
    
    test_packet(&dns_packet, rule_engine, logger, config, "DNS vers port 53");
    
    // Test 5: Port aléatoire (action par défaut)
    let random_packet = TestPacket::new(
        "192.168.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(45237),
        Some(1337),
        Protocol::TCP,
        Direction::Outbound,
        128,
    );
    
    test_packet(&random_packet, rule_engine, logger, config, "Port aléatoire 1337");
}

fn test_packet(
    packet: &TestPacket,
    rule_engine: &RuleEngine,
    logger: &Logger,
    config: &AppConfig,
    description: &str,
) {
    // Simuler l'application des règles
    let action = rule_engine.apply_rules(packet).unwrap_or(config.general.default_action.clone());
    
    match action {
        Action::Allow => {
            println!("   ✅ {} - AUTORISÉ", description);
            logger.log_allowed_packet(
                packet.src_ip, packet.dst_ip, packet.src_port, 
                packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
            );
        },
        Action::Block => {
            println!("   🚫 {} - BLOQUÉ", description);
            logger.log_blocked_packet(
                packet.src_ip, packet.dst_ip, packet.src_port, 
                packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
            );
        },
        Action::Log => {
            println!("   📝 {} - LOGGÉ", description);
            logger.log_packet(
                packet.src_ip, packet.dst_ip, packet.src_port, 
                packet.dst_port, packet.protocol.clone(), packet.direction.clone(), packet.size
            );
        },
    }
}

fn test_geo_firewall(geo_firewall: &SimpleGeoFirewall) {
    println!("\n🌍 Test du géo-firewall...");
    
    let test_ips = vec![
        ("8.8.8.8", "IP Google (US)"),
        ("127.0.0.1", "Localhost"),
        ("58.220.0.1", "IP Chine (simulée)"),
        ("46.23.45.67", "IP Russie (simulée)"),
        ("192.168.1.1", "IP locale"),
        ("61.135.0.1", "IP Chine 2 (simulée)"),
    ];
    
    for (ip_str, description) in test_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if geo_firewall.should_block(ip) {
                println!("   🚫 {} - BLOQUÉ par géo-firewall", description);
            } else {
                println!("   ✅ {} - Autorisé par géo-firewall", description);
            }
        }
    }
}

fn simulate_network_traffic(
    rule_engine: &RuleEngine,
    logger: &Logger,
    geo_firewall: &SimpleGeoFirewall,
    config: &AppConfig,
) {
    println!("🔄 Simulation de trafic réaliste...");
    
    let scenarios = vec![
        // Navigation web normale
        ("Navigation web", vec![
            TestPacket::new("192.168.1.100".parse().unwrap(), "93.184.216.34".parse().unwrap(), Some(45000), Some(80), Protocol::TCP, Direction::Outbound, 1024),
            TestPacket::new("192.168.1.100".parse().unwrap(), "93.184.216.34".parse().unwrap(), Some(45001), Some(443), Protocol::TCP, Direction::Outbound, 1024),
        ]),
        
        // Requêtes DNS
        ("Requêtes DNS", vec![
            TestPacket::new("192.168.1.100".parse().unwrap(), "8.8.8.8".parse().unwrap(), Some(53000), Some(53), Protocol::UDP, Direction::Outbound, 256),
            TestPacket::new("192.168.1.100".parse().unwrap(), "1.1.1.1".parse().unwrap(), Some(53001), Some(53), Protocol::TCP, Direction::Outbound, 256),
        ]),
        
        // Tentatives d'attaque
        ("Tentatives suspectes", vec![
            TestPacket::new("58.220.0.1".parse().unwrap(), "192.168.1.100".parse().unwrap(), Some(12345), Some(22), Protocol::TCP, Direction::Inbound, 512),
            TestPacket::new("46.23.45.67".parse().unwrap(), "192.168.1.100".parse().unwrap(), Some(12346), Some(23), Protocol::TCP, Direction::Inbound, 512),
            TestPacket::new("192.168.1.100".parse().unwrap(), "8.8.8.8".parse().unwrap(), Some(45002), Some(22), Protocol::TCP, Direction::Outbound, 512),
        ]),
    ];
    
    for (scenario_name, packets) in scenarios {
        println!("\n📦 Scénario: {}", scenario_name);
        
        for (i, packet) in packets.iter().enumerate() {
            // Check geo-firewall first
            let geo_blocked = if packet.direction == Direction::Inbound {
                geo_firewall.should_block(packet.src_ip)
            } else {
                geo_firewall.should_block(packet.dst_ip)
            };
            
            if geo_blocked {
                println!("   🌍🚫 Paquet {}: BLOQUÉ par géo-firewall", i+1);
                continue;
            }
            
            // Apply firewall rules
            test_packet(packet, rule_engine, logger, config, &format!("Paquet {}", i+1));
            
            // Petite pause pour rendre la simulation réaliste
            thread::sleep(Duration::from_millis(100));
        }
    }
    
    info!("Simulation de trafic terminée");
}
