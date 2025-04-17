// src/firewall.rs
use std::net::IpAddr;
use std::time::{Instant, Duration, SystemTime};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use anyhow::Result;
use anyhow::anyhow;
use log::info;

use crate::config::{Direction, Protocol, BlocklistConfig, AppConfig};
use crate::rules::RuleEngine;
use crate::logger::Logger;
/// Représente un paquet réseau pour le firewall.
pub struct Packet {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub size: usize,
    pub timestamp: u64,
}

impl Packet {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
            size,
            timestamp,
        }
    }

    pub fn is_outbound(&self) -> bool {
        self.direction == Direction::Outbound
    }

    pub fn is_inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }
}

/// Gère le blocage dynamique d’IP via seuils et liste blanche.
pub struct Blocker {
    enabled: bool,
    blocked_ips: HashMap<IpAddr, (Instant, Option<Duration>)>,
    whitelist: HashSet<IpAddr>,
    connection_attempts: HashMap<IpAddr, u32>,
    auto_block_threshold: u32,
    block_duration: u64,
}

impl Blocker {
    pub fn new(config: &BlocklistConfig) -> Self {
        let mut whitelist = HashSet::new();
        for ip_str in &config.whitelist {
            if let Ok(ip) = ip_str.parse() {
                whitelist.insert(ip);
            }
        }
        Self {
            enabled: config.enabled,
            blocked_ips: HashMap::new(),
            whitelist,
            connection_attempts: HashMap::new(),
            auto_block_threshold: config.auto_block_threshold,
            block_duration: config.block_duration,
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.whitelist.contains(ip) {
            return false;
        }
        if let Some((since, duration)) = self.blocked_ips.get(ip) {
            match duration {
                Some(d) => since.elapsed() < *d,
                None => true,
            }
        } else {
            false
        }
    }

    /// Incrémente le compteur et auto-bloque si seuil dépassé.
    pub fn record_connection_attempt(&mut self, ip: IpAddr) {
        if !self.enabled || self.whitelist.contains(&ip) || self.is_blocked(&ip) {
            return;
        }
        let count = self.connection_attempts.entry(ip).or_insert(0);
        *count += 1;
        if *count >= self.auto_block_threshold {
            let duration = Duration::from_secs(self.block_duration);
            self.blocked_ips.insert(ip, (Instant::now(), Some(duration)));
            self.connection_attempts.remove(&ip);
            info!("Auto-blocked IP {} for excessive attempts", ip);
        }
    }

    /// Bloque manuellement une IP pour une durée optionnelle.
    pub fn block_ip(&mut self, ip: IpAddr, duration: Option<u64>) -> Result<()> {
        if self.whitelist.contains(&ip) {
            return Err(anyhow!("Cannot block whitelisted IP"));
        }
        let d = duration.map(Duration::from_secs);
        self.blocked_ips.insert(ip, (Instant::now(), d));
        info!("Blocked IP {}", ip);
        Ok(())
    }

    /// Débloque une IP si elle était présente.
    pub fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        if self.blocked_ips.remove(&ip).is_some() {
            info!("Unblocked IP {}", ip);
            Ok(())
        } else {
            Err(anyhow!("IP not in blocklist"))
        }
    }

    /// Nettoie les blocs expirés.
    pub fn cleanup_expired_blocks(&mut self) {
        self.blocked_ips.retain(|_, (since, duration)| {
            match duration {
                Some(d) => since.elapsed() < *d,
                None => true,
            }
        });
    }


    /// Gère l’ensemble du pare-feu: config, règles, logs, blocage, threads.
pub struct Firewall {
    config: AppConfig,
    rule_engine: RuleEngine,
    logger: Logger,
    blocker: Blocker,
    running: bool,
    handle: Option<JoinHandle<()>>,
}

impl Firewall {
    /// Crée le Firewall à partir de la configuration.
    pub fn new(config: AppConfig) -> Result<Self> {
        let rule_engine = RuleEngine::new(config.rules.clone());
        let logger = Logger::new();
        let blocker = Blocker::new(&config.blocklist);
        Ok(Self {
            config,
            rule_engine,
            logger,
            blocker,
            running: false,
            handle: None,
        })
    }

}

// (le Firewall arrive dans le commit suivant…)
