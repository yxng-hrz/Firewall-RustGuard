// src/firewall.rs

use std::net::IpAddr;
use std::time::{Instant, Duration, SystemTime};
use std::collections::{HashMap, HashSet};
use crate::config::{Direction, Protocol, BlocklistConfig};

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
    /// Initialise le Blocker d’après la config.
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

    /// Vérifie si l’IP est actuellement bloquée.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.whitelist.contains(ip) {
            return false;
        }
        if let Some((since, duration)) = self.blocked_ips.get(ip) {
            match duration {
                Some(d) => since.elapsed() < *d,
                None => true, // blocage permanent
            }
        } else {
            false
        }
    }
}

// (à suivre dans le commit 3…)
