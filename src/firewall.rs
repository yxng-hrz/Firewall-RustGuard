// src/firewall.rs

use std::net::IpAddr;
use std::time::SystemTime;
use crate::config::Direction;

/// Représente un paquet réseau extrait depuis pnet pour le firewall.
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
    /// Construit un Packet à partir de ses attributs, en enregistrant l’instant UNIX.
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

    /// Renvoie `true` si le paquet est sortant.
    pub fn is_outbound(&self) -> bool {
        self.direction == Direction::Outbound
    }

    /// Renvoie `true` si le paquet est entrant.
    pub fn is_inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }
}

// TODO: Ajouter Blocker et Firewall plus tard.
