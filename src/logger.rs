use std::net::IpAddr;
use log::info;
use chrono::{Local, DateTime};
use std::time::UNIX_EPOCH;

use crate::config::{Direction, Protocol};

#[derive(Clone)]
pub struct Logger {}

impl Logger {
    // Crée une nouvelle instance de Logger
    pub fn new() -> Self {
        Self {}
    }
    
    // Log un paquet autorisé avec ses métadonnées
    pub fn log_allowed_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) {
        // Formate l’adresse source avec ou sans port
        let src = if let Some(port) = src_port {
            format!("{}:{}", src_ip, port)
        } else {
            src_ip.to_string()
        };
        
        // Formate l’adresse destination avec ou sans port
        let dst = if let Some(port) = dst_port {
            format!("{}:{}", dst_ip, port)
        } else {
            dst_ip.to_string()
        };
        
        info!("ALLOW {:?} {} -> {} ({} bytes)", protocol, src, dst, size);
    }
    
    // Log un paquet bloqué avec ses métadonnées
    pub fn log_blocked_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) {
        let src = if let Some(port) = src_port {
            format!("{}:{}", src_ip, port)
        } else {
            src_ip.to_string()
        };
        
        let dst = if let Some(port) = dst_port {
            format!("{}:{}", dst_ip, port)
        } else {
            dst_ip.to_string()
        };
        
        // Enregistre dans les logs un paquet bloqué avec protocole et taille
        info!("BLOCK {:?} {} -> {} ({} bytes)", protocol, src, dst, size);
    }
    
    // Log un paquet sans préciser s'il est autorisé ou bloqué
    pub fn log_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        size: usize,
    ) {
        let src = if let Some(port) = src_port {
            format!("{}:{}", src_ip, port)
        } else {
            src_ip.to_string()
        };
        
        let dst = if let Some(port) = dst_port {
            format!("{}:{}", dst_ip, port)
        } else {
            dst_ip.to_string()
        };
        
        info!("LOG {:?} {} -> {} ({} bytes)", protocol, src, dst, size);
    }
    
    // Log une mise à jour de la liste de blocage (blocklist)
    pub fn log_blocklist_update(&self, ip: &IpAddr, action: &str) {
        // Action peut être "Ajout" ou "Suppression" d'une IP dans la blocklist
        info!("{} IP {}", action, ip);
    }
}
