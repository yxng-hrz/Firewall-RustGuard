use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use anyhow::{Result, Context};

// Structure principale de la configuration de l'application
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub rules: Vec<FirewallRule>,
    pub blocklist: BlocklistConfig,
}
// Configuration générale du pare-feu
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeneralConfig {
    pub interface: String,
    pub default_action: Action,
}

// Énumération des actions possibles pour une règle de pare-feu
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum Action {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "log")]
    Log,
}

// Structure d'une règle de pare-feu
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FirewallRule {
    pub name: String,
    pub action: Action,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub enabled: bool,
}

// Énumération des directions possibles pour le trafic réseau
// Permet de filtrer selon que le trafic est entrant, sortant ou les deux
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum Direction {
    #[serde(rename = "outbound")]
    Outbound,
    #[serde(rename = "inbound")]
    Inbound,
    #[serde(rename = "any")]
    Any,
}

// Énumération des protocoles réseau pouvant être filtrés
// Permet de cibler des types spécifiques de trafic
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub enum Protocol {
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "icmp")]
    ICMP
    #[serde(rename = "any")]
    Any,
}

// Configuration de la liste noire
// Gère le blocage automatique des adresses IP malveillantes
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistConfig {
    pub enabled: bool,
    pub auto_block_threshold: u32,
    pub block_duration: u64,
    pub whitelist: Vec<String>,
}
