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
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistConfig {
    pub enabled: bool,
    pub auto_block_threshold: u32,
    pub block_duration: u64,
    pub whitelist: Vec<String>,
}

impl AppConfig {
    /// Charge la configuration à partir d'un fichier
    pub fn load(path: &Path) -> Result<Self> {
        let config_str = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: AppConfig = toml::from_str(&config_str)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }
    
    /// Sauvegarde la configuration dans un fichier
    pub fn save(&self, path: &Path) -> Result<()> {
        let config_str = toml::to_string_pretty(self)?;
        fs::write(path, config_str)?;
        Ok(())
    }
    
    /// Crée une configuration par défaut et la sauvegarde dans un fichier
    pub fn create_default(path: &Path) -> Result<Self> {
        let config = Self {
            general: GeneralConfig {
                interface: "default".to_string(),
                default_action: Action::Block,
            },
            rules: vec![
                // Règle pour autoriser le trafic HTTP sortant
                FirewallRule {
                    name: "Allow HTTP".to_string(),
                    action: Action::Allow,
                    direction: Direction::Outbound,
                    protocol: Protocol::TCP,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: Some(80),
                    enabled: true,
                },
                // Règle pour autoriser le trafic HTTPS sortant
                FirewallRule {
                    name: "Allow HTTPS".to_string(),
                    action: Action::Allow,
                    direction: Direction::Outbound,
                    protocol: Protocol::TCP,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: Some(443),
                    enabled: true,
                },
                // Règle pour autoriser le trafic DNS sortant
                FirewallRule {
                    name: "Allow DNS".to_string(),
                    action: Action::Allow,
                    direction: Direction::Outbound,
                    protocol: Protocol::UDP,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: Some(53),
                    enabled: true,
                },
            ],
            // Configuration de la liste noire
            blocklist: BlocklistConfig {
                enabled: true,
                auto_block_threshold: 5,
                block_duration: 3600,
                whitelist: vec![
                    "127.0.0.1".to_string(),
                    "::1".to_string()
                ],
            },
        };
        config.save(path)?;
        Ok(config)
    }
}
