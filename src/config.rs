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
// Définit l'interface réseau à utiliser et l'action par défaut à appliquer
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GeneralConfig {
    pub interface: String,
    pub default_action: Action,
}

// Énumération des actions possibles pour une règle de pare-feu
// PartialEq permet la comparaison entre les actions
// Les attributs serde(rename) permettent d'utiliser des noms en minuscules dans le fichier TOML
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
// Définit tous les critères pour filtrer le trafic réseau
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
