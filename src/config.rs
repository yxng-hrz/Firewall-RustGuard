use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use anyhow::{Result, Context};

// Structure principale de la configuration de l'application
// Contient les paramètres généraux, les règles du pare-feu et la configuration de la liste noire
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub rules: Vec<FirewallRule>,
    pub blocklist: BlocklistConfig,
}