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