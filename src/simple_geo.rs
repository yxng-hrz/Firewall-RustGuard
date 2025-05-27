use std::net::IpAddr;
use log::{info, warn};

#[derive(Clone)]
pub struct SimpleGeoFirewall {
    enabled: bool,
    blocked_countries: Vec<String>,
}

impl SimpleGeoFirewall {
    pub fn new(blocked_countries: Vec<String>, enabled: bool) -> Self {
        Self {
            enabled,
            blocked_countries: blocked_countries.iter().map(|s| s.to_uppercase()).collect(),
        }
    }
    
    /// Vérifie si une IP doit être bloquée selon son pays
    pub fn should_block(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        
        if let Some(country) = self.get_country_code(ip) {
            if self.blocked_countries.contains(&country) {
                warn!("🌍🚫 IP {} bloquée ({})", ip, self.get_flag(&country));
                return true;
            } else {
                info!("🌍✅ IP {} autorisée ({})", ip, self.get_flag(&country));
            }
        }
        false
    }
    
    /// Géolocalisation ultra-simple basée sur les premiers octets
    fn get_country_code(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let first_octet = ipv4.octets()[0];
                match first_octet {
                    // Ranges IP simplifiés (exemples basiques)
                    46..=47 => Some("RU".to_string()),  // Russie
                    58..=61 => Some("CN".to_string()),  // Chine  
                    91 => Some("IN".to_string()),       // Inde
                    185 => Some("IR".to_string()),      // Iran
                    192 => Some("PRIVATE".to_string()), // Réseau privé
                    172 => Some("PRIVATE".to_string()), // Réseau privé
                    10 => Some("PRIVATE".to_string()),  // Réseau privé
                    127 => Some("LOCAL".to_string()),   // Localhost
                    1..=45 => Some("US".to_string()),   // États-Unis (approximatif)
                    128..=184 => Some("EU".to_string()), // Europe (approximatif)
                    _ => Some("OTHER".to_string()),
                }
            },
            IpAddr::V6(_) => Some("V6".to_string()), // IPv6
        }
    }
    
    /// Retourne l'emoji du drapeau selon le code pays
    fn get_flag(&self, country_code: &str) -> String {
        match country_code {
            "CN" => "🇨🇳 Chine".to_string(),
            "RU" => "🇷🇺 Russie".to_string(),
            "IR" => "🇮🇷 Iran".to_string(),
            "US" => "🇺🇸 USA".to_string(),
            "EU" => "🇪🇺 Europe".to_string(),
            "IN" => "🇮🇳 Inde".to_string(),
            "PRIVATE" => "🏠 Privé".to_string(),
            "LOCAL" => "💻 Local".to_string(),
            "V6" => "🌐 IPv6".to_string(),
            _ => format!("🏳️ {}", country_code),
        }
    }
    
    /// Ajoute un pays à bloquer
    pub fn block_country(&mut self, country_code: &str) {
        let code = country_code.to_uppercase();
        if !self.blocked_countries.contains(&code) {
            self.blocked_countries.push(code.clone());
            info!("🌍 Pays bloqué: {}", self.get_flag(&code));
        }
    }
    
    /// Active le mode anti-menaces (Chine, Russie, Iran)
    pub fn enable_threat_protection(&mut self) {
        self.blocked_countries = vec!["CN".to_string(), "RU".to_string(), "IR".to_string()];
        info!("🛡️ Protection anti-menaces activée: Chine, Russie, Iran bloqués");
    }
}
