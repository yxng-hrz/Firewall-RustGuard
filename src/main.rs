use std::process;
use std::path::Path;
use log::{info, error};
use simplelog::*;
use std::fs::File;

mod config;
mod firewall;
mod rules;
mod logger;

use crate::config::AppConfig;
use crate::firewall::Firewall;

fn main() {
    // Initialiser le logger avec un fichier dans le répertoire courant
    let log_file = File::create("./rustguard.log").expect("Impossible de créer le fichier de log");
    WriteLogger::init(
        LevelFilter::Debug, // Changer en Debug pour plus d'informations
        Config::default(),
        log_file,
    ).expect("Erreur d'initialisation du logger");

    println!("RustGuard: Pare-feu Applicatif Minimaliste");
    info!("RustGuard: Démarrage de l'application");
    println!("Version 0.1.0");
    println!("Développé par Guillaume, Theo, Mohamed et Youness");

    // Vérifier les privilèges d'exécution
    if !is_root() {
        error!("Privilèges insuffisants pour exécuter le pare-feu");
        eprintln!("Erreur: RustGuard nécessite des privilèges administrateur pour capturer les paquets réseau.");
        eprintln!("Veuillez exécuter avec sudo ou en tant qu'administrateur.");
        process::exit(1);
    }

    println!("Initialisation...");
    info!("Phase d'initialisation du pare-feu");

    // Charger la configuration
    let config_path = Path::new("./config.toml");
    let config = match AppConfig::load(config_path) {
        Ok(config) => {
            info!("Configuration chargée avec succès");
            config
        },
        Err(e) => {
            error!("Erreur lors du chargement de la configuration: {}", e);
            eprintln!("Erreur: Impossible de charger la configuration. Création d'une configuration par défaut.");
            
            // Créer une configuration par défaut si le chargement échoue
            match AppConfig::create_default(config_path) {
                Ok(default_config) => {
                    info!("Configuration par défaut créée avec succès");
                    default_config
                },
                Err(e) => {
                    error!("Erreur lors de la création de la configuration par défaut: {}", e);
                    eprintln!("Erreur fatale: Impossible de créer une configuration par défaut.");
                    process::exit(1);
                }
            }
        }
    };

    // Créer et démarrer le pare-feu
    info!("Création de l'instance du pare-feu");
    let mut firewall = match Firewall::new(config) {
        Ok(fw) => fw,
        Err(e) => {
            error!("Erreur lors de la création du pare-feu: {}", e);
            eprintln!("Erreur fatale: Impossible d'initialiser le pare-feu.");
            process::exit(1);
        }
    };

    info!("Démarrage du pare-feu");
    if let Err(e) = firewall.run() {
        error!("Erreur lors du démarrage du pare-feu: {}", e);
        eprintln!("Erreur fatale: Impossible de démarrer le pare-feu.");
        process::exit(1);
    }

    println!("RustGuard démarré avec succès.");
    info!("RustGuard démarré avec succès");
    println!("Appuyez sur Ctrl+C pour arrêter.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}
