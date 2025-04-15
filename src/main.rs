use std::process;

fn main() {
    println!("RustGuard: Pare-feu Applicatif Minimaliste");
    println!("Version 0.1.0");
    println!("Développé par Guillaume, Theo et Mohamed");
    // Vérifier les privilèges d'exécution (le pare-feu nécessite généralement des droits root)
    if !is_root() {
        eprintln!("Erreur: RustGuard nécessite des privilèges administrateur pour capturer les paquets réseau.");
        eprintln!("Veuillez exécuter avec sudo ou en tant qu'administrateur.");
        process::exit(1);
    }
    
    println!("Initialisation...");
    
    // Partie à implémenter plus tard:
    // - Analyse des arguments de ligne de commande
    // - Chargement de la configuration
    // - Initialisation du pare-feu
    // - Démarrage du pare-feu
    
    println!("RustGuard démarré avec succès.");
    println!("Appuyez sur Ctrl+C pour arrêter.");
    
    // Simple boucle pour maintenir le programme en exécution
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
        // Pour Windows ou autres OS, on ignore cette vérification pour l'instant
        true
    }
}
