import paramiko
from scp import SCPClient
from scapy.all import ARP, Ether, srp
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

class SSHFileDownloaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Extracteur de Données")

        # ajouter l'icône
        base_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base_dir, "logos", "data_extractor.ico")
        self.root.iconbitmap(icon_path)

        self.root.geometry("800x800")  # Ajuster la taille de la fenêtre pour mieux voir les résultats
        
        # Dossier temporaire pour les rapports intermédiaires
        self.temp_dir = os.path.join(os.path.dirname(__file__), "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # interface pour le scan réseau
        self.create_scan_interface()
        
        # interface pour connexion SSH et téléchargement
        self.create_ssh_interface()
        
        # affichage des résultats
        self.create_result_display()
        
    def create_scan_interface(self):
        frame = ttk.LabelFrame(self.root, text="Scan Réseau", padding=10)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        ttk.Label(frame, text="Sous-réseau (ex: 192.168.1.0/24)").grid(row=0, column=0, padx=5, pady=5)
        self.subnet_entry = ttk.Entry(frame)
        self.subnet_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.scan_button = ttk.Button(frame, text="Scanner", command=self.run_scan_network_thread)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)
        
    def create_ssh_interface(self):
        frame = ttk.LabelFrame(self.root, text="Connexion SSH et Téléchargement", padding=10)
        frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        ttk.Label(frame, text="Adresse IP de la machine cible").grid(row=0, column=0, padx=5, pady=5)
        self.host_entry = ttk.Entry(frame)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Port SSH (par défaut : 22)").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(frame)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "22")
        
        ttk.Label(frame, text="Nom d'utilisateur").grid(row=2, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(frame)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Mot de passe").grid(row=3, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Chemin du fichier distant").grid(row=4, column=0, padx=5, pady=5)
        self.remote_path_entry = ttk.Entry(frame)
        self.remote_path_entry.grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Chemin local (répertoire courant par défaut)").grid(row=5, column=0, padx=5, pady=5)
        self.local_path_entry = ttk.Entry(frame)
        self.local_path_entry.grid(row=5, column=1, padx=5, pady=5)
        self.local_path_entry.insert(0, os.getcwd())
        
        self.select_path_button = ttk.Button(frame, text="Sélectionner un chemin", command=self.select_local_path)
        self.select_path_button.grid(row=5, column=2, padx=5, pady=5)
        
        self.download_button = ttk.Button(frame, text="Télécharger", command=self.run_download_files_thread)
        self.download_button.grid(row=6, column=1, padx=5, pady=5)
        
    def create_result_display(self):
        frame = ttk.LabelFrame(self.root, text="Résultats", padding=10)
        frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        self.result_text = tk.Text(frame, height=20, wrap=tk.WORD)
        self.result_text.grid(row=0, column=0, padx=5, pady=5)

        self.result_text.tag_configure("blue", foreground="blue")
        self.result_text.tag_configure("green", foreground="green")
        self.result_text.tag_configure("red", foreground="red")
        self.result_text.tag_configure("yellow", foreground="yellow")
        
    def clear_result_display(self):
        self.result_text.delete(1.0, tk.END)
    
    def save_to_temp_report(self, message):
        temp_report_file = os.path.join(self.temp_dir, "extracteur_data_report.txt")
        with open(temp_report_file, 'a') as f:
            f.write(message + "\n")
        
    def select_local_path(self):
        selected_path = filedialog.askdirectory()
        if selected_path:
            self.local_path_entry.delete(0, tk.END)
            self.local_path_entry.insert(0, selected_path)
        
    def run_scan_network_thread(self):
        print("Lancement du thread de scan réseau")
        thread = threading.Thread(target=self.scan_network)
        thread.start()
        
    def run_download_files_thread(self):
        print("Lancement du thread de téléchargement de fichiers")
        thread = threading.Thread(target=self.download_files)
        thread.start()
        
    def scan_network(self):
        self.clear_result_display()
        subnet = self.subnet_entry.get()
        if not subnet:
            messagebox.showerror("Erreur", "Veuillez entrer un sous-réseau.")
            return
        
        self.result_text.insert(tk.END, "Scan du sous-réseau {} en cours...\n".format(subnet), "blue")
        self.result_text.update()
        
        try:
            active_hosts = self.scan_arp(subnet)
            open_ports = [ip for ip in active_hosts if self.scan_port_22(ip)]
            
            if open_ports:
                self.result_text.insert(tk.END, "Machines avec le port 22 ouvert :\n", "green")
                for ip in open_ports:
                    self.result_text.insert(tk.END, "{}\n".format(ip))
                    self.result_text.update()
                    self.save_to_temp_report(f"{ip} avec le port 22 ouvert.")
            else:
                message = "Aucune machine avec le port 22 ouvert trouvée."
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
                self.result_text.update()
        except Exception as e:
            messagebox.showerror("Erreur", str(e))
            
    def scan_arp(self, subnet):
        print(f"Scan ARP du sous-réseau {subnet}")
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append(received.psrc)
        return devices

    def scan_port_22(self, ip):
        print(f"Scan du port 22 sur l'adresse IP {ip}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 22))
        sock.close()
        return result == 0

    def download_files(self):
        self.clear_result_display()
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        username = self.username_entry.get()
        password = self.password_entry.get()
        remote_path = self.remote_path_entry.get()
        local_path = self.local_path_entry.get()
        
        if not host or not username or not password or not remote_path:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs nécessaires.")
            return
        
        self.result_text.insert(tk.END, "Connexion au serveur SSH {}...\n".format(host), "blue")
        self.result_text.update()
        
        try:
            ssh_client = self.create_ssh_client(host, port, username, password)
            if ssh_client is None:
                message = "Impossible de se connecter au serveur SSH après plusieurs tentatives."
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
                self.result_text.update()
                return
            
            self.result_text.insert(tk.END, "Téléchargement du fichier en cours...\n", "blue")
            self.result_text.update()
            self.download_file(ssh_client, remote_path, local_path)
        except paramiko.SSHException as e:
            message = f"Erreur SSH : {e}"
            messagebox.showerror("Erreur SSH", str(e))
            self.save_to_temp_report(message)
        except socket.timeout as e:
            message = f"Erreur de délai d'attente : {e}"
            messagebox.showerror("Erreur de délai d'attente", str(e))
            self.save_to_temp_report(message)
        except Exception as e:
            message = f"Erreur : {e}"
            messagebox.showerror("Erreur", str(e))
            self.save_to_temp_report(message)
        finally:
            if ssh_client:
                ssh_client.close()
        
        message = "Téléchargement terminé."
        self.result_text.insert(tk.END, message + "\n", "blue")
        self.save_to_temp_report(message)
        self.result_text.update()
        
    def create_ssh_client(self, host, port, username, password, retries=3):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for attempt in range(retries):
            try:
                print(f"Tentative de connexion SSH {attempt + 1}/{retries} à {host}:{port} avec l'utilisateur {username}")
                client.connect(host, port=port, username=username, password=password, timeout=10)
                return client
            except paramiko.AuthenticationException:
                message = "Authentification échouée, veuillez vérifier votre nom d'utilisateur ou mot de passe."
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
                self.result_text.update()
                break
            except paramiko.SSHException as sshException:
                message = f"Erreur de connexion SSH : {sshException}"
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
                self.result_text.update()
            except Exception as e:
                message = f"Erreur : {e}"
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
                self.result_text.update()
            self.result_text.insert(tk.END, "Nouvelle tentative ({}/{}).\n".format(attempt+1, retries), "yellow")
            self.result_text.update()
        return None

    def download_file(self, ssh_client, remote_path, local_path):
        remote_filename = os.path.basename(remote_path)
        local_file_path = os.path.join(local_path, remote_filename)
        try:
            print(f"Téléchargement du fichier {remote_path} vers {local_file_path}")
            self.result_text.insert(tk.END, "Téléchargement du fichier {} vers {}\n".format(remote_path, local_file_path), "blue")
            self.result_text.update()
            with SCPClient(ssh_client.get_transport()) as scp:
                scp.get(remote_path, local_file_path)
            if os.path.isfile(local_file_path):
                message = f"Téléchargement terminé avec succès ! Fichier enregistré sous : {local_file_path}"
                self.result_text.insert(tk.END, message + "\n", "green")
                self.save_to_temp_report(message)
            else:
                message = f"Erreur : Le fichier {local_file_path} n'a pas été trouvé après le téléchargement."
                self.result_text.insert(tk.END, message + "\n", "red")
                self.save_to_temp_report(message)
        except FileNotFoundError:
            message = f"Erreur : Le fichier {remote_path} n'existe pas sur le serveur."
            self.result_text.insert(tk.END, message + "\n", "red")
            self.save_to_temp_report(message)
        except Exception as e:
            message = f"Erreur lors du téléchargement de {remote_path} : {e}"
            self.result_text.insert(tk.END, message + "\n", "red")
            self.save_to_temp_report(message)
        self.result_text.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHFileDownloaderApp(root)
    root.mainloop()
