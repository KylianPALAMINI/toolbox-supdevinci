import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import webbrowser

# Variable pour suivre l'état du mode sombre
dark_mode = False

# Variable pour suivre l'état du programme en cours d'exécution
program_running = False

def open_program(program_path):
    global program_running
    if program_running:
        messagebox.showwarning("Attention", "Un programme est déjà en cours d'exécution.")
        return

    def run_program():
        global program_running
        program_running = True
        disable_buttons()
        subprocess.run(['python', program_path], creationflags=subprocess.CREATE_NO_WINDOW)
        program_running = False
        enable_buttons()

    program_thread = threading.Thread(target=run_program)
    program_thread.start()

def disable_buttons():
    for button_frame in button_frames:
        for widget in button_frame.winfo_children():
            widget.config(state=tk.DISABLED)

def enable_buttons():
    for button_frame in button_frames:
        for widget in button_frame.winfo_children():
            widget.config(state=tk.NORMAL)

def toggle_mode():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme()

def apply_theme():
    if dark_mode:
        root.config(bg="#2e2e2e")
        title_label.config(bg="#2e2e2e", fg="white")
        created_by_label.config(bg="#2e2e2e", fg="white")
        mode_button.config(bg="#444444", fg="white")
        for button_frame in button_frames:
            button_frame.config(bg="#444444")
            button_frame.pack_configure(pady=5)
            for widget in button_frame.winfo_children():
                widget.config(bg="#444444", fg="white", activebackground="#555555", activeforeground="white")
    else:
        root.config(bg="white")
        title_label.config(bg="white", fg="black")
        created_by_label.config(bg="white", fg="black")
        mode_button.config(bg="lightgray", fg="black")
        for button_frame in button_frames:
            button_frame.config(bg="lightgray")
            button_frame.pack_configure(pady=5)
            for widget in button_frame.winfo_children():
                widget.config(bg="lightgray", fg="black", activebackground="#dddddd", activeforeground="black")

def create_button(frame, text, icon_path, command):
    icon = Image.open(icon_path)
    icon = icon.resize((50, 50), Image.LANCZOS)
    icon_photo = ImageTk.PhotoImage(icon)

    button_frame = tk.Frame(frame, bg="lightgray")
    button_frame.pack(fill=tk.X, pady=5)

    icon_label = tk.Label(button_frame, image=icon_photo, bg="lightgray")
    icon_label.image = icon_photo
    icon_label.pack(side=tk.LEFT, padx=10)

    button = tk.Button(button_frame, text=text, compound=tk.LEFT, command=command, bg="lightgray")
    button.pack(side=tk.LEFT, fill=tk.X, expand=True)

    button_frames.append(button_frame)

def open_github():
    webbrowser.open("https://github.com/KylianPALAMINI/toolbox-supdevinci.git")

def show_about():
    about_text = (
        "Présentation Globale du Programme:\n\n"
        "Le programme 'Cybersécurité Toolbox' est une suite d'outils destinée aux professionnels et aux étudiants "
        "en cybersécurité. Ce programme offre une gamme d'utilitaires pour effectuer divers types de tests et d'analyses "
        "sur des réseaux et des systèmes informatiques, afin d'identifier des vulnérabilités, évaluer la sécurité et "
        "renforcer les défenses contre les cyberattaques.\n\n"
        "Situations d'Utilisation:\n"
        "Ce programme peut être utilisé dans de nombreuses situations, notamment:\n"
        "- Évaluation de la sécurité d'un réseau interne ou d'un réseau d'entreprise.\n"
        "- Tests de pénétration pour identifier les faiblesses potentielles avant qu'un attaquant ne les exploite.\n"
        "- Formation et éducation en cybersécurité pour les étudiants et les professionnels.\n"
        "- Validation de la configuration de la sécurité après des modifications ou des mises à jour.\n"
        "- Surveillance continue de la sécurité pour détecter les nouvelles vulnérabilités.\n\n"
        "Fonctionnalités Proposées:\n"
        "1. **Scan de Ports:**\n"
        "   - Effectue un scan des ports pour identifier les ports ouverts sur une cible spécifique.\n"
        "   - Utilise Nmap pour fournir des détails sur les services en cours d'exécution et leur état.\n"
        "   - Utile pour découvrir les points d'entrée potentiels pour les attaquants.\n\n"
        "2. **Scan de Vulnérabilités:**\n"
        "   - Utilise l'API Shodan pour rechercher les vulnérabilités connues sur une cible.\n"
        "   - Effectue également des scans de ports avec Scapy pour une analyse plus détaillée.\n"
        "   - Génère un rapport complet des vulnérabilités trouvées, y compris les descriptions et les scores CVSS.\n\n"
        "3. **Bruteforce FTP:**\n"
        "   - Tente de trouver le mot de passe FTP d'une cible en utilisant une liste de mots de passe.\n"
        "   - Utilise une approche multithread pour accélérer le processus de bruteforce.\n"
        "   - Idéal pour tester la robustesse des mots de passe FTP.\n\n"
        "4. **Bruteforce SSH:**\n"
        "   - Tente de trouver le mot de passe SSH d'une cible en utilisant une liste de mots de passe.\n"
        "   - Utilise une approche multithread pour accélérer le processus de bruteforce.\n"
        "   - Utile pour évaluer la sécurité des accès SSH.\n\n"
        "5. **Extracteur de Données:**\n"
        "   - Permet de télécharger des fichiers depuis une machine distante via SSH.\n"
        "   - Offre des fonctionnalités de scan de réseau pour identifier les hôtes actifs.\n"
        "   - Pratique pour l'analyse de fichiers sur des systèmes distants.\n\n"
        "6. **Scan CVE:**\n"
        "   - Recherche les vulnérabilités CVE associées aux services en cours d'exécution sur une cible.\n"
        "   - Utilise l'API Vulners pour obtenir des informations détaillées sur les CVE.\n"
        "   - Génère des rapports incluant des descriptions de vulnérabilités et des recommandations de mitigation.\n\n"
        "7. **Test de Débit/Connexion:**\n"
        "   - Effectue des tests de vitesse de connexion pour évaluer les débits de téléchargement et d'upload.\n"
        "   - Utilise des pings et des tests de vitesse pour fournir une évaluation complète de la qualité de la connexion.\n"
        "   - Idéal pour diagnostiquer les problèmes de réseau et de performance.\n\n"
        "Rappel Important:\n"
        "Ce programme est conforme aux recommandations de l'ANSSI (Agence Nationale de la Sécurité des Systèmes d'Information). "
        "Il est crucial de rappeler que l'utilisation de ce logiciel doit se faire dans un cadre légal et éthique. "
        "L'utilisation de ce programme à des fins malveillantes, telles que l'intrusion non autorisée ou la compromission de systèmes, "
        "est strictement interdite et passible de sanctions pénales conformément à l'article 323-3 du Code pénal français. "
        "Cet article stipule que le fait d'accéder frauduleusement ou de se maintenir dans tout ou partie d'un système de traitement automatisé "
        "de données est puni de deux ans d'emprisonnement et de 30 000 euros d'amende.\n\n"
        "Conclusion:\n"
        "La 'Cybersécurité Toolbox' est un ensemble d'outils puissants et polyvalents pour quiconque souhaite renforcer la sécurité de ses systèmes "
        "informatiques. En suivant les bonnes pratiques et en respectant les lois en vigueur, vous pouvez utiliser ces outils pour identifier "
        "et corriger les failles de sécurité, contribuant ainsi à un environnement numérique plus sûr."
    )
    messagebox.showinfo("À propos", about_text)


root = tk.Tk()
root.title("Menu Principal")
root.geometry("600x720")
root.iconbitmap("F:/Documents/07_projet_python/programmes_ok/logos/menu_principal.ico")

title_label = tk.Label(root, text="Cybersécurité Toolbox", font=("Helvetica", 24, "bold"))
title_label.pack(pady=20)

nav_frame = tk.Frame(root)
nav_frame.pack(pady=5)

github_button = tk.Button(nav_frame, text="GitHub", command=open_github)
github_button.pack(side=tk.LEFT, padx=10)

about_button = tk.Button(nav_frame, text="À Propos", command=show_about)
about_button.pack(side=tk.LEFT, padx=10)

mode_button = tk.Button(root, text="Mode Sombre", command=toggle_mode)
mode_button.pack(pady=10)

frame = tk.Frame(root)
frame.pack(pady=20)

button_frames = []

# Ajouter les boutons pour chaque programme
programs = [
    ("Scan de Ports", "F:/Documents/07_projet_python/programmes_ok/icons/scan_port.png", "F:/Documents/07_projet_python/programmes_ok/scan_port_v3_ui.py"),
    ("Scan de Vulnérabilités", "F:/Documents/07_projet_python/programmes_ok/icons/scan_vuln.png", "F:/Documents/07_projet_python/programmes_ok/vulnera_scan_v1_ui.py"),
    ("Bruteforce FTP", "F:/Documents/07_projet_python/programmes_ok/icons/bruteforce_ftp.png", "F:/Documents/07_projet_python/programmes_ok/bruteforce_ftp_v1_ui.py"),
    ("Bruteforce SSH", "F:/Documents/07_projet_python/programmes_ok/icons/bruteforce_ssh.png", "F:/Documents/07_projet_python/programmes_ok/bruteforce_ssh_v1_ui.py"),
    ("Extracteur de Données", "F:/Documents/07_projet_python/programmes_ok/icons/data_extractor.png", "F:/Documents/07_projet_python/programmes_ok/extracteur_data_v4_ui.py"),
    ("Scan CVE", "F:/Documents/07_projet_python/programmes_ok/icons/scan_cve.png", "F:/Documents/07_projet_python/programmes_ok/scan_cve_01_ui.py"),
    ("Test de Débit/Connexion", "F:/Documents/07_projet_python/programmes_ok/icons/test_connection.png", "F:/Documents/07_projet_python/programmes_ok/test_debit_connexion_ui.py"),
]

for text, icon_path, program_path in programs:
    create_button(frame, text, icon_path, lambda p=program_path: open_program(p))

created_by_label = tk.Label(root, text="Créé par Kylian Palamini, étudiant Master 1 Sup de Vinci", font=("Helvetica", 10))
created_by_label.pack(side=tk.BOTTOM, pady=20)

apply_theme()
root.mainloop()
