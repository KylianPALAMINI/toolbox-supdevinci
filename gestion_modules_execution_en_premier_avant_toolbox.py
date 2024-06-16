import subprocess
import sys

def install_and_verify(package, module_name, display_name):
    try:
        __import__(module_name)
        print(f"{display_name} est déjà installé.")
    except ImportError:
        print(f"{display_name} n'est pas installé. Installation en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        try:
            __import__(module_name)
            print(f"{display_name} a été installé avec succès.")
        except ImportError:
            print(f"Erreur : {display_name} n'a pas pu être installé.")

def uninstall_module(package, display_name):
    try:
        print(f"Désinstallation de {display_name} en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", package])
        print(f"{display_name} a été désinstallé avec succès.")
    except subprocess.CalledProcessError:
        print(f"Erreur : {display_name} n'a pas pu être désinstallé.")

def install_all_modules():
    modules = {
        "python-nmap": "nmap",
        "shodan": "shodan",
        "ftplib": "ftplib",
        "paramiko": "paramiko",
        "scp": "scp",
        "requests": "requests",
        "python-docx": "docx",
        "pythonping": "pythonping",
        "scapy": "scapy.all"
    }

    for package, module_name in modules.items():
        install_and_verify(package, module_name, package)

    print("Installation des modules terminée. Appuyez sur Entrée pour fermer le programme.")

def uninstall_all_modules():
    modules = {
        "python-nmap": "nmap",
        "shodan": "shodan",
        "ftplib": "ftplib",
        "paramiko": "paramiko",
        "scp": "scp",
        "requests": "requests",
        "python-docx": "docx",
        "pythonping": "pythonping",
        "scapy": "scapy.all"
    }

    for package, module_name in modules.items():
        uninstall_module(package, package)

    print("Désinstallation des modules terminée. Appuyez sur Entrée pour fermer le programme.")

def main():
    print("Choisissez une option :")
    print("1. Installer les modules")
    print("2. Désinstaller les modules")
    choice = input("Entrez votre choix (1 ou 2) : ")

    if choice == "1":
        install_all_modules()
    elif choice == "2":
        uninstall_all_modules()
    else:
        print("Choix invalide. Veuillez réessayer.")

    input("Appuyez sur Entrée pour fermer le programme.")

if __name__ == "__main__":
    main()
