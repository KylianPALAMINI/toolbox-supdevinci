import subprocess
import sys

def install_and_verify(package):
    try:
        __import__(package)
        print(f"{package} est déjà installé.")
    except ImportError:
        print(f"{package} n'est pas installé. Installation en cours...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def uninstall_and_verify(package):
    try:
        __import__(package)
        print(f"Désinstallation de {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", package])
    except ImportError:
        print(f"{package} n'est pas installé.")

def install_all_modules():
    modules = [
        "nmap", "requests", "docx", "openai", "tk", "pillow", "colorama", "pythonping", 
        "shodan", "paramiko", "scp", "ftplib", "speedtest-cli", "python-docx", 
        "reportlab", "uuid", "json", "threading", "datetime", "subprocess", 
        "tkinter", "scrolledtext", "pywin32"
    ]
    for module in modules:
        install_and_verify(module)

def uninstall_all_modules():
    modules = [
        "nmap", "requests", "docx", "openai", "tk", "pillow", "colorama", "pythonping", 
        "shodan", "paramiko", "scp", "ftplib", "speedtest-cli", "python-docx", 
        "reportlab", "uuid", "json", "threading", "datetime", "subprocess", 
        "tkinter", "scrolledtext", "pywin32"
    ]
    for module in modules:
        uninstall_and_verify(module)

def main():
    print("Choisissez une option :")
    print("1. Installer les modules")
    print("2. Désinstaller les modules")
    choix = input("Entrez votre choix (1 ou 2) : ")

    if choix == "1":
        install_all_modules()
    elif choix == "2":
        uninstall_all_modules()
    else:
        print("Choix invalide.")

    input("Appuyez sur une touche pour fermer le programme.")

if __name__ == "__main__":
    main()
