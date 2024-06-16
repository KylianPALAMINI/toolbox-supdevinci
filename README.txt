!!! Attention !!!
MERCI d'éxecuter en premier lieu le programme "gestion_modules_execution_en_premier_avant_toolbox.py" qui permet l'installation de l'ensemble des modules nécessaires à l'utilisation de la toolbox ET la désinstallation de ces derniers si voulu.


# Cybersécurité Toolbox

## Présentation Globale du Programme

Le programme 'Cybersécurité Toolbox' est une suite d'outils destinée aux professionnels et aux étudiants en cybersécurité. Ce programme offre une gamme d'utilitaires pour effectuer divers types de tests et d'analyses sur des réseaux et des systèmes informatiques, afin d'identifier des vulnérabilités, évaluer la sécurité et renforcer les défenses contre les cyberattaques.

### Situations d'Utilisation
Ce programme peut être utilisé dans de nombreuses situations, notamment:
- Évaluation de la sécurité d'un réseau interne ou d'un réseau d'entreprise.
- Tests de pénétration pour identifier les faiblesses potentielles avant qu'un attaquant ne les exploite.
- Formation et éducation en cybersécurité pour les étudiants et les professionnels.
- Validation de la configuration de la sécurité après des modifications ou des mises à jour.
- Surveillance continue de la sécurité pour détecter les nouvelles vulnérabilités.

## Fonctionnalités Proposées

1. **Scan de Ports:**
   - Effectue un scan des ports pour identifier les ports ouverts sur une cible spécifique.
   - Utilise Nmap pour fournir des détails sur les services en cours d'exécution et leur état.
   - Utile pour découvrir les points d'entrée potentiels pour les attaquants.

2. **Scan de Vulnérabilités:**
   - Utilise l'API Shodan pour rechercher les vulnérabilités connues sur une cible.
   - Effectue également des scans de ports avec Scapy pour une analyse plus détaillée.
   - Génère un rapport complet des vulnérabilités trouvées, y compris les descriptions et les scores CVSS.

3. **Bruteforce FTP:**
   - Tente de trouver le mot de passe FTP d'une cible en utilisant une liste de mots de passe.
   - Utilise une approche multithread pour accélérer le processus de bruteforce.
   - Idéal pour tester la robustesse des mots de passe FTP.

4. **Bruteforce SSH:**
   - Tente de trouver le mot de passe SSH d'une cible en utilisant une liste de mots de passe.
   - Utilise une approche multithread pour accélérer le processus de bruteforce.
   - Utile pour évaluer la sécurité des accès SSH.

5. **Extracteur de Données:**
   - Permet de télécharger des fichiers depuis une machine distante via SSH.
   - Offre des fonctionnalités de scan de réseau pour identifier les hôtes actifs.
   - Pratique pour l'analyse de fichiers sur des systèmes distants.

6. **Scan CVE:**
   - Recherche les vulnérabilités CVE associées aux services en cours d'exécution sur une cible.
   - Utilise l'API Vulners pour obtenir des informations détaillées sur les CVE.
   - Génère des rapports incluant des descriptions de vulnérabilités et des recommandations de mitigation.

7. **Test de Débit/Connexion:**
   - Effectue des tests de vitesse de connexion pour évaluer les débits de téléchargement et d'upload.
   - Utilise des pings et des tests de vitesse pour fournir une évaluation complète de la qualité de la connexion.
   - Idéal pour diagnostiquer les problèmes de réseau et de performance.

## Rappel Important

Ce programme est conforme aux recommandations de l'ANSSI (Agence Nationale de la Sécurité des Systèmes d'Information). Il est crucial de rappeler que l'utilisation de ce logiciel doit se faire dans un cadre légal et éthique. L'utilisation de ce programme à des fins malveillantes, telles que l'intrusion non autorisée ou la compromission de systèmes, est strictement interdite et passible de sanctions pénales conformément à l'article 323-3 du Code pénal français. Cet article stipule que le fait d'accéder frauduleusement ou de se maintenir dans tout ou partie d'un système de traitement automatisé de données est puni de deux ans d'emprisonnement et de 30 000 euros d'amende.

## Conclusion

La 'Cybersécurité Toolbox' est un ensemble d'outils puissants et polyvalents pour quiconque souhaite renforcer la sécurité de ses systèmes informatiques. En suivant les bonnes pratiques et en respectant les lois en vigueur, vous pouvez utiliser ces outils pour identifier et corriger les failles de sécurité, contribuant ainsi à un environnement numérique plus sûr.
