  <h1 align="center">🛡️ Security Onion SOC Lab</h1>
  <h3 align="center">Laboratoire de Cybersécurité Défensive</h3>
</p>

---

## 🔧 Objectif du projet

Ce laboratoire SOC (Security Operations Center) a été mis en place pour simuler des scénarios d’attaque/défense dans un environnement contrôlé, en utilisant des outils open source comme Security Onion, Suricata, Splunk, et des machines Windows/Linux.  
Il permet de comprendre la détection, l’analyse et la réponse aux incidents.

Vous pouvez l'installer en suivant ce qui est noter dans le fichier requirements.txt

---

## 🖥️ Topologie du lab virtuel

> 📌 Réalisé sur VMware Workstation  
> 📡 Toutes les VM sont interconnectées via des interfaces NAT/Host-Only + un routeur PFsense (Firewall/IDS)

---

## 💻 Machines virtuelles

### 🧅 Security Onion
- **Rôle** : SIEM, IDS/IPS (Suricata), HIDS (Wazuh), Analyse de logs
- **Outils installés** : Suricata, Zeek, Wazuh, Elasticsearch, Kibana, Sigma
- **IP** : `ip a` (eth0) / `10.0.0.5` (eth1)
- **Services monitorés** : SSH, Auth, Système, Netflow
- **Mot de passe** : `admin` (user: admin)

📸 *interface Security Onion effectuant la commande so-status*  
![image](https://github.com/user-attachments/assets/95fd0181-33f4-40d8-b39d-ced10a19f821)


---

### 🐍 Kali Linux
- **Rôle** : Machine d’attaque / Red Team
- **Utilisation** : Attaques SSH bruteforce, scan Nmap, exploitation
- **IP** : `ifconfig` ou `10.0.0.6`
- **Mot de passe** : `kali` (user: kali)

📸 *Capture terminal avec tentative SSH + alertes générées*  
 ![image](https://github.com/user-attachments/assets/8d716885-502a-4f80-9be6-42cb2385fe1c)
![image](https://github.com/user-attachments/assets/a9369eed-7894-4cc1-b7e1-b926a23fb579)


---

### 🪟 Windows 10
- **Rôle** : Machine utilisateur simulée
- **Utilisation** : Lancer des sessions bureautiques ou recevoir des payloads
- **Services** : RDP, navigateur, logs Winlogbeat
- **Mot de passe** : `P@ssw0rd` (user: LAB\j.wick)

---

### 🧱 Windows Server (Active Directory)
- **Rôle** : Serveur Windows 2019, Contrôleur de Domaine (DC)
- **Services** : Active Directory, DNS, LDAP
- **Utilisation** : Authentification des utilisateurs, tests de Kerberos
- **Mot de passe** : `P@ssw0rd` (user: LAB\Administrateur)

📸 *image de l'active directory*  
![image](https://github.com/user-attachments/assets/580f12d5-a970-4fc2-895e-3f345d342b3f) ![image](https://github.com/user-attachments/assets/6d7c0e04-77e1-4969-b8a4-b389f6152ea8)

---

### 🧾 Ubuntu
- **Rôle** : Poste analyste SOC
- **Utilisation** :
    - Connexion via navigateur à Security Onion pour visualisation des alertes dans Kibana, SOC, et Hunt
    - Connexion à pfSense pour administration du pare-feu via interface web
    - Utilisation comme poste centralisé d’investigation (accès web + outils)
    - Aucune attaque ni service déployé depuis cette machine, elle simule un poste analyste pur
- **Mot de passe** : `password`(user: analyst)
📸 *interface security onion*  
![image](https://github.com/user-attachments/assets/69e7a693-dcfd-40da-9d30-b90485c0298d)

📸 *interface security onion*  
![image](https://github.com/user-attachments/assets/82c8e606-4432-454f-ba58-fa69237e21cd)

---

### 🛡️ pfSense
- **Rôle** : Firewall & IDS (Suricata/Netflow optionnel)
- **Utilisation** : NAT, blocage d’IP, test de règles firewall
- **Interface web** : https://10.0.1.1/
- **Mot de passe** : `admin123` (user: admin)

📸 *liste des interfaces réseau détectées et configurée*  
![image](https://github.com/user-attachments/assets/734f6978-13b3-485c-9547-f30c5997ede1)

---

### 📊 Splunk
- Complément d’analyse log & alertes.
- Utilisé pour corréler les événements entre host Windows/Linux.
- Exemples : corrélation entre logs d’authentification et flux réseau suspects.
- **Mot de passe** : `p@ssw0rd` (user: admin)
📸 *Image dashboard Splunk*
![image](https://github.com/user-attachments/assets/16f3fd5d-5435-4272-9cf0-77e7f106c542)

---
# Vidéo à venir 

## 📽️ Démonstration Vidéo : simulation Brute-force SSH + visualisation alerte et log + Blocage IP

### Étapes de la vidéo

1. ✅ Vérifier que **Security Onion** est actif (`sudo so-status`)
2. ⚡ Depuis **Kali**, effectuer un brute-force SSH avec des mots de passe incorrects vers `Security Onion`
3. 🔔 Observer la génération automatique d'une alerte **Sigma** dans Kibana (`Grid Node Login Failure`)
4. 🔎 Analyser le fichier `/var/log/secure` :
   ```bash
   sudo grep 'sshd' /var/log/secure
5. 🚫 Bloquer l’adresse IP fautive avec :
   ```bash
   sudo iptables -A INPUT -s <IP_Kali> -j DROP
6. ✅ Vérifier l'effet avec un ping
7. 🧹 Débloquer l'IP avec :
   ```bash
   sudo iptables -D INPUT -s <IP_Kali> -j DROP
### 🧠 Compétences SOC mises en avant
- **Détection d’incidents avec Suricata et règles Sigma**
- **Corrélation d’événements dans Kibana (ex. : brute-force SSH, exploration réseau)**
- **Investigation des logs système (/var/log/secure, logs d’authentification)**
- **Réaction immédiate via iptables (blocage d’IP source d’attaque)**
- **Administration de pare-feu avec pfSense (règles de filtrage, NAT)**
- **Utilisation de Splunk pour l’analyse enrichie et la recherche inter-host**
- **Architecture sécurisée avec segmentation réseau (sous-réseaux, routage, DMZ)**
- **Mise en place d’un Active Directory sous Windows Server**
       - **Création d’un domaine et configuration du contrôleur de domaine**
       - **Ajout d’utilisateurs dans l’annuaire LDAP (avec politiques de mot de passe)**
       - **Intégration des postes Windows 10 et Ubuntu au domaine**
       - **Test d’authentification via des comptes du domaine depuis les clients**

### 📌 À venir
- **Configuration de Wazuh**
- **Intégration de vulnérabilités via Metasploit**
- **Test de détection exfiltration de données**

## 📬 Contact

Pour toute question ou suggestion, contactez-moi à :  
📧 **omar.elnmrawy@hotmail.com**

---

<h2 align="center">
⭐ Merci de laisser une étoile si ce projet vous a plu ! ⭐
</h2>

<p align="center">
<em>Laboratoire SOC que j’ai conçu pour apprendre concrètement à détecter, analyser et réagir face à des attaques simulées.</em>
</p>
