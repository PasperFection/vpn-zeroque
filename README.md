# VPS-Zero

Enterprise Production Server Hardening Script voor Ubuntu 24.04 LTS. Dit script biedt een complete oplossing voor het beveiligen van VPS servers voor het draaien van gecontaineriseerde applicaties.

## 🚀 Snelle Start

```bash
# Download en maak uitvoerbaar
chmod +x server-hardening.sh

# Start interactief menu
sudo ./server-hardening.sh

# Of volledige automatische installatie
sudo ./server-hardening.sh --full

# Help weergeven
sudo ./server-hardening.sh --help
```

## ✨ Features

### Interactief Menu Systeem
- **Optie 1**: Volledige Automatische Installatie (aanbevolen)
- **Opties 2-16**: Individuele configuratie modules
- **Optie 20**: Systeem Status Dashboard
- **Optie 21**: Security Audit met Lynis
- **Optie 22**: Backup Configuratie

### Menu Opties Overzicht

| Optie | Functie | Beschrijving |
|-------|---------|--------------|
| 1 | Volledige Installatie | Voert alle hardening stappen automatisch uit |
| 2 | Systeem Updates | APT update, upgrade en cleanup |
| 3 | Docker Engine | Installeert Docker met security configuratie |
| 4 | UFW Firewall | Configureert firewall met rate limiting |
| 5 | SSH Hardening | Custom poort, key-only authenticatie |
| 6 | Fail2Ban | Brute-force bescherming |
| 7 | Kernel Security | Sysctl parameters voor beveiliging |
| 8 | Auditd | Linux Audit Framework |
| 9 | Auto Updates | Automatische security updates |
| 10 | Swap | Swap space configuratie |
| 11 | Filesystem | Hardening van /tmp, /var/tmp, /dev/shm |
| 12 | Logging | Logrotate en journald configuratie |
| 13 | User Management | PAM wachtwoord policy |
| 14 | Time Sync | NTP synchronisatie |
| 15 | Security Tools | AIDE, rkhunter, lynis, tripwire |
| 16 | Docker Security | User namespaces, seccomp profiles |
| 20 | Status | Systeem status dashboard |
| 21 | Security Audit | Lynis security scan |
| 22 | Backup | Configuratie backup maken |

## 🔧 Geïmplementeerde Hardening

- **Docker Engine** met security best practices
- **UFW Firewall** met rate limiting
- **SSH Hardening** (custom poort, key-only auth)
- **Fail2Ban** met Docker protection
- **Kernel Security Parameters** (sysctl)
- **Auditd** met uitgebreide rules
- **Automatische Security Updates** (unattended-upgrades)
- **Swap Configuratie** (2GB standaard)
- **Filesystem Hardening** (noexec, nosuid, nodev)
- **Logging & Logrotate** configuratie
- **User Management & PAM** hardening
- **NTP Synchronisatie** via systemd-timesyncd
- **Security Tools** (AIDE, Lynis, rkhunter, tripwire)
- **Docker Security** (user namespaces, seccomp)

## 🛡️ Veiligheidsfeatures

- ✅ Automatische backups van alle configuraties
- ✅ Gedetailleerde logging (`/var/log/server-hardening/`)
- ✅ Color-coded output (info/success/warning/error)
- ✅ Bevestigingen voor kritieke acties
- ✅ Error handling met `set -euo pipefail`
- ✅ Rollback mogelijkheid via backups

## 📋 Vereisten

- Ubuntu 24.04 LTS (of compatibele versie)
- Root toegang (sudo)
- Werkende internetverbinding
- SSH toegang (voor remote servers)

## ⚠️ Belangrijke Waarschuwingen

Na installatie:
1. SSH draait op een **custom poort** (standaard: 2222)
2. Alleen **SSH key authenticatie** is toegestaan
3. **UFW firewall** is actief
4. **Herstart** de server voor alle wijzigingen: `sudo reboot`

## 📁 Bestanden Locaties

| Type | Locatie |
|------|---------|
| Logs | `/var/log/server-hardening/` |
| Backups | `/root/config-backups-{timestamp}/` |
| Docker config | `/etc/docker/daemon.json` |
| SSH config | `/etc/ssh/sshd_config.d/99-hardening.conf` |
| Firewall | `/etc/ufw/` |
| Audit rules | `/etc/audit/rules.d/hardening.rules` |

## 🔄 Omgevingsvariabelen

```bash
# SSH configuratie (optioneel)
export SSH_PORT=22           # Huidige SSH poort
export CUSTOM_SSH_PORT=2222  # Nieuwe SSH poort

# Admin email voor notificaties
export ADMIN_EMAIL=admin@example.com
```

## 📄 Licentie

MIT License - Zie [LICENSE](LICENSE) voor details.

## 🤝 Bijdragen

Bijdragen zijn welkom! Open een issue of pull request voor verbeteringen.
