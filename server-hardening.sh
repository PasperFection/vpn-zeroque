#!/bin/bash
################################################################################
# Enterprise Production Server Hardening Script
# Voor Ubuntu 24.04 LTS - Gecontaineriseerde Applicatie Omgeving
# 
# Dit script configureert een volledig beveiligde productieserver
# voor het draaien van gecontaineriseerde applicaties.
#
# Gebruik: sudo ./server-hardening.sh
# Datum: November 2025
################################################################################

set -euo pipefail

# Kleuren voor output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging configuratie
LOG_DIR="/var/log/server-hardening"
LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/config-backups-$(date +%Y%m%d-%H%M%S)"

# Email voor notificaties (optioneel)
ADMIN_EMAIL="${ADMIN_EMAIL:-root@localhost}"

# SSH configuratie
SSH_PORT="${SSH_PORT:-22}"
CUSTOM_SSH_PORT="${CUSTOM_SSH_PORT:-2222}"

################################################################################
# HELPER FUNCTIES
################################################################################

# Logging functie
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Info output
info() {
    echo -e "${BLUE}[INFO]${NC} $@"
    log "INFO" "$@"
}

# Success output
success() {
    echo -e "${GREEN}[SUCCESS]${NC} $@"
    log "SUCCESS" "$@"
}

# Warning output
warning() {
    echo -e "${YELLOW}[WARNING]${NC} $@"
    log "WARNING" "$@"
}

# Error output
error() {
    echo -e "${RED}[ERROR]${NC} $@"
    log "ERROR" "$@"
}

# Backup functie
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_path="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -p "$file" "${backup_path}/$(basename "$file").bak"
        info "Backup gemaakt: $file"
    fi
}

# Check of script als root draait
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Dit script moet als root uitgevoerd worden"
        exit 1
    fi
}

# Systeem informatie detectie
detect_system() {
    info "Systeem informatie detecteren..."
    OS_VERSION=$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    KERNEL_VERSION=$(uname -r)
    TOTAL_RAM=$(free -h | awk '/^Mem:/ {print $2}')
    TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
    
    info "OS: $OS_VERSION"
    info "Kernel: $KERNEL_VERSION"
    info "RAM: $TOTAL_RAM"
    info "Disk: $TOTAL_DISK"
}

# Vraag bevestiging
confirm() {
    local prompt="$1"
    local default="${2:-n}"
    
    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" response
    response=${response:-$default}
    
    [[ "$response" =~ ^[Yy]$ ]]
}

################################################################################
# CONFIGURATIE FUNCTIES
################################################################################

# 1. Systeem Updates
update_system() {
    info "=== Systeem Updates Installeren ==="
    
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get autoclean -y
    
    success "Systeem volledig geüpdatet"
}

# 2. Docker Installatie
install_docker() {
    info "=== Docker Engine Installeren ==="
    
    if command -v docker &> /dev/null; then
        warning "Docker is al geïnstalleerd: $(docker --version)"
        return 0
    fi
    
    # Vereiste pakketten
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Docker repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Installeer Docker
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Docker daemon configuratie
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "storage-driver": "overlay2"
}
EOF
    
    systemctl enable docker
    systemctl restart docker
    
    success "Docker geïnstalleerd: $(docker --version)"
}

# 3. UFW Firewall Configuratie
configure_firewall() {
    info "=== UFW Firewall Configureren ==="
    
    # Installeer UFW
    apt-get install -y ufw
    
    # Backup huidige configuratie
    backup_file /etc/ufw/ufw.conf
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH toegang (belangrijk om lockout te voorkomen!)
    if [[ "$SSH_PORT" != "22" ]]; then
        ufw allow "$SSH_PORT/tcp" comment 'SSH Custom Port'
    else
        ufw limit 22/tcp comment 'SSH with rate limiting'
    fi
    
    # Docker networking
    ufw allow 2376/tcp comment 'Docker TLS'
    
    # HTTP/HTTPS voor containers
    if confirm "HTTP/HTTPS poorten openen voor webapplicaties?" "y"; then
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
    fi
    
    # Enable UFW
    ufw --force enable
    
    success "UFW Firewall geconfigureerd en actief"
    ufw status verbose
}

# 4. SSH Hardening
harden_ssh() {
    info "=== SSH Configuratie Hardenen ==="
    
    backup_file /etc/ssh/sshd_config
    
    # SSH configuratie aanpassingen
    cat >> /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
# SSH Hardening Configuration
Port $CUSTOM_SSH_PORT
Protocol 2

# Authenticatie
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable forwarding
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Kerberos en GSSAPI
KerberosAuthentication no
GSSAPIAuthentication no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
EOF
    
    # SSH service herstarten
    systemctl restart ssh
    
    success "SSH configuratie gehard (Poort: $CUSTOM_SSH_PORT)"
    warning "LET OP: SSH draait nu op poort $CUSTOM_SSH_PORT"
}

# 5. Fail2Ban Installatie
install_fail2ban() {
    info "=== Fail2Ban Installeren ==="
    
    apt-get install -y fail2ban
    
    # Fail2Ban configuratie
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = $ADMIN_EMAIL
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = $CUSTOM_SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[docker-auth]
enabled = true
filter = docker-auth
logpath = /var/log/docker.log
maxretry = 3
EOF
    
    # Custom filter voor Docker
    cat > /etc/fail2ban/filter.d/docker-auth.conf <<EOF
[Definition]
failregex = ^.*authentication failure.*rhost=<HOST>.*$
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "Fail2Ban geïnstalleerd en geconfigureerd"
}

# 6. Kernel Security Parameters
configure_sysctl() {
    info "=== Kernel Security Parameters Configureren ==="
    
    backup_file /etc/sysctl.conf
    
    cat >> /etc/sysctl.d/99-security.conf <<EOF
# Network Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 Security (indien niet gebruikt)
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# IP Forwarding voor Docker
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1

# Kernel Hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File System
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Performance & Limits
vm.swappiness = 10
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
EOF
    
    # Load bridge module voor Docker
    modprobe br_netfilter || true
    echo "br_netfilter" >> /etc/modules-load.d/br_netfilter.conf
    
    sysctl -p /etc/sysctl.d/99-security.conf
    
    success "Kernel security parameters toegepast"
}

# 7. Auditd Installatie
install_auditd() {
    info "=== Linux Audit Framework Installeren ==="
    
    apt-get install -y auditd audispd-plugins
    
    # Audit rules voor security monitoring
    cat > /etc/audit/rules.d/hardening.rules <<EOF
# Delete all previous rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Audit system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# User/Group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network-config
-w /etc/hosts -p wa -k network-config
-w /etc/network/ -p wa -k network-config

# Login/Logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd-config

# Docker events
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker/ -p wa -k docker
-w /etc/docker/ -p wa -k docker

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# File deletion by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Make configuration immutable
-e 2
EOF
    
    systemctl enable auditd
    systemctl restart auditd
    
    success "Auditd geïnstalleerd en geconfigureerd"
}

# 8. Unattended Upgrades
configure_auto_updates() {
    info "=== Automatische Security Updates Configureren ==="
    
    apt-get install -y unattended-upgrades apt-listchanges
    
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::Mail "$ADMIN_EMAIL";
Unattended-Upgrade::MailReport "on-change";
EOF
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    
    systemctl restart unattended-upgrades
    
    success "Automatische updates geconfigureerd"
}

# 9. Swap Configuratie
configure_swap() {
    info "=== Swap Space Configureren ==="
    
    local current_swap=$(free -h | awk '/^Swap:/ {print $2}')
    
    if [[ "$current_swap" == "0B" ]]; then
        if confirm "Swap space aanmaken (aanbevolen 2GB)?" "y"; then
            fallocate -l 2G /swapfile
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            
            # Swappiness voor server workload
            sysctl vm.swappiness=10
            
            success "Swap space aangemaakt (2GB)"
        fi
    else
        info "Swap space al geconfigureerd: $current_swap"
    fi
}

# 10. File System Hardening
harden_filesystem() {
    info "=== File System Hardening ==="
    
    # /tmp hardening met tmpfs
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0" >> /etc/fstab
    fi
    
    # /var/tmp hardening
    if ! grep -q "/var/tmp" /etc/fstab; then
        echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
    fi
    
    # /dev/shm hardening
    if grep -q "/dev/shm" /etc/fstab; then
        sed -i 's|tmpfs.*/dev/shm.*tmpfs.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' /etc/fstab
    else
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi
    
    success "Filesystem hardening toegepast (herstart vereist voor /tmp wijzigingen)"
}

# 11. Logging Configuratie
configure_logging() {
    info "=== Logging en Monitoring Configureren ==="
    
    # Logrotate configuratie
    cat > /etc/logrotate.d/docker-containers <<EOF
/var/lib/docker/containers/*/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
    
    # Journald configuratie
    backup_file /etc/systemd/journald.conf
    
    cat > /etc/systemd/journald.conf.d/99-logging.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
SystemMaxFileSize=100M
MaxRetentionSec=30day
ForwardToSyslog=yes
EOF
    
    systemctl restart systemd-journald
    
    success "Logging geconfigureerd"
}

# 12. User Management
configure_users() {
    info "=== User Management Configureren ==="
    
    # Docker groep membership beperken
    if getent group docker > /dev/null 2>&1; then
        info "Docker groep bestaat al"
    else
        groupadd docker
    fi
    
    # PAM hardening - wachtwoord policy
    apt-get install -y libpam-pwquality
    
    backup_file /etc/security/pwquality.conf
    
    cat > /etc/security/pwquality.conf <<EOF
# Wachtwoord complexiteit
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 3
EOF
    
    success "User management geconfigureerd"
}

# 13. Time Synchronization
configure_time_sync() {
    info "=== NTP Time Synchronization Configureren ==="
    
    # Systemd-timesyncd is standaard in Ubuntu
    backup_file /etc/systemd/timesyncd.conf
    
    cat > /etc/systemd/timesyncd.conf <<EOF
[Time]
NTP=ntp.ubuntu.com time.google.com time.cloudflare.com
FallbackNTP=pool.ntp.org
EOF
    
    systemctl restart systemd-timesyncd
    timedatectl set-ntp true
    
    success "Time synchronization geconfigureerd"
    timedatectl status
}

# 14. Installeer Security Tools
install_security_tools() {
    info "=== Extra Security Tools Installeren ==="
    
    apt-get install -y \
        aide \
        rkhunter \
        lynis \
        tripwire \
        net-tools \
        htop \
        iotop \
        iftop \
        ncdu \
        jq
    
    # AIDE initialiseren
    if [[ ! -f /var/lib/aide/aide.db ]]; then
        info "AIDE database initialiseren (dit kan even duren)..."
        aideinit || true
    fi
    
    success "Security tools geïnstalleerd"
}

# 15. Docker Security Configuratie
configure_docker_security() {
    info "=== Docker Security Best Practices Configureren ==="
    
    if ! command -v docker &> /dev/null; then
        warning "Docker niet geïnstalleerd, overslaan..."
        return 0
    fi
    
    # Docker default network met isolatie
    cat > /etc/docker/daemon.json.tmp <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "storage-driver": "overlay2",
  "userns-remap": "default",
  "seccomp-profile": "/etc/docker/seccomp-default.json"
}
EOF
    
    mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
    
    # Seccomp profile
    curl -sSL https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json \
        -o /etc/docker/seccomp-default.json 2>/dev/null || true
    
    systemctl restart docker
    
    success "Docker security configuratie toegepast"
}

################################################################################
# MAIN MENU FUNCTIE
################################################################################

show_menu() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}       ${GREEN}Enterprise Production Server Hardening Script${NC}                       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}       Ubuntu 24.04 LTS - Container Platform                               ${BLUE}║${NC}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}[AANBEVOLEN]${NC}                                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   1)  🚀 Volledige Automatische Installatie                               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}[SYSTEEM & NETWERK]${NC}                                                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   2)  📦 Systeem Updates                                                  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   3)  🐳 Docker Engine Installeren                                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   4)  🔥 Firewall (UFW) Configureren                                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  14)  🕐 Time Synchronization                                             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}[BEVEILIGING]${NC}                                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   5)  🔐 SSH Hardening                                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   6)  🛡️  Fail2Ban Installeren                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   7)  ⚙️  Kernel Security Parameters                                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   8)  📝 Auditd Installeren                                               ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  15)  🔧 Security Tools Installeren                                       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  16)  🐳 Docker Security Configuratie                                     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}[SYSTEEM CONFIGURATIE]${NC}                                                   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   9)  🔄 Automatische Updates                                             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  10)  💾 Swap Configuratie                                                ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  11)  📁 File System Hardening                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  12)  📋 Logging Configureren                                             ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  13)  👤 User Management                                                  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${YELLOW}[TOOLS & MONITORING]${NC}                                                     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  20)  📊 Systeem Status Weergeven                                         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  21)  🔍 Security Audit Uitvoeren (Lynis)                                 ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  22)  💾 Backup Configuratie Maken                                        ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}   ${RED}0)  ❌ Exit${NC}                                                            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                           ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Volledige installatie
full_installation() {
    info "=== VOLLEDIGE AUTOMATISCHE INSTALLATIE STARTEN ==="
    info "Dit proces kan 15-30 minuten duren..."
    
    if ! confirm "Volledige installatie uitvoeren?" "y"; then
        warning "Installatie geannuleerd"
        return 1
    fi
    
    update_system
    install_docker
    configure_sysctl
    configure_firewall
    harden_ssh
    install_fail2ban
    install_auditd
    configure_auto_updates
    configure_swap
    harden_filesystem
    configure_logging
    configure_users
    configure_time_sync
    install_security_tools
    configure_docker_security
    
    success "═══════════════════════════════════════════════════════════════"
    success "  VOLLEDIGE INSTALLATIE SUCCESVOL AFGEROND!"
    success "═══════════════════════════════════════════════════════════════"
    warning ""
    warning "BELANGRIJKE WAARSCHUWINGEN:"
    warning "1. SSH draait nu op poort $CUSTOM_SSH_PORT"
    warning "2. Alleen SSH key authenticatie is toegestaan"
    warning "3. UFW firewall is actief"
    warning "4. Herstart de server voor alle wijzigingen: sudo reboot"
    warning ""
    info "Logs: $LOG_FILE"
    info "Backups: $BACKUP_DIR"
}

# Systeem status weergeven
show_system_status() {
    clear
    info "=== SYSTEEM STATUS ==="
    echo ""
    
    echo "## Docker Status"
    if command -v docker &> /dev/null; then
        docker --version
        systemctl is-active docker && echo "✓ Docker service actief"
    else
        echo "✗ Docker niet geïnstalleerd"
    fi
    echo ""
    
    echo "## Firewall Status"
    ufw status
    echo ""
    
    echo "## Fail2Ban Status"
    if command -v fail2ban-client &> /dev/null; then
        fail2ban-client status || true
    else
        echo "✗ Fail2Ban niet geïnstalleerd"
    fi
    echo ""
    
    echo "## Security Services"
    systemctl is-active auditd && echo "✓ Auditd actief" || echo "✗ Auditd inactief"
    systemctl is-active unattended-upgrades && echo "✓ Auto-updates actief" || echo "✗ Auto-updates inactief"
    echo ""
    
    echo "## Resources"
    free -h | grep -E "Mem|Swap"
    echo ""
    df -h / | grep -v Filesystem
    echo ""
    
    read -p "Druk op Enter om terug te gaan..."
}

# Security audit met Lynis
run_security_audit() {
    info "=== SECURITY AUDIT UITVOEREN ==="
    
    if ! command -v lynis &> /dev/null; then
        warning "Lynis niet geïnstalleerd, installeren..."
        apt-get install -y lynis
    fi
    
    lynis audit system --quick
    
    read -p "Druk op Enter om terug te gaan..."
}

# Backup configuratie
backup_configuration() {
    info "=== CONFIGURATIE BACKUP MAKEN ==="
    
    local backup_timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_location="/root/manual-backup-${backup_timestamp}"
    
    mkdir -p "$backup_location"
    
    info "Backup locatie: $backup_location"
    
    # Lijst van belangrijke configuratiebestanden
    local config_files=(
        "/etc/ssh/sshd_config"
        "/etc/ssh/sshd_config.d/99-hardening.conf"
        "/etc/ufw/ufw.conf"
        "/etc/fail2ban/jail.local"
        "/etc/sysctl.d/99-security.conf"
        "/etc/docker/daemon.json"
        "/etc/audit/rules.d/hardening.rules"
        "/etc/apt/apt.conf.d/50unattended-upgrades"
        "/etc/apt/apt.conf.d/20auto-upgrades"
        "/etc/security/pwquality.conf"
        "/etc/systemd/timesyncd.conf"
        "/etc/systemd/journald.conf"
        "/etc/fstab"
    )
    
    local backed_up=0
    local skipped=0
    
    for file in "${config_files[@]}"; do
        if [[ -f "$file" ]]; then
            local backup_path="${backup_location}$(dirname "$file")"
            mkdir -p "$backup_path"
            cp -p "$file" "${backup_path}/$(basename "$file")"
            info "Gebackupt: $file"
            ((backed_up++))
        else
            warning "Bestand niet gevonden (overgeslagen): $file"
            ((skipped++))
        fi
    done
    
    # Backup UFW rules
    if command -v ufw &> /dev/null; then
        mkdir -p "${backup_location}/ufw-rules"
        ufw status verbose > "${backup_location}/ufw-rules/ufw-status.txt" 2>/dev/null || true
        info "UFW status gebackupt"
    fi
    
    # Backup Docker informatie
    if command -v docker &> /dev/null; then
        mkdir -p "${backup_location}/docker-info"
        docker info > "${backup_location}/docker-info/docker-info.txt" 2>/dev/null || true
        docker network ls > "${backup_location}/docker-info/networks.txt" 2>/dev/null || true
        info "Docker informatie gebackupt"
    fi
    
    # Backup iptables rules
    if command -v iptables &> /dev/null; then
        mkdir -p "${backup_location}/iptables"
        iptables-save > "${backup_location}/iptables/iptables-rules.txt" 2>/dev/null || true
        info "iptables rules gebackupt"
    fi
    
    # Maak tar archief
    local archive_name="/root/backup-${backup_timestamp}.tar.gz"
    tar -czf "$archive_name" -C "/root" "manual-backup-${backup_timestamp}" 2>/dev/null
    
    success "═══════════════════════════════════════════════════════════════"
    success "  BACKUP SUCCESVOL AFGEROND!"
    success "═══════════════════════════════════════════════════════════════"
    echo ""
    info "Bestanden gebackupt: $backed_up"
    info "Bestanden overgeslagen: $skipped"
    echo ""
    info "Backup directory: $backup_location"
    info "Backup archief: $archive_name"
    echo ""
    
    read -p "Druk op Enter om terug te gaan..."
}

################################################################################
# MAIN SCRIPT
################################################################################

main() {
    check_root
    
    # Setup logging directory
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    log "INFO" "Script gestart door gebruiker: $(whoami)"
    
    detect_system
    
    # Interactive mode
    if [[ $# -eq 0 ]]; then
        while true; do
            show_menu
            read -p "Selecteer optie: " choice
            
            case $choice in
                1) full_installation ;;
                2) update_system ;;
                3) install_docker ;;
                4) configure_firewall ;;
                5) harden_ssh ;;
                6) install_fail2ban ;;
                7) configure_sysctl ;;
                8) install_auditd ;;
                9) configure_auto_updates ;;
                10) configure_swap ;;
                11) harden_filesystem ;;
                12) configure_logging ;;
                13) configure_users ;;
                14) configure_time_sync ;;
                15) install_security_tools ;;
                16) configure_docker_security ;;
                20) show_system_status ;;
                21) run_security_audit ;;
                22) backup_configuration ;;
                0) 
                    info "Script beëindigd"
                    exit 0
                    ;;
                *)
                    error "Ongeldige optie: $choice"
                    sleep 2
                    ;;
            esac
            
            if [[ $choice != "20" && $choice != "21" && $choice != "22" && $choice != "0" ]]; then
                read -p "Druk op Enter om door te gaan..."
            fi
        done
    fi
    
    # Non-interactive mode
    if [[ "$1" == "--full" || "$1" == "-f" ]]; then
        full_installation
    elif [[ "$1" == "--help" || "$1" == "-h" ]]; then
        echo "Gebruik: $0 [OPTIE]"
        echo ""
        echo "Opties:"
        echo "  --full, -f    Volledige automatische installatie"
        echo "  --help, -h    Deze help tekst"
        echo ""
        echo "Zonder opties wordt het interactieve menu getoond"
    fi
}

# Start script
main "$@"
