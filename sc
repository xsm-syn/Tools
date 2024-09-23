#!/bin/bash

# Colors
green="\e[38;5;82m"
red="\e[38;5;196m"
neutral="\e[0m"
orange="\e[38;5;130m"
blue="\e[38;5;39m"
yellow="\e[38;5;226m"
purple="\e[38;5;141m"
bold_white="\e[1;37m"
reset="\e[0m"
pink="\e[38;5;205m"

print_rainbow() {
    local text="$1"
    local length=${#text}
    local start_color=(0 5 0)
    local mid_color=(0 200 0)
    local end_color=(0 5 0)

    for ((i = 0; i < length; i++)); do
        local progress=$((i * 100 / (length - 1)))

        if [ $progress -lt 50 ]; then
            local factor=$((progress * 2))
            r=$(((start_color[0] * (100 - factor) + mid_color[0] * factor) / 100))
            g=$(((start_color[1] * (100 - factor) + mid_color[1] * factor) / 100))
            b=$(((start_color[2] * (100 - factor) + mid_color[2] * factor) / 100))
        else
            local factor=$(((progress - 50) * 2))
            r=$(((mid_color[0] * (100 - factor) + end_color[0] * factor) / 100))
            g=$(((mid_color[1] * (100 - factor) + end_color[1] * factor) / 100))
            b=$(((mid_color[2] * (100 - factor) + end_color[2] * factor) / 100))
        fi

        printf "\e[38;2;%d;%d;%dm%s" "$r" "$g" "$b" "${text:$i:1}"
    done
    echo -e "$reset" # Reset color at the end
}
# Create directories if they do not exist
directories=(
    /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /usr/bin/xray /var/log/xray
    /var/www/html /etc/haproxy /etc/xray/vmess /etc/xray/vless /etc/xray/trojan /etc/xray/shadowsocks /etc/xray/ssh
)
for dir in "${directories[@]}"; do
    [ ! -d "$dir" ] && mkdir -p "$dir"
    chmod 777 "$dir"
done
clear
# Tampilkan menu
if [ -z "$1" ]; then
    echo -e "${orange}─────────────────────────────────────────${neutral}"
    echo -e "     ${green}.::::. FIGHTERTUNNEL .::::.${neutral}"
    echo -e "${orange}─────────────────────────────────────────${neutral}"
    echo -e "${blue}The Best Place for Secure and Fast Connection!${neutral}"
    echo -e "${yellow}Enter your domain to start the installer:${neutral}"
    echo -e ""
    print_rainbow "────────────────────────────────────"
    read -p "  Enter your domain: " domain
    read -p "  Enter key: " keys
else
    domain="$1"
fi

# Check if the domain resolves to the VPS IP
vps_ip=$(curl -s ipinfo.io/ip)
domain_ip=$(getent ahosts $domain | awk '{print $1}' | head -n 1)

if [ "$domain_ip" != "$vps_ip" ]; then
    echo -e "${red}Domain is not connected to the VPS IP. Please check again.${neutral}"
    exit 1
fi

echo $domain >/etc/xray/domain
echo $keys >/root/.key

# Create files if they do not exist
files=(
    /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log /etc/xray/vmess/.vmess.db
    /etc/xray/vless/.vless.db /etc/xray/trojan/.trojan.db /etc/xray/shadowsocks/.shadowsocks.db /etc/xray/ssh/.ssh.db /etc/ssh/.ssh.db
    /var/log/xray/access.log /var/log/xray/error.log
)
for file in "${files[@]}"; do
    [ ! -f "$file" ] && touch "$file"
    chmod 777 "$file"
done

# Grant execution permissions to directories
chmod +x /var/log/xray /etc/xray /etc/haproxy /etc/xray/vmess /etc/xray/vless /etc/xray/trojan /etc/xray/shadowsocks /etc/xray/ssh

# Define variables
domain_ns="dnstt.me"
timezone="Asia/Jakarta"
slowdns_dir="/etc/slowdns"
city=$(curl -s ipinfo.io/city)
isp=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
domain=$(cat /etc/xray/domain)
cf_id="nuryahyamuhaimin@gmail.com"
cf_key="9dd2f30c099dbcf541cbd5c188d61ce060cf7"
ip=$(wget -qO- ipinfo.io/ip)
key=$(curl -s https://xcodez1.pythonanywhere.com/apikey?ip=$ip)
nginx_key_url="https://nginx.org/keys/nginx_signing.key"
dropbear_init_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/dropbear/dropbear"
dropbear_conf_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/FighterTunnel-examples/dropbear"
dropbear_dss_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/dropbear/dropbear_dss_host_key"
sshd_conf_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/FighterTunnel-examples/sshd"
banner_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/FighterTunnel-examples/banner"
common_password_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/FighterTunnel-examples/common-password"
ws_py_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/websocket/ws.py"
client_service_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/X-SlowDNS/client"
server_service_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/X-SlowDNS/server"
gotop_url="https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh"
haproxy_cfg_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/Haproxy/haproxy.cfg"
xray_conf_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/nginx/xray.conf"
udp_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/bhoikfostyahya/udp-custom-linux-amd64"
nginx_conf_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/nginx/nginx.conf"
badvpn_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/BadVPN-UDPWG/badvpn"
openvpn_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/openvpn/openvpn.zip"
vmess_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/VMess-VLESS-Trojan+Websocket+gRPC/vmess/config.json"
vless_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/VMess-VLESS-Trojan+Websocket+gRPC/vless/config.json"
trojan_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/VMess-VLESS-Trojan+Websocket+gRPC/trojan/config.json"
shadowsocks_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/VMess-VLESS-Trojan+Websocket+gRPC/shadowsocks/config.json"
bbr_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/fodder/bbr.sh"
dnstt_client_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/X-SlowDNS/dnstt-client"
dnstt_server_url="https://raw.githubusercontent.com/FighterTunnel/tunnel/main/X-SlowDNS/dnstt-server"
file_dir="https://raw.githubusercontent.com/xsm-syn/reinstall/main/src.zip"

os_id=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
os_version=$(grep -w VERSION_ID /etc/os-release | head -n1 | sed 's/VERSION_ID=//g' | sed 's/"//g')
echo "OS: $os_id, Version: $os_version"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${red}This script must be run as root${neutral}"
    exit 1
fi

# Update and install basic packages
if ! apt update -y; then
    echo -e "${red}Failed to update${neutral}"
fi

if ! dpkg -s sudo >/dev/null 2>&1; then
    if ! apt install sudo -y; then
        echo -e "${red}Failed to install sudo${neutral}"
    fi
else
    echo -e "${green}sudo is already installed, skipping...${neutral}"
fi

if ! dpkg -s software-properties-common debconf-utils >/dev/null 2>&1; then
    if ! apt install -y --no-install-recommends software-properties-common debconf-utils; then
        echo -e "${red}Failed to install basic packages${neutral}"
    fi
else
    echo -e "${green}software-properties-common and debconf-utils are already installed, skipping...${neutral}"
fi

# Remove unnecessary packages
if dpkg -s exim4 >/dev/null 2>&1; then
    if ! apt remove --purge -y exim4; then
        echo -e "${red}Failed to remove exim4${neutral}"
    else
        echo -e "${green}exim4 removed successfully${neutral}"
    fi
else
    echo -e "${green}exim4 is not installed, skipping...${neutral}"
fi

if dpkg -s ufw >/dev/null 2>&1; then
    if ! apt remove --purge -y ufw; then
        echo -e "${red}Failed to remove ufw${neutral}"
    else
        echo -e "${green}ufw removed successfully${neutral}"
    fi
else
    echo -e "${green}ufw is not installed, skipping...${neutral}"
fi

if dpkg -s firewalld >/dev/null 2>&1; then
    if ! apt remove --purge -y firewalld; then
        echo -e "${red}Failed to remove firewalld${neutral}"
    else
        echo -e "${green}firewalld removed successfully${neutral}"
    fi
else
    echo -e "${green}firewalld is not installed, skipping...${neutral}"
fi

# Configure iptables-persistent and keyboard
if ! echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections; then
    echo -e "${red}Failed to configure iptables-persistent v4${neutral}"
fi

if ! echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections; then
    echo -e "${red}Failed to configure iptables-persistent v6${neutral}"
fi

if ! debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"; then
    echo -e "${red}Failed to configure keyboard layout${neutral}"
fi

if ! debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"; then
    echo -e "${red}Failed to configure keyboard variant${neutral}"
fi

# Update and upgrade system
export DEBIAN_FRONTEND=noninteractive
if ! apt update -y; then
    echo -e "${red}Failed to update${neutral}"
fi

if ! apt-get upgrade -y; then
    echo -e "${red}Failed to upgrade${neutral}"
else
    echo -e "${green}System upgraded successfully${neutral}"
fi

if ! apt dist-upgrade -y; then
    echo -e "${red}Failed to dist-upgrade${neutral}"
else
    echo -e "${green}System dist-upgraded successfully${neutral}"
fi

# Install additional packages
packages=(
    libnss3-dev liblzo2-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev
    libcap-ng-utils libselinux1-dev flex bison make libnss3-tools libevent-dev bc
    rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential
    gcc g++ htop lsof tar wget curl ruby zip unzip p7zip-full libc6 util-linux
    ca-certificates iptables iptables-persistent netfilter-persistent
    net-tools openssl gnupg gnupg2 lsb-release shc cmake git whois
    screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq
    tmux python3 python3-pip lsb-release gawk
    libncursesw5-dev libgdbm-dev tk-dev libffi-dev libbz2-dev checkinstall
    openvpn easy-rsa dropbear
)

for package in "${packages[@]}"; do
    if ! dpkg -s "$package" >/dev/null 2>&1; then
        if ! apt-get update -y; then
            echo -e "${red}Failed to update${neutral}"
        fi

        if ! apt-get install -y "$package"; then
            echo -e "${red}Failed to install $package${neutral}"
        fi
    else
        echo -e "${green}$package is already installed, skipping...${neutral}"
    fi
done

if [ -n "$city" ]; then
    if [ -f /etc/xray/city ]; then
        rm /etc/xray/city
    fi
    echo "$city" >>/etc/xray/city
else
    if [ -f /etc/xray/city ]; then
        rm /etc/xray/city
    fi
    echo "City information not available" >>/etc/xray/city
fi

if [ -n "$isp" ]; then
    if [ -f /etc/xray/isp ]; then
        rm /etc/xray/isp
    fi
    echo "$isp" >>/etc/xray/isp
else
    if [ -f /etc/xray/isp ]; then
        rm /etc/xray/isp
    fi
    echo "ISP information not available" >>/etc/xray/isp
fi
# Install Node.js
if ! dpkg -s nodejs >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - || echo -e "${red}Failed to download Node.js setup${neutral}"
    apt-get install -y nodejs || echo -e "${red}Failed to install Node.js${neutral}"
    npm install -g npm@latest
else
    echo -e "${green}Node.js is already installed, skipping...${neutral}"
fi

# Install and configure vnstat
if ! dpkg -s vnstat; then
    apt-get install -y vnstat || echo -e "${red}Failed to install vnstat${neutral}"
    wget -q https://humdi.net/vnstat/vnstat-2.9.tar.gz
    tar zxvf vnstat-2.9.tar.gz || echo -e "${red}Failed to extract vnstat${neutral}"
    cd vnstat-2.9 || echo -e "${red}Failed to enter vnstat-2.9 directory${neutral}"
    ./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
    cd || echo -e "${red}Failed to return to home directory${neutral}"

    net=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    vnstat -i $net
    if grep -q 'Interface "eth0"' /etc/vnstat.conf; then
        sed -i 's/Interface "'""eth0""'"/Interface "'""$net""'"/g' /etc/vnstat.conf
    else
        echo -e "Interface eth0 not found in /etc/vnstat.conf"
    fi
    chown vnstat:vnstat /var/lib/vnstat -R || echo -e "${red}Failed to change ownership of vnstat directory${neutral}"
    systemctl enable vnstat
    /etc/init.d/vnstat restart
else
    echo -e "${green}vnstat is already installed, skipping...${neutral}"
fi

# Clean up vnstat installation files
rm -f /root/vnstat-2.9.tar.gz >/dev/null 2>&1 || echo -e "${red}Failed to delete vnstat-2.6.tar.gz file${neutral}"
rm -rf /root/vnstat-2.9 >/dev/null 2>&1 || echo -e "${red}Failed to delete vnstat-2.6 directory${neutral}"

# Set timezone to Asia/Jakarta
ln -fs /usr/share/zoneinfo/$timezone /etc/localtime

# Additional configuration based on OS
os_id=$(grep -w ID /etc/os-release | head -n1 | sed 's/ID=//g' | sed 's/"//g')
if [[ $os_id == "ubuntu" ]]; then
    # Configuration for Ubuntu
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"

    if ! dpkg -s software-properties-common >/dev/null 2>&1; then
        apt-get install --no-install-recommends software-properties-common || echo -e "${red}Failed to install software-properties-common${neutral}"
    else
        echo -e "${green}software-properties-common is already installed, skipping...${neutral}"
    fi

    rm -f /etc/apt/sources.list.d/nginx.list || echo -e "${red}Failed to delete nginx.list${neutral}"

    if ! dpkg -s ubuntu-keyring >/dev/null 2>&1; then
        apt install -y ubuntu-keyring || echo -e "${red}Failed to install ubuntu-keyring${neutral}"
    else
        echo -e "${green}ubuntu-keyring is already installed, skipping...${neutral}"
    fi

    curl $nginx_key_url | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx

    if ! dpkg -s nginx >/dev/null 2>&1; then
        if ! apt install -y nginx; then
            echo -e "${red}Failed to install nginx${neutral}"
        fi
    else
        echo -e "${green}nginx is already installed, skipping...${neutral}"
    fi

    if [ -f /etc/nginx/conf.d/default.conf ]; then
        rm /etc/nginx/conf.d/default.conf || echo -e "${red}Failed to delete /etc/nginx/conf.d/default.conf${neutral}"
    else
        echo -e "${yellow}/etc/nginx/conf.d/default.conf does not exist, skipping deletion${neutral}"
    fi

elif [[ $os_id == "debian" ]]; then
    # Configuration for Debian haproxy-2.6

    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"

    rm -f /etc/apt/sources.list.d/nginx.list || echo -e "${red}Failed to delete nginx.list${neutral}"

    if ! dpkg -s debian-archive-keyring >/dev/null 2>&1; then
        apt install -y debian-archive-keyring || echo -e "${red}Failed to install debian-archive-keyring${neutral}"
    else
        echo -e "${green}debian-archive-keyring is already installed, skipping...${neutral}"
    fi

    curl $nginx_key_url | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | tee /etc/apt/preferences.d/99nginx

    if ! dpkg -s nginx >/dev/null 2>&1; then
        apt install -y nginx || echo -e "${red}Failed to install nginx${neutral}"
    else
        echo -e "${green}nginx is already installed, skipping...${neutral}"
    fi

else
    # If OS is not supported
    echo -e "${red}Unsupported OS. Exiting.${neutral}"
    exit 1
fi

if [[ $os_id == "ubuntu" && $os_version == "18.04" ]]; then
    add-apt-repository -y ppa:vbernat/haproxy-2.6 || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=2.6.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "ubuntu" && $os_version == "20.04" ]]; then
    add-apt-repository -y ppa:vbernat/haproxy-2.9 || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=2.9.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "ubuntu" && $os_version == "22.04" ]]; then
    add-apt-repository -y ppa:vbernat/haproxy-3.0 || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "ubuntu" && $os_version == "24.04" ]]; then
    add-apt-repository -y ppa:vbernat/haproxy-3.0 || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "debian" && $os_version == "10" ]]; then
    curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-2.6 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=2.6.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "debian" && $os_version == "11" ]]; then
    curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net bullseye-backports-3.0 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"

elif [[ $os_id == "debian" && $os_version == "12" ]]; then
    curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || echo -e "${red}Failed to add haproxy repository${neutral}"
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net bookworm-backports-3.0 main >/etc/apt/sources.list.d/haproxy.list || echo -e "${red}Failed to add haproxy repository${neutral}"
    sudo apt update -y || echo -e "${red}Failed to update package list${neutral}"
    apt-get install -y haproxy=3.0.\* || echo -e "${red}Failed to install haproxy${neutral}"

else
    echo -e "${red}Unsupported OS. Exiting.${neutral}"
    exit 1
fi

# Download and install configuration
if [ -n "$file_dir" ]; then
    wget $file_dir -O /tmp/src.zip >/dev/null 2>&1 || echo -e "${red}Failed to download src.zip${neutral}"
    unzip -o /tmp/src.zip -d /tmp/src >/dev/null 2>&1 || echo -e "${red}Failed to extract src.zip${neutral}"
    chmod +x /tmp/src/* >/dev/null 2>&1 || echo -e "${red}Failed to give execute permission to files in /tmp/src${neutral}"
    cp -r /tmp/src/* /usr/bin/ >/dev/null 2>&1 || echo -e "${red}Failed to copy files to /usr/bin${neutral}"
else
    echo -e "${yellow}file_dir is not set, skipping download of src.zip${neutral}"
fi

if [ -n "$dropbear_conf_url" ]; then
    [ -f /etc/default/dropbear ] && rm /etc/default/dropbear
    wget -q -O /etc/default/dropbear $dropbear_conf_url >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear.conf${neutral}"
    
    [ -f /etc/init.d/dropbear ] && rm /etc/init.d/dropbear
    wget -q -O /etc/init.d/dropbear $dropbear_init_url && chmod +x /etc/init.d/dropbear >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear.init${neutral}"
    
    [ -f /etc/dropbear/dropbear_dss_host_key ] && rm /etc/dropbear/dropbear_dss_host_key
    wget -q -O /etc/dropbear/dropbear_dss_host_key $dropbear_dss_url && chmod +x /etc/dropbear/dropbear_dss_host_key >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear_dss_host_key${neutral}"
else
    echo -e "${yellow}dropbear_conf_url is not set, skipping download of dropbear_dss_host_key${neutral}"
fi

if [ -n "$sshd_conf_url" ]; then
    [ -f /etc/ssh/sshd_config ] && rm /etc/ssh/sshd_config
    wget -q -O /etc/ssh/sshd_config $sshd_conf_url >/dev/null 2>&1 || echo -e "${red}Failed to download sshd_config${neutral}"
else
    echo -e "${yellow}sshd_conf_url is not set, skipping download of sshd_config${neutral}"
fi

if [ -n "$banner_url" ]; then
    wget -q -O /etc/fightertunnel.txt $banner_url && chmod +x /etc/fightertunnel.txt >/dev/null 2>&1 || echo -e "${red}Failed to download fightertunnel.txt${neutral}"
else
    echo -e "${yellow}banner_url is not set, skipping download of fightertunnel.txt${neutral}"
fi

if [ -n "$common_password_url" ]; then
    [ -f /etc/pam.d/common-password ] && rm /etc/pam.d/common-password
    wget -O /etc/pam.d/common-password $common_password_url >/dev/null 2>&1 || echo -e "${red}Failed to download common-password${neutral}"
else
    echo -e "${yellow}common_password_url is not set, skipping download of common-password${neutral}"
fi

if [ -n "$ws_py_url" ]; then
    wget -O /usr/bin/ws.py "$ws_py_url" >/dev/null 2>&1 && chmod +x /usr/bin/ws.py || echo -e "${red}Failed to download ws.py${neutral}"
else
    echo -e "${yellow}ws_py_url is not set, skipping download of ws.py${neutral}"
fi

if [ ! -d "$slowdns_dir" ]; then
    mkdir -p $slowdns_dir || echo -e "${red}Failed to create directory $slowdns_dir${neutral}"
fi

if [ -n "$dnstt_server_url" ]; then
    wget -O /etc/slowdns/dnstt-server $dnstt_server_url >/dev/null 2>&1 && chmod +x /etc/slowdns/dnstt-server || echo -e "${red}Failed to download or give execute permission to server${neutral}"
else
    echo -e "${yellow}dnstt_server_url is not set, skipping download of server${neutral}"
fi

if [ -n "$dnstt_client_url" ]; then
    wget -O /etc/slowdns/dnstt-client $dnstt_client_url >/dev/null 2>&1 && chmod +x /etc/slowdns/dnstt-client || echo -e "${red}Failed to download or give execute permission to client${neutral}"
else
    echo -e "${yellow}dnstt_client_url is not set, skipping download of client${neutral}"
fi

if [ -f /etc/slowdns/dnstt-server ]; then
    /etc/slowdns/dnstt-server -gen-key -privkey-file /etc/slowdns/server.key -pubkey-file /etc/slowdns/server.pub || echo -e "${red}Failed to generate keys for server${neutral}"
else
    echo -e "${red}server not found, skipping key generation${neutral}"
fi

if [ -f /etc/pam.d/common-password ]; then
    chmod +x /etc/pam.d/common-password || echo -e "${red}Failed to give execute permission to common-password${neutral}"
else
    echo -e "${yellow}/etc/pam.d/common-password not found, skipping permission change${neutral}"
fi

if curl -s $gotop_url | bash; then
    chmod +x gotop && sudo mv gotop /usr/local/bin/ || echo -e "${red}Failed to give execute permission or move gotop${neutral}"
else
    echo -e "${red}Failed to download and execute gotop script${neutral}"
fi

if [ -f /etc/haproxy/haproxy.cfg ]; then
    rm /etc/haproxy/haproxy.cfg
    echo -e "${yellow}Existing haproxy.cfg removed${neutral}"
fi

if dpkg -s apache2 >/dev/null 2>&1; then
    apt-get remove --purge apache2 -y
    echo -e "${yellow}Apache has been removed${neutral}"
else
    echo -e "${green}Apache is not installed, skipping removal${neutral}"
fi

if wget -O /etc/haproxy/haproxy.cfg $haproxy_cfg_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded haproxy.cfg${neutral}"
else
    echo -e "${red}Failed to download haproxy.cfg${neutral}"
fi

if wget -O /etc/nginx/conf.d/xray.conf $xray_conf_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded xray.conf${neutral}"
else
    echo -e "${red}Failed to download xray.conf${neutral}"
fi

if wget -O /etc/xray/vmess/config.json $vmess_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded vmess${neutral}"
else
    echo -e "${red}Failed to download vmess${neutral}"
fi

if wget -O /etc/xray/vless/config.json $vless_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded vless${neutral}"
else
    echo -e "${red}Failed to download vless${neutral}"
fi

if wget -O /etc/xray/trojan/config.json $trojan_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded trojan${neutral}"
else
    echo -e "${red}Failed to download trojan${neutral}"
fi

if wget -O /etc/xray/shadowsocks/config.json $shadowsocks_url >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded shadowsocks${neutral}"
else
    echo -e "${red}Failed to download shadowsocks${neutral}"
fi

if wget -O /usr/bin/udp $udp_url >/dev/null 2>&1 && chmod +x /usr/bin/udp >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded udp-custom-linux-amd64${neutral}"
else
    echo -e "${red}Failed to download udp-custom-linux-amd64${neutral}"
fi

if wget -O /etc/nginx/nginx.conf $nginx_conf_url >/dev/null 2>&1 && chmod +x /etc/nginx/nginx.conf >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded nginx.conf${neutral}"
else
    echo -e "${red}Failed to download nginx.conf${neutral}"
fi

if wget -O /usr/bin/badvpn "$badvpn_url" >/dev/null 2>&1 && chmod +x /usr/bin/badvpn >/dev/null 2>&1; then
    echo -e "${green}Successfully downloaded badvpn${neutral}"
else
    echo -e "${red}Failed to download badvpn${neutral}"
fi

if [[ "$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')" != "bbr" ]]; then
    bash -c "$(curl -L $bbr_url)"
else
    echo -e "${green}BBR is already installed, skipping installation${neutral}"
fi

# Replace $interface with the appropriate network interface name, e.g., eth0
interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# Adding iptables rules
if iptables -t nat -A PREROUTING -i $interface -p udp -m udp --dport 53 -j REDIRECT --to-ports 5300; then
    iptables-save >/etc/iptables/rules.v4
else
    echo -e "${red}Failed to add PREROUTING iptables rule${neutral}"
fi

if iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE; then
    iptables-save >/etc/iptables/rules.v4
else
    echo -e "${red}Failed to add POSTROUTING iptables rule untuk 10.8.0.0/24${neutral}"
fi

if iptables -t nat -A POSTROUTING -s 20.8.0.0/24 -o $interface -j MASQUERADE; then
    iptables-save >/etc/iptables/rules.v4
else
    echo -e "${red}Failed to add POSTROUTING iptables rule untuk 20.8.0.0/24${neutral}"
fi

if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >>/etc/sysctl.conf
    fi
else
    echo -e "${green}net.ipv4.ip_forward=1 is already in /etc/sysctl.conf, skipping...${neutral}"
fi
sysctl -p

# Saving iptables rules
if iptables-save >/etc/iptables/rules.v4; then
    echo -e "${green}Successfully saved iptables rules${neutral}"
else
    echo -e "${red}Failed to save iptables rules${neutral}"
fi

# Install Xray
if ! command -v xray >/dev/null 2>&1; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.23
else
    echo -e "${green}Xray is already installed, skipping installation${neutral}"
fi

if [ ! -d "/root/.acme.sh" ]; then
    mkdir /root/.acme.sh
fi

systemctl daemon-reload
systemctl stop haproxy
systemctl stop nginx

domain=$(cat /etc/xray/domain)

#detail nama perusahaan
country="ID"
state="West Sumatera"
locality="Kab. 50 Kota"
organization="XSM"
organizationalunit="99999"
commonname="XSM"
email="decodez60@gmail.com"

# delete
systemctl stop nginx haproxy
rm -fr /etc/xray/xray.crt
rm -fr /etc/xray/xray.key

# make a certificate
openssl genrsa -out /etc/xray/xray.key 2048
openssl req -new -x509 -key /etc/xray/xray.key -out /etc/xray/xray.crt -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat /etc/xray/xray.key /etc/xray/xray.crt | tee /etc/haproxy/yha.pem
chmod 644 /etc/xray/*
systemctl restart nginx haproxy

#rm -rf /root/.acme.sh
#mkdir /root/.acme.sh
#systemctl stop haproxy
#curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
#chmod +x /root/.acme.sh/acme.sh
#/root/.acme.sh/acme.sh --upgrade --auto-upgrade
#/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
#/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
#~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
#cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/yha.pem
#chown www-data.www-data /etc/xray/xray.key
#chown www-data.www-data /etc/xray/xray.crt

sub=$(tr </dev/urandom -dc a-z0-9 | head -c7)
sub_domain="$sub.$domain_ns"
ns_domain="$sub_domain"
set -euo pipefail

zone=$(
    curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${domain_ns}&status=active" \
        -H "X-Auth-Email: ${cf_id}" \
        -H "X-Auth-Key: ${cf_key}" \
        -H "Content-Type: application/json" | jq -r .result[0].id
)

record=$(
    curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${zone}/dns_records?name=${ns_domain}" \
        -H "X-Auth-Email: ${cf_id}" \
        -H "X-Auth-Key: ${cf_key}" \
        -H "Content-Type: application/json" | jq -r .result[0].id
)

if [[ "${#record}" -le 10 ]]; then
    record=$(
        curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${zone}/dns_records" \
            -H "X-Auth-Email: ${cf_id}" \
            -H "X-Auth-Key: ${cf_key}" \
            -H "Content-Type: application/json" \
            --data '{"type":"NS","name":"'${ns_domain}'","content":"'${domain}'","proxied":false}' | jq -r .result.id
    )
fi

result=$(
    curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${zone}/dns_records/${record}" \
        -H "X-Auth-Email: ${cf_id}" \
        -H "X-Auth-Key: ${cf_key}" \
        -H "Content-Type: application/json" \
        --data '{"type":"NS","name":"'${ns_domain}'","content":"'${domain}'","proxied":false}'
)
echo $ns_domain >/etc/xray/dns
# Install OpenVPN
mkdir -p /usr/lib/openvpn/ || echo -e "${red}Failed to create directory /usr/lib/openvpn/${neutral}"

# Exception if the directory already exists
if [ -d "/etc/openvpn/" ]; then
    echo -e "${green}Directory /etc/openvpn/ already exists, continuing...${neutral}"
else
    mkdir -p /usr/lib/openvpn/ || echo -e "${red}Failed to create directory /usr/lib/openvpn/${neutral}"
fi

if wget -O /etc/openvpn/openvpn.zip $openvpn_url >/dev/null 2>&1; then
    if unzip -d /etc/openvpn/ /etc/openvpn/openvpn.zip >/dev/null 2>&1; then
        echo -e "${green}Successfully downloaded and extracted openvpn.zip${neutral}"
        rm -f /etc/openvpn/openvpn.zip
    else
        echo -e "${red}Failed to extract openvpn.zip${neutral}"
    fi
else
    echo -e "${red}Failed to download openvpn.zip${neutral}"
fi

cat >/etc/openvpn/client-tcp.ovpn <<-EOF
auth-user-pass
client
dev tun
proto tcp
remote $ip 1194
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
auth none
EOF

cat >/etc/openvpn/client-udp.ovpn <<-EOF
auth-user-pass
client
dev tun
proto udp
remote $ip 2200
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
auth none
EOF

cat >/etc/openvpn/client-ssl.ovpn <<-EOF
auth-user-pass
client
dev tun
proto tcp
remote $ip 443
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
auth none
EOF

function input_cert_ovpn() {
    for config in client-tcp client-udp client-ssl; do
        echo '<ca>' >>/etc/openvpn/${config}.ovpn
        cat /etc/openvpn/ca.crt >>/etc/openvpn/${config}.ovpn
        echo '</ca>' >>/etc/openvpn/${config}.ovpn
        cp /etc/openvpn/${config}.ovpn /var/www/html/${config}.ovpn
    done

    cd /var/www/html/
    zip allovpn.zip client-tcp.ovpn client-udp.ovpn client-ssl.ovpn >/dev/null 2>&1
    sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
    cd
}

input_cert_ovpn

# Create a zip file for all client configurations
if ! zip -j /var/www/html/allovpn.zip /var/www/html/*.ovpn; then
    echo "Failed to create zip file for all client configurations."
fi

# Enable autostart for OpenVPN
if ! sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn; then
    echo "Failed to enable autostart for OpenVPN."
fi

# Buat file konfigurasi untuk server
cat >/usr/bin/config.json <<EOF
{
  "listen": ":2100",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF

# Buat cron job untuk menjalankan /usr/bin/xp setiap hari pada pukul 02:00
cat >/etc/cron.d/xp_all <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/exp
EOF

# Create .profile file for root user
cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
ft dashboard
EOF
chmod 644 /root/.profile

cat >/root/.bashrc <<EOF
# ~/.bashrc: executed by bash(1) for non-login shells.
cat /dev/null > ~/.bash_history && history -c
EOF
chmod 644 /root/.bashrc

# Menambahkan /bin/false ke /etc/shells
cat >/etc/shells <<EOF
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/screen
/usr/bin/tmux
/bin/false
/usr/sbin/nologin
EOF
chmod +x /etc/shells
# Clear command history or other cmd files
cat /dev/null >~/.bash_history && history -c

# Create a cron job to reboot the system every day at 05:00
cat >/etc/cron.d/daily_reboot <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
EOF

cat >/etc/cron.d/logclear <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */6 * * * root /usr/bin/logclear
EOF
# Restart cron service
service cron restart

# Save daily reboot time in /home/daily_reboot file
cat >/home/daily_reboot <<EOF
5
EOF
capabilities="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
limits="LimitNPROC=10000
LimitNOFILE=1000000"
restart="Restart=on-failure
RestartPreventExitStatus=23"
wanted_by="WantedBy=multi-user.target"
after="After=network.target nss-lookup.target"
documentation="Documentation=https://t.me/fightertunnell"

# Function to create service
create_service() {
    local name=$1
    local description=$2
    local exec_start=$3

    cat >/etc/systemd/system/${name}@config.service <<EOF
[Unit]
Description=${description} %i
${documentation}
${after}

[Service]
User=www-data
CapabilityBoundingSet=${capabilities}
AmbientCapabilities=${capabilities}
NoNewPrivileges=yes
ExecStart=${exec_start}
${restart}
${limits}

[Install]
${wanted_by}
EOF
}

# Create services for vmess, vless, trojan, and shadowsocks
create_service "vmess" "FighterTunnel Server Xray Instance" "/usr/local/bin/xray run -config /etc/xray/vmess/%i.json"
create_service "vless" "FighterTunnel Server Xray Instance" "/usr/local/bin/xray run -config /etc/xray/vless/%i.json"
create_service "trojan" "FighterTunnel Server Xray Instance" "/usr/local/bin/xray run -config /etc/xray/trojan/%i.json"
create_service "shadowsocks" "FighterTunnel Server Shadowsocks Instance" "/usr/local/bin/xray run -config /etc/xray/shadowsocks/%i.json"

# Create additional configuration file for xray
cat >/etc/systemd/system/xray@.service.d/10-donot_touch_single_conf.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/xray run -config /etc/xray/%i.json
EOF

# Reload daemon, disable and stop xray dropbear
sudo systemctl daemon-reload
sudo systemctl stop xray
sudo systemctl disable xray

sudo systemctl disable dropbear
sudo systemctl stop dropbear
rm -rf /lib/systemd/system/dropbear.service

sudo systemctl daemon-reload
/etc/init.d/dropbear start
/etc/init.d/dropbear restart
# Create ws service
cat >/etc/systemd/system/ws.service <<EOF
[Unit]
Description=Python Proxy FighterTunnel
Documentation=https://t.me/yha_bot
${after}

[Service]
Type=simple
User=root
CapabilityBoundingSet=${capabilities}
AmbientCapabilities=${capabilities}
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O /usr/bin/ws.py
${restart}

[Install]
${wanted_by}
EOF

# Create udp service
cat >/etc/systemd/system/udp.service <<EOF
[Unit]
Description=ePro Udp-Custom VPN Server By HC
After=network.target

[Service]
User=root
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/udp server -exclude 2200,7300,7200,7100,323,10008,10004 /usr/bin/config.json
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
${limits}
${restart}

[Install]
${wanted_by}
EOF

# Create limit ip service
cat >/etc/systemd/system/limitip.service <<EOF
[Unit]
Description=Limit IP Usage Xray Service
Documentation=https://t.me/yha_bot
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/bin/bash -c '/usr/bin/limitipssh 15 & /usr/bin/limitip 15 & wait'
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Create limit quota service
cat >/etc/systemd/system/limitquota.service <<EOF
[Unit]
Description=Limit Quota Usage Xray Service
Documentation=https://t.me/yha_bot
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/quota
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Create BadVPN service
cat >/etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Service
Documentation=https://t.me/bhoikfost_yahya
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/bin/badvpn --listen-addr 127.0.0.1:7100 --listen-addr 127.0.0.1:7200 --listen-addr 127.0.0.1:7300 --max-clients 500
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# Create slowdns service
cat >/etc/systemd/system/dnstt-server.service <<EOF
[Unit]
Description=Server SlowDNS
Documentation=https://t.me/bhoikfost_yahya
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/dnstt-server -udp 0.0.0.0:5300 -privkey-file /etc/slowdns/server.key xxxx 127.0.0.1:443
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/dnstt-client.service <<EOF
[Unit]
Description=Client SlowDNS
Documentation=https://t.me/bhoikfost_yahya
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/slowdns/dnstt-client -doh https://cloudflare-dns.com/dns-query --pubkey-file /etc/slowdns/server.pub xxxx 127.0.0.1:88
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

sed -i "s/xxxx/$ns_domain/g" /etc/systemd/system/dnstt-client.service
sed -i "s/xxxx/$ns_domain/g" /etc/systemd/system/dnstt-server.service

if [ -f /root/.key ]; then
    rm -f /root/.key
fi
echo "$key" >>/root/.key

uuid_baru=$(cat /proc/sys/kernel/random/uuid)
for config in vmess vless trojan shadowsocks; do
    sudo sed -i "s/1d1c1d94-6987-4658-a4dc-8821a30fe7e0/$uuid_baru/g" /etc/xray/$config/config.json
done
npm i --prefix /usr/bin express express-fileupload

setup_bot() {
    # Membuat direktori .bot jika belum ada /root/bot"
    if [ ! -d "/root/.bot" ]; then
        mkdir -p /root/.bot
    fi

    # Memeriksa dan menginstal dependensi npm jika belum terinstal
    if ! npm list --prefix /root/.bot express telegraf axios moment sqlite3 >/dev/null 2>&1; then
        npm install --prefix /root/.bot express telegraf axios moment sqlite3
    fi

    # Mengunduh bot.zip jika app.js belum ada
    if [ ! -f /root/.bot/app.js ]; then
        wget -q -O /root/.bot/bot.zip https://raw.githubusercontent.com/xsm-syn/reinstall/main/bot.zip
        unzip -o /root/.bot/bot.zip -d /root/.bot >/dev/null 2>&1
        rm /root/.bot/bot.zip >/dev/null 2>&1
    fi

    # Memberikan izin eksekusi pada semua file di dalam direktori .bot
    if [ -n "$(ls -A /root/.bot)" ]; then
        chmod +x /root/.bot/*
    fi
}

setup_bot
# Adding swap RAM
swap_file="/swapfile"
swap_size="5G" # Swap size, can be adjusted as needed 

# Creating swap file
if [ ! -f "$swap_file" ]; then
    fallocate -l $swap_size $swap_file
    chmod 600 $swap_file
    mkswap $swap_file
    swapon $swap_file
    echo "$swap_file swap swap defaults 0 0" >> /etc/fstab
    echo -e "${green}Swap RAM successfully added with size $swap_size${neutral}"
else
    echo -e "${yellow}Swap file already exists, skipping swap RAM addition${neutral}"
fi
# Enable and start services
sudo systemctl daemon-reload

services=(
    "vmess@config.service"
    "vless@config.service"
    "trojan@config.service"
    "shadowsocks@config.service"
    "haproxy.service"
    "ws.service"
    "udp.service"
    "limitip.service"
    "limitquota.service"
    "badvpn.service"
    "nginx.service"
    "dnstt-server.service"
    "dnstt-client.service"
    "ssh.service"
    "dropbear.service"
)

for service in "${services[@]}"; do
    sudo systemctl enable $service
    sudo systemctl start $service
    sudo systemctl restart $service
    echo -ne "Restarting $service...\r"
    sleep 1
    echo -ne "Restarting $service...$green Done! $neutral\n"
done
sudo systemctl restart netfilter-persistent
if [ -d "/root/ub20" ]; then
    rm -rf /root/ub20
else
    echo ""
fi
clear
print_rainbow "───────────────────────────────────────"
echo -e "${green}         INSTALLASI SELESAI            ${neutral}"
print_rainbow "───────────────────────────────────────"
echo -e "${green}  Selamat! Proses instalasi selesai${neutral}"
echo -e "${green}Silakan reboot server Anda dengan 'enter'.${neutral}"
print_rainbow "───────────────────────────────────────"
read -p "Tekan enter untuk reboot server..."
reboot
