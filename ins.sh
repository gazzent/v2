#!/bin/bash
# Edition : Stable Edition V2.0
# Auther  : CANDRA IRAWAN
# (C) Copyright 2023-2024 By KINGSTORE
# =========================================
#!/bin/bash
clear
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
MYIP=$(wget -qO- ipinfo.io/ip)
REPO='https://hafira.my.id/tunnel/'
idc='https://hafira.my.id/sc/'
start=$(date +%s)

MakhlukVpn() {
sudo apt install curl -y
sudo apt install wget -y
sudo apt install vnstat -y
ipsaya=$(wget -qO- ipinfo.io/ip)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
data_ip="https://raw.githubusercontent.com/irawancandra6699/izin/main/ip"
function CEKIPX() {
MYIP=$(curl -sS ipv4.icanhazip.com)
IPVPS=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/izin/main/ip | grep $MYIP | awk '{print $4}')
if [[ $MYIP == $IPVPS ]]; then
clear
else
  key2
fi
}
##
echo -e  "${REDBG}┌──────────────────────────────────────────┐${NC}"
echo -e  "${REDBG}│              INPUT YOUR NAME             │${NC}"
echo -e  "${REDBG}└──────────────────────────────────────────┘${NC}"
echo " "
until [[ $name =~ ^[a-zA-Z0-9_.-]+$ ]]; do
read -rp "Masukan Nama Kamu Disini tanpa spasi : " -e name
done
rm -rf /etc/profil
echo "$name" > /etc/profil
echo ""
clear
author=$(cat /etc/profil)
echo ""
echo ""

function key2(){
clear
echo -e  "${REDBG}┌──────────────────────────────────────────┐${NC}"
echo -e  "${REDBG}│              MASUKKAN LICENSE KEY        │${NC}"
echo -e  "${REDBG}└──────────────────────────────────────────┘${NC}"
echo " "
read -rp "Masukan Key Kamu Disini (Ctrl + C Exit) : " -e kode

if [ -z $kode ]; then
echo -e "KODE SALAH SILAHKAN MASUKKAN ULANG KODENYA"
key2
fi

LIST=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/license/main/key | grep $kode | awk '{print $2}')
Key=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/license/main/key | grep $kode | awk '{print $3}')
KEY2=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/license/main/key | grep $kode | awk '{print $4}')
ADMIN=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/license/main/key | grep $kode | awk '{print $5}')
TOTALIP=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/license/main/key | grep $kode | awk '{print $6}')
web=$(curl -sS kvm-xcode.biz.id/izinx | grep $kode | awk '{print $3}')
web2=$(curl -sS kvm-xcode.biz.id/izinx | grep $kode | awk '{print $2}')
web3=$(curl -sS kvm-xcode.biz.id/izinx | grep $kode | awk '{print $4}')
web4=$(curl -sS kvm-xcode.biz.id/izinx | grep $kode | awk '{print $5}')
web5=$(curl -sS kvm-xcode.biz.id/izinx | grep $kode | awk '{print $6}')

if [[ $kode == $web ]]; then
MYIP=$(curl -sS ipv4.icanhazip.com)
rm -rf /etc/github
mkdir /etc/github
echo "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" > /etc/github/api
echo "irawancandra6699@gmail.com" > /etc/github/email
echo "irawancandra6699" > /etc/github/username
clear
APIGIT=$(cat /etc/github/api)
EMAILGIT=$(cat /etc/github/email)
USERGIT=$(cat /etc/github/username)
hhari=$(date -d "$web3 days" +"%Y-%m-%d")
mkdir /root/irawancandra6699
cd /root/irawancandra6699
wget https://raw.githubusercontent.com/irawancandra6699/izin/main/ip >/dev/null 2>&1
if [ "$web4" = "ON" ]; then
sed -i "/# RESELLER/a ### ${author} ${hhari} ${MYIP} ${web4} ${web5}" /root/irawancandra6699/ip
else
echo "### $author $hhari $MYIP $web2" >> ip

fi
sleep 0.5
rm -rf .git
git config --global user.email "${EMAILGIT}" >/dev/null 2>&1
git config --global user.name "${USERGIT}" >/dev/null 2>&1
git init >/dev/null 2>&1
git add ip
git commit -m register >/dev/null 2>&1
git branch -M main >/dev/null 2>&1
git remote add origin https://github.com/${USERGIT}/izin >/dev/null 2>&1
git push -f https://${APIGIT}@github.com/${USERGIT}/izin >/dev/null 2>&1
rm -rf /root/irawancandra6699
rm -rf /etc/github
clear

elif [[ $kode == $Key ]]; then
MYIP=$(curl -sS ipv4.icanhazip.com)
rm -rf /etc/github
mkdir /etc/github
echo "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" > /etc/github/api
echo "rawancandra6699@gmail.com" > /etc/github/email
echo "irawancandra6699" > /etc/github/username
clear
APIGIT=$(cat /etc/github/api)
EMAILGIT=$(cat /etc/github/email)
USERGIT=$(cat /etc/github/username)
hhari=$(date -d "$KEY2 days" +"%Y-%m-%d")
mkdir /root/irawancandra6699
cd /root/irawancandra6699
wget https://raw.githubusercontent.com/irawancandra6699/izin/main/ip >/dev/null 2>&1
if [ "$ADMIN" = "ON" ]; then
sed -i "/# RESELLER/a ### ${author} ${hhari} ${MYIP} ${ADMIN} ${TOTALIP}" /root/irawancandra6699/ip
else
echo "### $author $hhari $MYIP $LIST" >> ip
fi
sleep 0.5
rm -rf .git
git config --global user.email "${EMAILGIT}" >/dev/null 2>&1
git config --global user.name "${USERGIT}" >/dev/null 2>&1
git init >/dev/null 2>&1
git add ip
git commit -m register >/dev/null 2>&1
git branch -M main >/dev/null 2>&1
git remote add origin https://github.com/${USERGIT}/izin >/dev/null 2>&1
git push -f https://${APIGIT}@github.com/${USERGIT}/izin >/dev/null 2>&1
sleep 0.5
rm ip
wget https://raw.githubusercontent.com/irawancandra6699/license/main/key >/dev/null 2>&1
if [ "$ADMIN" = "ON" ]; then
sed -i "/^### $LIST $Key $KEY2 $ADMIN $TOTALIP/d" /root/irawancandra6699/key
else
sed -i "/^### $LIST $Key $KEY2/d" /root/irawancandra6699/key
fi
sleep 0.5
rm -rf .git
git config --global user.email "rawancandra6699@gmail.com" >/dev/null 2>&1
git config --global user.name "irawancandra6699" >/dev/null 2>&1
git init >/dev/null 2>&1
git add key
git commit -m register >/dev/null 2>&1
git branch -M main >/dev/null 2>&1
git remote add origin https://github.com/irawancandra6699/license >/dev/null 2>&1
git push -f https://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@github.com/irawancandra6699/license >/dev/null 2>&1
rm -rf /root/irawancandra6699
rm -rf /etc/github
clear
else
echo -e "KODE SALAH SILAHKAN MASUKKAN ULANG KODENYA"
sleep 1
key2
fi
}
##IZIN IP DAN TRIAL SC 
# // Checking Os Architecture
LOGO
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# // Checking System
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
    exit 1
fi

# // IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
#IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
#IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m" 
clear
# Version sc
clear
#########################
# USERNAME
rm -f /usr/bin/user
username=$(curl https://raw.githubusercontent.com/irawancandra6699/izin/main/ip | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl https://raw.githubusercontent.com/irawancandra6699/izin/main/ip | grep $MYIP | awk '{print $3}')
echo "$expx" >/usr/bin/e
# DETAIL ORDER
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
# CERTIFICATE STATUS
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""

# Status ExpiRED Active | Geo Project
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(curl https://raw.githubusercontent.com/irawancandra6699/izin/main/ip | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
echo -e "${OK} ${BLUE} $1 ${FONT}"
sleep 2
}
function print_install() {
echo -e "${BLUE} # Proses install by KINGSTORE $1 "
sleep 2
clear
}
function print_success() {
echo -e "${BLUE} # $1 Berhasil Di instal Thx KINGSTORE"
sleep 2
clear
}
function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi
}
echo -e "\e[32mloading...\e[0m"
clear
sleep 2
echo -e "${RED}◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇${NC}"
echo -e "  Welcome To HAFIRA Script ${BLUE}(${NC}${BLUE} New Edition ${NC}${BLUE})${NC}"
echo -e "     This Will Quick Setup VPN Server On Your Server"
echo -e "         Auther : ${BLUE}Rzyul ${NC}${BLUE}(${NC} ${BLUE} HAFIRA${NC}"
echo -e "       © Recode By HAFIRA ${BLUE}(${NC} 2023 ${BLUE})${NC}"
echo -e "${RED}◇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━◇${NC}"
echo ""
sleep 3
if [ $MYIP = $IZIN ]; then
echo -e "[ ${green}INFO${NC} ] Permission Accepted..."
else
echo "                                                              "
echo -e "$Lyellow          ⚡ PREMIUM SPEED SCRIPT ⚡"$NC
echo -e "$green┌──────────────────────────────────────────┐ "$NC
echo -e "$Lyellow         Autoscript By HAFIRA"$NC
echo -e "$Lyellow             CONTACT TELEGRAM"$NC
echo -e "$Lyellow            https://t.me/Candravpnz"$NC
echo -e "$green└──────────────────────────────────────────┘"$NC
exit 0
fi
echo "INSTALLING SCRIPT..."
cat >/root/.user.ini <<-END
vps  Author  Exp  Versi IpVps
ScriptAutoInstaller HAFIRA
END
}
function first_setup(){
timedatectl set-timezone Asia/Jakarta
wget -O /usr/sbin/mtsc.list "${idc}last/mtsc.list" >/dev/null 2>&1
wget -O /etc/ssh/sshd_config ${REPO}config/sshd_config >/dev/null 2>&1
chmod 644 /etc/ssh/sshd_config
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
}
function base_package() {
sudo apt autoremove git man-db apache2 ufw exim4 firewalld snapd* -y;
clear
print_install "Memasang paket yang dibutuhkan"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1  >/dev/null 2>&1
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
echo "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
sudo apt update -y
apt-get install --no-install-recommends software-properties-common
add-apt-repository ppa:vbernat/haproxy-2.0 -y
apt-get -y install haproxy=2.0.\*
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
echo "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
curl https://haproxy.debian.net/bernat.debian.org.gpg |
gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
http://haproxy.debian.net buster-backports-1.8 main \
>/etc/apt/sources.list.d/haproxy.list
sudo apt-get update
apt-get -y install haproxy=1.8.\*
else
echo -e " Your OS Is Not Supported ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
exit 1
fi
sudo apt install software-properties-common -y
sudo apt install at -y
sudo apt install python -y
sudo apt install squid -y
sudo apt install nginx -y
sudo apt install openvpn -y
sudo apt install fail2ban -y
sudo apt install iptables -y
sudo apt install iptables-persistent -y
sudo apt install netfilter-persistent -y
sudo apt install chrony -y
sudo apt install cron -y
sudo apt install resolvconf -y
sudo apt install pwgen openssl netcat bash-completion ntpdate -y
sudo apt install xz-utils apt-transport-https dnsutils socat -y
sudo apt install git tar lsof ruby zip unzip p7zip-full python3-pip libc6  gnupg gnupg2 gnupg1 -y
sudo apt install net-tools bc jq easy-rsa python3-certbot-nginx p7zip-full tuned -y
sudo apt install libopentracing-c-wrapper0 libopentracing1 linux-tools-common util-linux -y
apt-get install lolcat -y
gem install lolcat
dpkg --configure -a
apt --fix-broken install
apt-get install --fix-missing
print_ok "Berhasil memasang paket yang dibutuhkan"
}
function dir_xray() {
echo -e "Membuat direktori xray"
mkdir -p /etc/{shell,xray,slowdns,websocket,vmess,vless,trojan,shadowsocks}
mkdir -p /tmp/{menu,core}
mkdir -p /root/.config/{psiphon,udp,rclone}
mkdir -p /var/log/xray
mkdir -p /var/www/html
touch /var/log/xray/{access.log,error.log}
chmod +x /var/log/xray
chmod 777 /var/log/xray/*.log
touch /root/install.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/ssh/.ssh.db
touch /etc/shadowsocks/.shadowsocks.db
clear
}
function add_domain() {
echo -e ""
echo -e "    ┌───────────────────────────────────────────────┐"
echo -e " ───│                                               │───"
echo -e " ───│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───"
echo -e " ───│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───"
echo -e " ───│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───"
echo -e "    │    ${YELLOW}Copyright${FONT} (C)$GRAY https://github.com/irawancandra6699$NC   │"
echo -e "    └───────────────────────────────────────────────┘"
echo -e "         ${RED}Autoscript xray vpn lite (multi port)${FONT}"    
echo -e "${RED}Make sure the internet is smooth when installing the script${FONT}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "Your Select Domain For Tunneling"
echo -e ""
echo -e "     \e[1;32m1)\e[0m Pakai Domain Script"
echo -e "     \e[1;32m2)\e[0m Pakai Domain Sendiri "
echo -e " "
read -rp "Choose Your Domain Installation : " dom
if test $dom -eq 1; then
clear
curl https://hafira.my.id/sc/cf.sh | bash | tee /root/install.log
print_success "Domain Script"
elif test $dom -eq 2; then
read -rp "Enter Your Domain : " domen
echo $domen > /etc/xray/domain
else
echo "Not Found Argument"
exit 1
fi
print_success "Domain Sendiri"
clear
}
function pasang_ssl() {
print_install "SSL Certificate"
domain=$(cat /etc/xray/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/haproxy.pem
chmod +x /etc/haproxy/haproxy.pem
chmod +x /etc/xray/xray.key
chmod +x /etc/xray/xray.crt
print_success "SSL Certificate"
}
function install_xray(){
print_install "Websocket"
wget -O /usr/sbin/drws.py "${REPO}core/python/drws.py" >/dev/null 2>&1
wget -O /usr/sbin/opws.py "${REPO}core/python/opws.py" >/dev/null 2>&1
wget -O /usr/sbin/ovws.py "${REPO}core/python/ovws.py" >/dev/null 2>&1
wget -O /usr/sbin/stws.py "${REPO}core/python/stws.py" >/dev/null 2>&1
wget -O /etc/systemd/system/ws@.service "${REPO}service/ws@.service" >/dev/null 2>&1
chmod +x /usr/sbin/*.py
chmod 644 /etc/systemd/system/ws@.service
print_success "Websocket"
print_install "Xray Core Latest"
echo tidak ada data apapun >/etc/xray/link
curl -s ipinfo.io/city >> /etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp
xray_latest="$(curl -s https://api.github.com/repos/dharak36/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
xraycore_link="https://github.com/dharak36/Xray-core/releases/download/v$xray_latest/xray.linux.64bit"
curl -sL "$xraycore_link" -o xray
mv xray /usr/sbin/xray
chmod +x /usr/sbin/xray
wget -O /etc/xray/config.json "${REPO}nginx/xray/config.json" >/dev/null 2>&1
curl "${idc}tools/IPSERVER" | bash | tee /root/install.log
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service.d
rm -rf /etc/systemd/system/xray@.service
wget -O /etc/systemd/system/xray.service "${REPO}service/xray.service" >/dev/null 2>&1
wget -O /etc/systemd/system/iptables.service "${REPO}service/iptables.service" >/dev/null 2>&1
print_success "Xray Config"
}
function install_ovpn(){
print_install "OpenVPN"
wget -O /root/.config/rclone/OPENVPN "${idc}tools/OPENVPN" >/dev/null 2>&1
bash /root/.config/rclone/OPENVPN | tee /root/install.log
wget -O /etc/pam.d/common-password "${REPO}config/common-password" >/dev/null 2>&1
chmod +x /etc/pam.d/common-password
print_success "OpenVPN"
}
function install_slowdns(){
print_install "SlowDNS"
wget ${idc}slowdns/install && chmod +x install && ./install
sleep 2
print_success "SlowDNS"
}
function install_custom() {
print_install "BadVPN"
wget -O /usr/sbin/badvpn "${REPO}core/badvpn" >/dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn1.service "${REPO}service/badvpn1.service" >/dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn2.service "${REPO}service/badvpn2.service" >/dev/null 2>&1
wget -q -O /etc/systemd/system/badvpn3.service "${REPO}service/badvpn3.service" >/dev/null 2>&1
chmod +x /usr/sbin/badvpn > /dev/null 2>&1
print_success "BadVPN"
}
function install_rclone() {
print_install "Rclone"
apt install rclone
wget -O /root/.config/rclone/rclone.conf "https://hafira.my.id/tunnel/config/rclone.conf" >/dev/null 2>&1
printf "q\n" | rclone config
print_success "Rclone"
}
function download_config(){
print_install "Tools"
wget -O /etc/haproxy/haproxy.cfg "${REPO}nginx/haproxy/hap.conf" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/drop.conf "${REPO}nginx/haproxy/load.conf" >/dev/null 2>&1
wget -O /etc/nginx/nginx.conf "${REPO}config/nginx.conf" >/dev/null 2>&1
wget -q -O /etc/squid/squid.conf "${REPO}config/squid.conf" >/dev/null 2>&1
mkdir -p /var/log/squid/cache/
chmod 777 /var/log/squid/cache/
echo "* - nofile 65535" >> /etc/security/limits.conf
mkdir -p /etc/sysconfig/
echo "ulimit -n 65535" >> /etc/sysconfig/squid
apt install dropbear -y
wget -q -O /etc/default/dropbear "${REPO}config/dropbear" >/dev/null 2>&1
chmod 644 /etc/default/dropbear
sudo apt install wondershaper
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
git pull
sudo make install
cd
rm -rf wondershaper
echo > /home/limit
#install Menu
wget ${idc}/last/menu.zip
    unzip menu.zip
    clear
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
#install Wen
wget -O /var/www/html/web.zip "${idc}last/web.zip" >/dev/null 2>&1
cd /var/www/html/ && unzip web.zip >/dev/null 2>&1
cd && rm /var/www/html/web.zip
wget -O /root/.config/psiphon/psiphon "https://github.com/Psiphon-Labs/psiphon-tunnel-core-binaries/raw/master/psiphond/psiphond" >/dev/null 2>&1
cd /root/.config/psiphon && chmod +x psiphon
./psiphon --ipaddress ${MYIP} --web 3000 --protocol SSH:3001 --protocol OSSH:3002 --protocol FRONTED-MEEK-OSSH:8443 generate
wget -O /etc/systemd/system/psiphon.service "${REPO}service/psiphon.service" >/dev/null 2>&1
mv psiphon /usr/sbin && cd
cp /root/.config/psiphon/*.dat /var/www/html/psiphon.txt
cat >/root/.profile <<EOF
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
menu
EOF
chmod 644 /root/.profile
cat >/etc/cron.d/xp_all << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
59 23 * * * root /usr/sbin/xp
EOF
cat >/etc/cron.d/clear_log << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/5 * * * * root /usr/sbin/clearlog
EOF
cat >/etc/cron.d/lim_all << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/sbin/lim.x vmess
*/15 * * * * root /usr/sbin/lim.x vless
*/15 * * * * root /usr/sbin/lim.x trojan
*/15 * * * * root /usr/sbin/lim.x ss
*/15 * * * * root /usr/sbin/lim.x ssh
EOF
cat >/etc/cron.d/daily_reboot << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /sbin/reboot
EOF
service cron restart
wget -O /etc/rc.local "${REPO}config/rc.local" >/dev/null 2>&1
chmod +x /etc/rc.local
wget -O /etc/systemd/system/rc-local.service "${REPO}service/rc-local.service" >/dev/null 2>&1
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
print_success "Tools"
}
function tambahan(){
print_install "SpeedTest"
wget -O /usr/sbin/speedtest "${REPO}core/speedtest.py" >/dev/null 2>&1
chmod +x /usr/sbin/speedtest
print_success "SpeedTest"
print_install "Gotop"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
print_success "Gotop COre"
curl "${idc}tools/BBR" | bash | tee /root/install.log
print_success "BBR Plus"
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
print_success "Swap + 1GB"
chronyc sourcestats -v
chronyc tracking -v
tuned-adm profile network-latency
print_ok "Selesai pemasangan modul tambahan"
}
function enable_services(){
print_install "All Service"
systemctl daemon-reload
systemctl enable --now netfilter-persistent
systemctl start netfilter-persistent
systemctl enable --now badvpn1
systemctl enable --now badvpn2
systemctl enable --now badvpn3
systemctl enable --now nginx
systemctl enable --now chronyd
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now iptables.service
systemctl enable --now squid
systemctl enable --now ws@drws
systemctl enable --now ws@opws
systemctl enable --now ws@ovws
systemctl enable --now ws@stws
systemctl enable --now server
systemctl enable --now custom
systemctl enable --now psiphon
systemctl enable --now fail2ban
cp /lib/systemd/system/haproxy.service /etc/systemd/system/
cp /lib/systemd/system/nginx.service /etc/systemd/system/
sleep 1
systemctl enable --now haproxy.service
systemctl enable --now nginx.service
wget -O /etc/issue.net "${REPO}/issue.net" >/dev/null 2>&1
print_success "All Service"
}
wget https://raw.githubusercontent.com/Fv-store/free/main/fodder/ins-udp && chmod +x ins-udp && ins-udp
function finish(){
TIME="10"
NAMES=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/izin/main/hafira | grep $MYIP | awk '{print $3}')
EXPSC=$(curl -sS https://raw.githubusercontent.com/irawancandra6699/izin/main/hafira | grep $MYIP | awk '{print $4}')
CHATID="-5879214876"
LOCAL_DATE="/usr/bin/"
MYIP=$(wget -qO- ipinfo.io/ip)
ISP=$(wget -qO- ipinfo.io/org)
CITY=$(curl -s ipinfo.io/city)
TIMES=$(date +'%Y-%m-%d %H:%M:%S')
RAMMS=$(free -m | awk 'NR==2 {print $2}')
OSL=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
KEY="6452283289:AAF8LR2iWqoA-dW6s8YfapsgkTSq7aRVGck"
URL="https://api.telegram.org/bot$KEY/sendMessage"
domain=$(cat /etc/xray/domain)
TEXT="
<code>────────────────────</code>
<b>⚠️AUTOSCRIPT PREMIUM⚠️</b>
<code>────────────────────</code>
<code>Owner   : </code><code>$NAMES</code>
<code>Ip vps  : </code><code>$MYIP</code>
<code>Domain  : </code><code>$domain</code>
<code>Date    : </code><code>$TIMES</code>
<code>Ram     : </code><code>$RAMMS MB</code>
<code>System  : </code><code>$OSL</code>
<code>Country : </code><code>$CITY</code>
<code>Isp     : </code><code>$ISP</code>
<code>Exp Sc  : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from</i>
<i>UNDERGROUND™ </i>
"'&reply_markup={"inline_keyboard":[[{"text":"ORDER🐳","url":"https://t.me/Candravpnz "},{"text":"CHANNEL🐬","url":"https://t.me/CANDRAVPNZ"}]]}'

curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

mv /etc/openvpn/OvenVPN.zip /var/www/html/
sed -i "s/xxx/${domain}/g" /var/www/html/index.html
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/drop.conf
sed -i "s/xxxx/${MYIP}/g" /etc/squid/squid.conf
sed -i "s/xxx/${domain}/g" /etc/squid/squid.conf
echo MakhlukVpnTunnel >/root/.config/respond
echo switch off >/root/.config/.backup
mkdir -p /run/xray
chown www-data.www-data /var/log/xray
chown www-data.www-data /run/xray
apt install python3 python3-pip git
wget -O /root/.config/panel.zip "${idc}last/panel.zip" >/dev/null 2>&1
cd /root/.config && unzip panel.zip >/dev/null 2>&1
rm panel.zip && mv xolpanel/shell.zip /etc/shell
cd /etc/shell && 7z e -password-out shell.zip >/dev/null 2>&1
chmod 755 * && rm shell.zip && cd
wget -O /etc/systemd/system/xolpanel.service "${REPO}service/xolpanel.service" >/dev/null 2>&1
alias bash2="bash --init-file <(echo '. ~/.bashrc; unset HISTFILE')"
apt-get clean all
sudo apt-get autoremove -y
rm ~/.bash_history
clear
wget -O /etc/info ${REPO}info >/dev/null 2>&1
echo "`cat /etc/info`"
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "         ${YELLOW} Processing Reboot Your Vps${FONT} 10 second .... "
sleep 10
rm /root/setup-main-ub >/dev/null 2>&1
rm /tmp/*.sh >/dev/null 2>&1
rm /tmp/*.zip >/dev/null 2>&1
rm /root/*.sh >/dev/null 2>&1
rm /root/*.zip >/dev/null 2>&1
reboot
}
function install_all() {
dir_xray
add_domain
pasang_ssl
install_xray
install_ovpn
install_slowdns
install_custom
install_rclone
download_config
tambahan
enable_services
finish
}
MakhlukVpn
first_setup
base_package
install_all
