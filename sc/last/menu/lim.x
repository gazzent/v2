repo=hhttps://raw.githubusercontent.com/gazzent/ip/main/ip
ipsaya=$(wget -qO- ipv4.icanhazip.com);
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
useexp=$(wget -qO- ${repo} | grep $ipsaya | awk '{print $4}')
if [[ $date_list < $useexp ]]; then
echo -ne
else
exit
fi
domain=$(cat /etc/xray/domain)
MYIP=$(wget -qO- icanhazip.com)
timenow=$(date +%T)
function send_ip(){
TIMES="10"
source '/root/.config/xolpanel/var.txt'
URL="https://api.telegram.org/bot$BOT_TOKEN/sendMessage"
TEXT="
<code>◇────────────────────◇</code>
<b>   ◇⟨ ⚠️NOTIF LIMIT IP⚠️ ⟩◇</b>
<code>◇────────────────────◇</code>
<code>Username : </code><code>${user}</code>
<code>Limit Ip : </code>${cekcek}<code>
</code>
<code>◇────────────────────◇</code>
<code>Account Locked 5 minutes</code>
"
curl -s --max-time $TIMES -d "chat_id=$ADMIN&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
function send_quota(){
TIMES="10"
source '/root/.config/xolpanel/var.txt'
URL="https://api.telegram.org/bot$BOT_TOKEN/sendMessage"
TEXT="
<code>◇────────────────────◇</code>
<b>    ◇⟨ ⚠️NOTIF LIMIT QUOTA⚠️ ⟩◇</b>
<code>◇────────────────────◇</code>
<code>Username  : </code><code>$user</code>
<code>Usage     : </code><code>$total</code>
<code>◇────────────────────◇</code>
<code>Account Deleted</code>
"
curl -s --max-time $TIME -d "chat_id=$ADMIN&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}
function con() {
local -i bytes=$1;
if [[ $bytes -lt 1024 ]]; then
echo "${bytes}B"
elif [[ $bytes -lt 1048576 ]]; then
echo "$(( (bytes + 1023)/1024 ))KB"
elif [[ $bytes -lt 1073741824 ]]; then
echo "$(( (bytes + 1048575)/1048576 ))MB"
else
echo "$(( (bytes + 1073741823)/1073741824 ))GB"
fi
}
function cekvless(){
data=($(cat /etc/vless/.vless.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
if [[ ! -e /etc/vless/cache ]]; then
mkdir -p /etc/vless/cache
fi
for user in ${data[@]}; do
data=$(xray api statsquery --server=127.0.0.1:10000 | grep -C 2 $user | sed /"}"/d | sed /"{"/d | grep value | awk '{print $2}' | sed 's/,//g; s/"//g' | sort)
inb=$(echo $data | awk '{print $1}')
outb=$(echo $data | awk '{print $2}')
quota0=$((inb + outb))
if [ -e /etc/vless/cache/${user} ]; then
quota1=$(cat /etc/vless/cache/${user});
if [[ ${quota1} -gt 0 ]]; then
quota2=$(( ${quota0} + ${quota1} ));
echo "${quota2}" > /etc/vless/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
else
echo "${quota0}" > /etc/vless/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
done
}
function cekvmess(){
data=($(cat /etc/vmess/.vmess.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
if [[ ! -e /etc/vmess/cache ]]; then
mkdir -p /etc/vmess/cache
fi
for user in ${data[@]}
do
data=$(xray api statsquery --server=127.0.0.1:10000 | grep -C 2 $user | sed /"}"/d | sed /"{"/d | grep value | awk '{print $2}' | sed 's/,//g; s/"//g' | sort)
inb=$(echo $data | awk '{print $1}')
outb=$(echo $data | awk '{print $2}')
quota0=$((inb + outb))
if [ -e /etc/vmess/cache/${user} ]; then
quota1=$(cat /etc/vmess/cache/${user});
if [[ ${quota1} -gt 0 ]]; then
quota2=$(( ${quota0} + ${quota1} ));
echo "${quota2}" > /etc/vmess/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
else
echo "${quota0}" > /etc/vmess/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
done
}
function cektrojan(){
data=($(cat /etc/trojan/.trojan.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
if [[ ! -e /etc/trojan/cache ]]; then
mkdir -p /etc/trojan/cache
fi
for user in ${data[@]}
do
data=$(xray api statsquery --server=127.0.0.1:10000 | grep -C 2 $user | sed /"}"/d | sed /"{"/d | grep value | awk '{print $2}' | sed 's/,//g; s/"//g' | sort)
inb=$(echo $data | awk '{print $1}')
outb=$(echo $data | awk '{print $2}')
quota0=$((inb + outb))
if [ -e /etc/trojan/cache/${user} ]; then
quota1=$(cat /etc/trojan/cache/${user});
if [[ ${quota1} -gt 0 ]]; then
quota2=$(( ${quota0} + ${quota1} ));
echo "${quota2}" > /etc/trojan/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
else
echo "${quota0}" > /etc/trojan/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
done
}
function cekss(){
data=($(cat /etc/shadowsocks/.shadowsocks.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
if [[ ! -e /etc/shadowsocks/cache ]]; then
mkdir -p /etc/shadowsocks/cache
fi
for user in ${data[@]}
do
data=$(xray api statsquery --server=127.0.0.1:10000 | grep -C 2 $user | sed /"}"/d | sed /"{"/d | grep value | awk '{print $2}' | sed 's/,//g; s/"//g' | sort)
inb=$(echo $data | awk '{print $1}')
outb=$(echo $data | awk '{print $2}')
quota0=$((inb + outb))
if [ -e /etc/shadowsocks/cache/${user} ]; then
quota1=$(cat /etc/shadowsocks/cache/${user} );
if [[ ${quota1} -gt 0 ]]; then
quota2=$(( ${quota0} + ${quota1} ));
echo "${quota2}" > /etc/shadowsocks/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
else
echo "${quota0}" > /etc/shadowsocks/cache/"${user}"
xray api stats --server=127.0.0.1:10000 -name "user>>>${user}>>>traffic>>>downlink" -reset > /dev/null 2>&1
fi
done
}
function vm()(
data=($(cat /etc/vmess/.vmess.db | grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
iplim=$(cat /etc/vmess/$user | awk '{print $2}')
ehh=$(cat /var/log/xray/access.log | grep "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq);
cekcek=$(echo -e "$ehh" | wc -l);
if [[ $cekcek -gt $iplim ]]; then
uuid=$(grep -A1 '#vm# $user' /etc/xray/config.json| grep -o '"id": "[^"]*' | grep -o '[^"]*$')
exp=$(grep -wE "^#vm# $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#vm# $user $exp/,/^},{/d" /etc/xray/config.json
echo "res vmess ${user} ${exp} ${uuid}" | at now +5 minutes &> /dev/null
systemctl restart xray &> /dev/null
send_ip
else
echo ""
fi
sleep 0.1
done
cekvmess
data=($(cat /etc/vmess/.vmess.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
if [ -e /etc/vmess/${user} ]; then
cekdulu=$(cat /etc/vmess/${user} | awk '{print $1}');
if [[ ${cekdulu} -gt 1 ]]; then
if [ -e /etc/vmess/cache/${user} ]; then
pakai=$(cat /etc/vmess/cache/${user});
if [[ ${pakai} -gt ${cekdulu} ]]; then
printf "%s
" "${user}" | /etc/shell/del vmess
bol=$(cat /etc/vmess/cache/${user});
total=$(con ${bol})
send_quota
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
done
)
function vl()(
data=($(cat /etc/vless/.vless.db | grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
iplim=$(cat /etc/vless/$user | awk '{print $2}')
ehh=$(cat /var/log/xray/access.log | grep "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq);
cekcek=$(echo -e "$ehh" | wc -l);
if [[ $cekcek -gt $iplim ]]; then
uuid=$(grep -A1 '#vl# $user' /etc/xray/config.json| grep -o '"id": "[^"]*' | grep -o '[^"]*$')
exp=$(grep -wE "^#vl# $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#vl# $user $exp/,/^},{/d" /etc/xray/config.json
echo "res vless ${user} ${exp} ${uuid}" | at now +5 minutes &> /dev/null
systemctl restart xray &> /dev/null
send_ip
else
echo ""
fi
sleep 0.1
done
cekvless
data=($(cat /etc/vless/.vless.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
if [ -e /etc/vless/${user} ]; then
cekdulu=$(cat /etc/vless/${user} | awk '{print $1}');
if [[ ${cekdulu} -gt 1 ]]; then
if [ -e /etc/vless/cache/${user} ]; then
pakai=$(cat /etc/vless/cache/${user});
if [[ ${pakai} -gt ${cekdulu} ]]; then
printf "%s
" "${user}" | /etc/shell/del vless
bol=$(cat /etc/vless/cache/${user});
total=$(con ${bol})
send_quota
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
done
)
function tr()(
data=($(cat /etc/trojan/.trojan.db | grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
iplim=$(cat /etc/trojan/$user | awk '{print $2}')
ehh=$(cat /var/log/xray/access.log | grep "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq);
cekcek=$(echo -e "$ehh" | wc -l);
if [[ $cekcek -gt $iplim ]]; then
uuid=$(grep -A1 '#tr# $user' /etc/xray/config.json| grep -o '"id": "[^"]*' | grep -o '[^"]*$')
exp=$(grep -wE "^#tr# $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#tr# $user $exp/,/^},{/d" /etc/xray/config.json
echo "res trojan ${user} ${exp} ${uuid}" | at now +5 minutes &> /dev/null
systemctl restart xray &> /dev/null
send_ip
else
echo ""
fi
sleep 0.1
done
cektrojan
data=($(cat /etc/trojan/.trojan.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
if [ -e /etc/trojan/${user} ]; then
cekdulu=$(cat /etc/trojan/${user} | awk '{print $1}');
if [[ ${cekdulu} -gt 1 ]]; then
if [ -e /etc/trojan/cache/${user} ]; then
pakai=$(cat /etc/trojan/cache/${user});
if [[ ${pakai} -gt ${cekdulu} ]]; then
printf "%s
" "${user}" | /etc/shell/del trojan
bol=$(cat /etc/trojan/cache/${user});
total=$(con ${bol})
send_quota
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
done
)
function ss()(
data=($(cat /etc/shadowsocks/.shadowsocks.db | grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
iplim=$(cat /etc/shadowsocks/$user | awk '{print $2}')
ehh=$(cat /var/log/xray/access.log | grep "$user" | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq);
cekcek=$(echo -e "$ehh" | wc -l);
if [[ $cekcek -gt $iplim ]]; then
uuid=$(grep -A1 '#ss# $user' /etc/xray/config.json| grep -o '"id": "[^"]*' | grep -o '[^"]*$')
exp=$(grep -wE "^#ss# $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#ss# $user $exp/,/^},{/d" /etc/xray/config.json
echo "res ss ${user} ${exp} ${uuid}" | at now +5 minutes &> /dev/null
systemctl restart xray &> /dev/null
send_ip
else
echo ""
fi
sleep 0.1
done
cekss
data=($(cat /etc/shadowsocks/.shadowsocks.db| grep '^###' | cut -d ' ' -f 2 | sort | uniq))
for user in ${data[@]}; do
if [ -e /etc/shadowsocks/${user} ]; then
cekdulu=$(cat /etc/shadowsocks/${user} | awk '{print $1}');
if [[ ${cekdulu} -gt 1 ]]; then
if [ -e /etc/shadowsocks/cache/${user} ]; then
pakai=$(cat /etc/shadowsocks/cache/${user});
if [[ ${pakai} -gt ${cekdulu} ]]; then
printf "%s
" "${user}" | /etc/shell/del ss
bol=$(cat /etc/shadowsocks/cache/${user});
total=$(con ${bol})
send_quota
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
else
echo ""
fi
done
)
function sssh()(
data=($(cat /etc/ssh/.ssh.db | grep '^###' | cut -d ' ' -f 2 | sort | uniq))
mulog=$(data=($(ps aux | grep -i dropbear | awk '{print $2}'))
cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" >/tmp/login-db.txt
for PID in "${data[@]}"; do
cat /tmp/login-db.txt | grep "dropbear\[$PID\]" >/tmp/login-db-pid.txt
NUM=$(cat /tmp/login-db-pid.txt | wc -l)
USER=$(cat /tmp/login-db-pid.txt | awk '{print $10}')
IP=$(cat /tmp/login-db-pid.txt | awk '{print $12}')
if [ $NUM -eq 1 ]; then
echo "    $PID  - $USER - $IP"
fi
done
data=($(ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'))
cat /var/log/auth.log | grep -i sshd | grep -i "Accepted password for" >/tmp/login-op.txt
for PID in "${data[@]}"; do
cat /tmp/login-op.txt | grep "sshd\[$PID\]" >/tmp/login-op-pid.txt
NUM=$(cat /tmp/login-op-pid.txt | wc -l)
USER=$(cat /tmp/login-op-pid.txt | awk '{print $9}')
IP=$(cat /tmp/login-op-pid.txt | awk '{print $11}')
if [ $NUM -eq 1 ]; then
echo "    $PID - $USER - $IP"
fi
done)
for user in "${data[@]}"; do
iplimit=$(cat /etc/ssh/$user)
cekcek=$(echo -e "$mulog" | grep $user | wc -l);
if [[ $cekcek -gt $iplimit ]]; then
kill -9 $PID
passwd -l $user
echo "res ssh ${user}" | at now +5 minutes &> /dev/null
systemctl restart sshd
send_ip
echo -e "Removed User: $user Login: $cekcek IP Max: $iplimit IP" >> /root/ssh.log
else
echo > /dev/null
fi
sleep 0.1
done
rm -f /tmp/login-db-pid.txt
rm -f /tmp/login-db.txt
rm -f /tmp/login-op-pid.txt
rm -f /tmp/login-op.txt
rm -f /tmp/vpn-login-tcp.txt
rm -f /tmp/vpn-login-udp.txt
)
if [[ ${1} == "vmess" ]]; then
vm
fi
if [[ ${1} == "vless" ]]; then
vl
fi
if [[ ${1} == "trojan" ]]; then
tr
fi
if [[ ${1} == "ss" ]]; then
ss
fi
if [[ ${1} == "ssh" ]]; then
sssh
fi
