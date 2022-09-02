#!/bin/bash

# Color
N="\033[0m"
R="\033[0;31m"
G="\033[0;32m"
B="\033[0;34m"
Y="\033[0;33m"
C="\033[0;36m"
P="\033[0;35m"
LR="\033[1;31m"
LG="\033[1;32m"
LB="\033[1;34m"
LY="\033[1;33m"
LC="\033[1;36m"
LP="\033[1;35m"
RB="\033[41;37m"
GB="\033[42;37m"
BB="\033[44;37m"
BD="\033[1m"

# Notification
INFO="[ ${LB}INFO${N} ] ${B}"
OK="[ ${LG}OK${N} ] ${G}"
ERROR="[ ${LR}ERROR${N} ] ${R}"

clear

# Check Services
check_install() {
	if [[ 0 -eq $? ]]; then
		echo -e "${OK}$1 is installed${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not installed${N}\n"
		exit 1
	fi
}

check_status() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${OK}$1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not running${N}\n"
		exit 1
	fi
}

check_screen() {
	if screen -ls | grep -qw $1; then
		echo -e "${OK}$1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not running${N}\n"
		exit 1
	fi
}

# Source
repo='https://raw.githubusercontent.com/skynetcenter/Skynet-VPN/main/'
network=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)

# Update Packages
echo -e "${INFO}Updating packages ...${N}"
sleep 1
apt update
apt upgrade -y
apt autoremove --purge -y
clear

# Install Dependencies
echo -e "${INFO}Installing script dependencies ...${N}"
apt install systemd curl wget screen cmake zip unzip vnstat tar openssl git uuid-runtime -y
check_install systemd
check_install curl
check_install wget
check_install screen
check_install cmake
check_install unzip
check_install vnstat
check_install tar
check_install openssl
check_install git
check_install uuid-runtime
clear

# Get Domain
echo -e "${INFO}Getting domain info ...${N}"
echo -e "Enter domain name: \c"
read domain
echo -e "${INFO}Checking domain name ...${N}"
sleep 1
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "${OK}IP matched with the server${N}"
	sleep 1
	clear
elif grep -qw "$domain" /etc/hosts; then
	echo -e "${OK}IP matched with hostname${N}"
	clear
else
	echo -e "${ERROR}IP does not match with the server${N}\n"
	exit 1
fi

# Optimize Settings
echo -e "${INFO}Optimizing settings ...${N}"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US
clear

# Reset Iptables
echo -e "${INFO}Resetting Iptables ...${N}"
sleep 1
apt install iptables-persistent -y
checkInstall iptables-persistent
ufw disable
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore
clear

# Configure Cron
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${INFO}Installing Cron ...${N}"
	sleep 1
	apt install cron -y
	check_install cron
fi
echo -e "${INFO}Configuring Cron ...${N}"
sleep 1
mkdir /skynetvpn
cat > /skynetvpn/cron.daily << EOF
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/skynetvpn

systemctl daemon-reload
systemctl restart xray@config
reboot
EOF
chmod +x /skynetvpn/cron.daily
(crontab -l; echo "0 0 * * * /skynetvpn/cron.daily") | crontab -
clear

# Configure SSH
echo -e "${INFO}Configuring SSH ...${N}"
sleep 1
echo "Welcome To Skynet VPN Server" > /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /skynetvpn/ssh
touch /skynetvpn/ssh/ssh-clients.txt
systemctl restart ssh
check_status ssh
clear

# Install Dropbear
echo -e "${INFO}Installing Dropbear ...${N}"
sleep 1
apt install dropbear -y
check_install dropbear
echo -e "${INFO}Configuring Dropbear ...${N}"
sleep 1
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=85/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
cat > /etc/dropbear_issue.net << EOF
<p>░░▒▒▓▓ Skynet VPN ▓▓▒▒░░</p>
<p>╔ Server SG
<br>╠ Support Netflix
<br>╠ Support Gaming
<br>╚ Support VC
<p>╔ No Torrent
<br>╠ No PSN
<br>╠ No DDoS
<br>╚ No Carding
</p>
<p>&lsaquo; Server reboot at 12 am daily &rsaquo;</p>
<p>Support: admin@skynetcenter.me</p>
EOF
sed -i 's|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/dropbear_issue.net"|g' /etc/default/dropbear
systemctl restart dropbear
check_status dropbear
clear

# Install Stunnel
echo -e "${INFO}Installing Stunnel ...${N}"
sleep 1
apt install stunnel4 -y
check_install stunnel4
echo -e "${INFO}Configuring Stunnel ...${N}"
sleep 1
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Iriszz/emailAddress=admin@skynetcenter.me/O=Upcloud Ltd/OU=Skynet VPN/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 465
connect = 127.0.0.1:85
EOF
systemctl restart stunnel4
check_status stunnel4
clear

# Disable IPv6
echo -e "${INFO}Disabling IPv6 ...${N}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
clear

# Install OpenVPN
echo -e "${INFO}Installing OpenVPN ...${N}"
sleep 1
apt install openvpn -y
check_install openvpn
echo -e "${INFO}Configuring OpenVPN ...${N}"
sleep 1
wget "${repo}files/EasyRSA-3.0.8.tgz"
tar xvf EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"MY"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"Wilayah Persekutuan"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"Kuala Lumpur"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t\t"Upcloud Ltd"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_EMAIL\t"me@example.net"/set_var EASYRSA_REQ_EMAIL\t"admin@skynetcenter.me"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/set_var EASYRSA_REQ_OU\t\t"Skynet VPN"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CA_EXPIRE\t3650/set_var EASYRSA_CA_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CERT_EXPIRE\t825/set_var EASYRSA_CERT_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CN\t\t"ChangeMe"/set_var EASYRSA_REQ_CN\t\t"Skynet VPN"/g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
cat > /etc/openvpn/server-udp conf << EOF
port 1194
proto udp
dev tun
ca key/ca.crt
cert key/server.crt
key key/server.key
dh key/dh.pem
verify-client-cert none
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/server-udp-status.log
log /var/log/openvpn/server-udp.log
verb 3
mute 10
plugin openvpn-plugin-auth-pam.so login
username-as-common-name
EOF
cat > /etc/openvpn/server-tcp.conf << EOF
port 1194
proto tcp
dev tun
ca key/ca.crt
cert key/server.crt
key key/server.key
dh key/dh.pem
verify-client-cert none
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/server-tcp-status.log
log /var/log/openvpn/server-tcp.log
verb 3
mute 10
plugin openvpn-plugin-auth-pam.so login
username-as-common-name
EOF
sed -i "s/#AUTOSTART="all"/AUTOSTART="all"/g" /etc/default/openvpn
echo -e "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
rm EasyRSA-3.0.8.tgz
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o ${network} -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o ${network} -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp
check_status openvpn@server-udp
check_status openvpn@server-tcp

# Configure OpenVPN Client
echo -e "${INFO}Configuring OpenVPN client ...${N}"
sleep 1
mkdir /skynetvpn/openvpn
cat > /skynetvpn/openvpn/client-udp.ovpn << EOF
client
dev tun
proto udp
remote xx 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
verb 3
auth-user-pass
setenv CLIENT_CERT 0
EOF
cat > /skynetvpn/openvpn/client-tcp.ovpn << EOF
client
dev tun
proto tcp
remote xx 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
verb 3
auth-user-pass
setenv CLIENT_CERT 0
EOF
sed -i "s/xx/$ip/g" /skynetvpn/openvpn/client-udp.ovpn
sed -i "s/xx/$ip/g" /skynetvpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /skynetvpn/openvpn/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /skynetvpn/openvpn/client-tcp.ovpn
echo -e "</ca>" >> /skynetvpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /skynetvpn/openvpn/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /skynetvpn/openvpn/client-udp.ovpn
echo -e "</ca>" >> /skynetvpn/openvpn/client-udp.ovpn

# Install Squid
echo -e "${INFO}Installing Squid ...${N}"
sleep 1
apt install squid -y
check_install squid
cat > /etc/squid/squid.conf << EOF
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst ip/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname xx
EOF
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
systemctl restart squid
check_status squid
clear

# Install Open HTTP Puncher
echo -e "${INFO}Installing OHP ...${N}"
sleep 1
apt install python -y
check_install python
wget -O /usr/bin/ohpserver "${repo}files/ohpserver"
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:85
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:1194
check_screen ohp-dropbear
check_screen ohp-openvpn
clear

# Install BadVPN UDPGW
echo -e "${INFO}Installing BadVPN UDPGW ...${N}"
sleep 1
wget -O badvpn.zip "${repo}files/badvpn.zip"
unzip badvpn.zip
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -rf badvpn-master
rm -f badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
check_screen badvpn
clear

# Install Speedtest CLI
echo -e "${INFO}Installing Speedtest CLI ...${N}"
sleep 1
wget -O speedtest.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-linux-$(uname -m).tgz"
tar xvf speedtest.tgz -C /usr/bin/ speedtest
check_install speedtest
rm -f speedtest.tgz
clear

# Install Fail2ban
echo -e "${INFO}Installing Fail2Ban ...${N}"
sleep 1
apt install fail2ban -y
check_install fail2ban
systemctl restart fail2ban
check_status fail2ban
clear

# Install DDOS Deflate
echo -e "${INFO}Installing DDoS Deflate ...${N}"
sleep 1
apt install dnsutils tcpdump dsniff grepcidr net-tools -y
check_install dnsutils
check_install tcpdump
check_install dsniff
check_install grepcidr
check_install net-tools
wget -O ddos.zip "${repo}files/ddos-deflate.zip"
unzip ddos.zip
cd ddos-deflate
chmod +x install.sh
./install.sh
cd
rm -rf ddos.zip ddos-deflate
check_status ddos
clear

# Configure rc.local
echo -e "${INFO}Checking for rc.local service ...${N}"
sleep 1
systemctl status rc-local
if [[ 0 -ne $? ]]; then
	echo -e "${INFO}Installing rc.local ...${N}"
	sleep 1
	cat > /etc/systemd/system/rc-local.service << EOF
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
	echo -e "${INFO}Configuring rc.local ...${N}"
	sleep 1
	cat > /etc/rc.local << EOF
#!/bin/bash

/etc/init.d/procps restart
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:85
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:1194
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
iptables-restore < /skynetvpn/iptables.rules

exit 0
EOF
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local
	checkRun rc-local
else
	echo -e "${INFO}Configuring rc.local ...${N}"
	sleep 1
	cat > /etc/rc.local << EOF
#!/bin/bash

/etc/init.d/procps restart
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:85
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:1194
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
iptables-restore < /skynetvpn/iptables.rules

exit 0
EOF
	systemctl start rc-local
	systemctl enable rc-local
	checkRun rc-local
fi
clear

# Save Iptables
echo -e "${INFO}Saving Iptables ...${N}"
sleep 1
iptables-save > /skynetvpn/iptables.rules
clear

# Install Xray Onekey
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/main/install.sh" && chmod +x install.sh && bash install.sh

# Change Timezone
echo -e "${INFO}Changing timezone to Asia/Kuala_Lumpur (GMT +8) ...${N}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
clear

# Install BBR
wget -O tcpx.sh "https://git.io/JYxKU" && chmod +x tcpx.sh && ./tcpx.sh
./tcpx.sh

# Cleanup
clear
rm -f /root/skynet-vpn.sh
rm -f /root/install.sh
rm -f /root/tcpx.sh
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
echo -e ""
echo -e "${INFO}Autoscript executed succesfully${N}"
echo -e ""
read -n 1 -r -s -p $"Press enter to reboot .."
echo -e "\n"
reboot
