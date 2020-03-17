#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
pre_Install() {
#!/bin/bash
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"
OK="${GreenBG}[OK]${Font}"
Error="${RedBG}[错误]${Font}"
#root用户判断
is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        sleep 10
        exit 1
    fi
    }

#判断系统
check_system() {
    VERSION=$(cat /etc/issue | awk -F "[ ]" '{print $1}')
    System_Name=$(uname -a)
    if [ $VERSION == "Centos" ]; then
        echo -e "${OK} ${GreenBG} 当前系统为 $System_Name ${Font}"
        echo -e "${Error} ${RedBG} 仅支持Debian或Ubuntu系统 ${Font}"
        exit 1
    elif [ $VERSION == "Debian" ]; then
        echo -e "${OK} ${GreenBG} 当前系统为 $System_Name ${Font}"
        echo -e "${OK} ${GreenBG} 准备开始 ${Font}"
        sleep 5
    elif [ $VERSION == "Ubuntu" ]; then
        echo -e "${OK} ${GreenBG} 当前系统为 $System_Name ${Font}"
        systemctl stop ufw
        systemctl disable ufw
        echo -e "${OK} ${GreenBG} 防火墙已关闭 ${Font}"
        echo -e "${OK} ${GreenBG} 准备开始 ${Font}"
        sleep 5
    else
        echo -e "${Error} ${RedBG} 当前系统为 $System_Name 不予支持，安装中断 ${Font}"
        exit 1
    fi
    }

#更换国内源
Change_source() {
    VERSION=$(cat /etc/issue | awk -F "[ ]" '{print $1}')
    if [ $VERSION == "Debian" ]; then
        osRelease=$(cat /etc/os-release | grep VERSION= | cut -d '(' -f2 | cut -d ')' -f1)
        rm -rf /etc/apt/sources.list
        echo "deb http://mirrors.163.com/debian/ $osRelease main non-free contrib" > /etc/apt/sources.list
        echo "deb http://mirrors.163.com/debian/ $osRelease-updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/debian/ $osRelease-backports main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/debian/ $osRelease main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/debian/ $osRelease-updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/debian/ $osRelease-backports main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/debian-security/ $osRelease/updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/debian-security/ $osRelease/updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/debian/ $osRelease main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/debian/ $osRelease main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/debian-security $osRelease/updates main" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/debian-security $osRelease/updates main" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/debian/ $osRelease-updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/debian/ $osRelease-updates main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/debian/ $osRelease-backports main non-free contrib" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/debian/ $osRelease-backports main non-free contrib" >> /etc/apt/sources.list
    elif [ $VERSION == "Ubuntu" ]; then
        osRelease=$(cat /etc/os-release | grep VERSION_CODENAME | cut -c18- )
        rm -rf /etc/apt/sources.list
        echo "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease main restricted universe multiverse" > /etc/apt/sources.list
        echo "deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $osRelease-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/ubuntu/ $osRelease main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/ubuntu/ $osRelease-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/ubuntu/ $osRelease-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/ubuntu/ $osRelease-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.163.com/ubuntu/ $osRelease-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/ubuntu/ $osRelease main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/ubuntu/ $osRelease-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/ubuntu/ $osRelease-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/ubuntu/ $osRelease-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.163.com/ubuntu/ $osRelease-backports main restricted universe multiverse" >> /etc/apt/sources.list
    fi
    }
is_root
check_system
Change_source
apt update && apt dist-upgrade -y
apt install wget -y > /dev/null 2>&1
}
#调整系统时间至北京时间
Time_UTC8() {
    #!/bin/bash
    echo "Asia/Shanghai" >/etc/timezone
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    isWgetInstalled=$(dpkg-query -l | grep wget |wc -l)
    if [ $isWgetInstalled -eq 0 ]; then
        apt install wget -y > /dev/null 2>&1
        date -s "$(wget -qSO- --max-redirect=0 baidu.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
    else
        date -s "$(wget -qSO- --max-redirect=0 baidu.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
    fi
    hwclock -w
}
#改为静态IP
IP_Static() {
#!/bin/bash
apt install net-tools -y > /dev/null 2>&1
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
ethernetnum=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
localaddr=$(ip a | grep "$ethernetnum" | awk '{print $2}' | awk 'END {print}' | cut -d'/' -f1)
gatewayaddr=$(route -n | awk 'NR==3{print $2}')
cat >/etc/network/interfaces <<EOF
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto $ethernetnum
iface $ethernetnum inet static
address $localaddr
netmask 255.255.255.0
gateway $gatewayaddr
EOF
green "已更改为静态IP"
green "IP地址：$localaddr"
green "网关地址：$gatewayaddr"
sleep 5
}
#unbound安装
Unbound_Install() {
#!/bin/bash
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
touch $HOME/unbound.conf
cat > $HOME/unbound.conf <<EOF
include: "/etc/unbound/unbound.conf.d/accelerated-domains.china.unbound.conf"
include: "/etc/unbound/unbound.conf.d/apple.china.unbound.conf"
include: "/etc/unbound/unbound.conf.d/google.china.unbound.conf"
server:
  verbosity: 1
  statistics-interval: 0
  num-threads: 2
  interface: 127.0.0.1
  port: 5354
  outgoing-range: 4096
  outgoing-num-tcp: 256
  incoming-num-tcp: 1024
  so-reuseport: yes
  msg-cache-size: 64m
  rrset-cache-size: 128m
  cache-max-ttl: 604800
  cache-max-negative-ttl: 3600
  do-ip4: yes
  do-ip6: yes
  do-udp: yes
  do-tcp: yes
  tcp-upstream: no
  access-control: 127.0.0.0/8 allow
  root-hints: "/etc/unbound/root.hints"
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  unwanted-reply-threshold: 10000000
  do-not-query-localhost: no
  prefetch: yes
  minimal-responses: yes
  module-config: "iterator"
python:
  # Script file to load
  # python-script: "/usr/local/etc/unbound/ubmodule-tst.py"
remote-control:
  control-enable: yes
  control-interface: 127.0.0.1
  control-port: 8953
  control-use-cert: "no"
forward-zone:
   name: "."
   forward-addr: 127.0.0.1@5353
EOF
touch $HOME/netease.unbound.conf
cat > $HOME/netease.unbound.conf <<EOF
forward-zone:
  name: "apm3.music.163.com."
  forward-addr: 127.0.0.1@5353

forward-zone:
  name: "apm.music.163.com."
  forward-addr: 127.0.0.1@5353

forward-zone:
  name: "interface3.music.163.com."
  forward-addr: 127.0.0.1@5353

forward-zone:
  name: "interface.music.163.com."
  forward-addr: 127.0.0.1@5353
  
forward-zone:
  name: "music.163.com."
  forward-addr: 127.0.0.1@5353
EOF
green "正在安装所需软件中，请稍等...."
apt install wget git gcc automake autoconf libtool make -y > /dev/null 2>&1
wget -t 0 -c -S https://www.internic.net/domain/named.cache -O $HOME/root.hints
git clone https://github.com/felixonmars/dnsmasq-china-list.git --depth 1
COUNT=$(ps -ef |grep unbound |grep -v "grep" |wc -l)
isUnboundInstalled=$(dpkg-query -l | grep -w "unbound" |wc -l)
#定义一个函数，用于判断unbound服务是否启动成功
Start_status_unbound() {
    unbound_status=$(systemctl status unbound | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$unbound_status" == "running" ]; then
    echo -e "\033[32m\033[01m unbound服务已正常启动！ \033[0m"
    else
    echo -e "\033[31m\033[01m 尝试启动unbound服务未成功，请查找原因！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$unbound_status \033[0m"
    sleep 5
    fi
}
if [[ $COUNT -eq 0 ]] && [[ $isUnboundInstalled -eq 0 ]]; then
green "unbound未安装，开始安装...."
apt install unbound -y
touch /etc/default/unbound
cat > /etc/default/unbound <<EOF
RESOLVCONF="false"
ROOT_TRUST_ANCHOR_UPDATE="false"
EOF
chmod 0640 /etc/default/unbound
mv -f $HOME/root.hints /etc/unbound/root.hints
rm -rf /etc/unbound/unbound.conf
mv -f $HOME/unbound.conf /etc/unbound/unbound.conf
mv -f $HOME/netease.unbound.conf /etc/unbound/unbound.conf.d/netease.unbound.conf
chmod 0640 /etc/unbound/unbound.conf
cd $HOME/dnsmasq-china-list
make SERVER=127.0.0.1@5355 unbound > /dev/null 2>&1
cp $HOME/dnsmasq-china-list/*unbound.conf /etc/unbound/unbound.conf.d/
chmod 0640 /etc/unbound/unbound.conf.d/*unbound.conf
systemctl daemon-reload > /dev/null 2>&1
systemctl enable unbound > /dev/null 2>&1
Start_status_unbound
sleep 5
elif [[ $COUNT -eq 0 ]] && [[ $isUnboundInstalled -ge 0 ]]; then
red "unbound已安装，但未在运行，更新配置文件中...."
cat > /etc/default/unbound <<EOF
RESOLVCONF="false"
ROOT_TRUST_ANCHOR_UPDATE="false"
EOF
chmod 0640 /etc/default/unbound
mv -f $HOME/root.hints /etc/unbound/root.hints
rm -rf /etc/unbound/unbound.conf > /dev/null 2>&1
mv -f $HOME/unbound.conf /etc/unbound/unbound.conf
mv -f $HOME/netease.unbound.conf /etc/unbound/unbound.conf.d/netease.unbound.conf
chmod 0640 /etc/unbound/unbound.conf
cd $HOME/dnsmasq-china-list
make SERVER=127.0.0.1@5355 unbound
rm -rf /etc/unbound/unbound.conf.d > /dev/null 2>&1
mkdir /etc/unbound/unbound.conf.d
cp $HOME/dnsmasq-china-list/*unbound.conf /etc/unbound/unbound.conf.d/
chmod 0640 /etc/unbound/unbound.conf.d/*unbound.conf
green "尝试启动unbound中...."
systemctl start unbound > /dev/null 2>&1
Start_status_unbound
sleep 5
else
red "unbound已安装并正常运行，跳过安装,更新配置文件中...."
cat > /etc/default/unbound <<EOF
RESOLVCONF="false"
ROOT_TRUST_ANCHOR_UPDATE="false"
EOF
chmod 0640 /etc/default/unbound
mv -f $HOME/root.hints /etc/unbound/root.hints
rm -rf /etc/unbound/unbound.conf > /dev/null 2>&1
mv -f $HOME/unbound.conf /etc/unbound/unbound.conf
mv -f $HOME/netease.unbound.conf /etc/unbound/unbound.conf.d/netease.unbound.conf
chmod 0640 /etc/unbound/unbound.conf
cd $HOME/dnsmasq-china-list
make SERVER=127.0.0.1@5355 unbound
rm -rf /etc/unbound/unbound.conf.d > /dev/null 2>&1
mkdir /etc/unbound/unbound.conf.d
cp $HOME/dnsmasq-china-list/*unbound.conf /etc/unbound/unbound.conf.d/
chmod 0640 /etc/unbound/unbound.conf.d/*unbound.conf
systemctl restart unbound > /dev/null 2>&1
Start_status_unbound
sleep 5
fi
cd $HOME
rm -rf $HOME/unbound.conf
rm -rf $HOME/root.hints
rm -rf $HOME/dnsmasq-china-list
rm -rf $HOME/netease.unbound.conf
}
#smartdns安装
Smartdns_Install() {
#!/bin/bash
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
touch $HOME/smartdns.conf
cat > $HOME/smartdns.conf <<EOF
# dns server name, defaut is host name
# server-name,
# example:
#   server-name smartdns
#

# Include another configuration options
# conf-file [file]
# conf-file blacklist-ip.conf

# dns server bind ip and port, default dns server port is 53, support binding multi ip and port
# bind udp server
#   bind [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
# bind tcp server
#   bind-tcp [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
# option:
#   -group: set domain request to use the appropriate server group.
#   -no-rule-addr: skip address rule.
#   -no-rule-nameserver: skip nameserver rule.
#   -no-rule-ipset: skip ipset rule.
#   -no-speed-check: do not check speed.
#   -no-cache: skip cache.
#   -no-rule-soa: Skip address SOA(#) rules.
#   -no-dualstack-selection: Disable dualstack ip selection.
# example:
#  IPV4:
#    bind :53
#    bind :6053 -group office -no-speed-check
#  IPV6:
#    bind [::]:53
#    bind-tcp [::]:53
bind 127.0.0.1:5355

# tcp connection idle timeout
# tcp-idle-time [second]

# dns cache size
# cache-size [number]
#   0: for no cache
cache-size 2048

# prefetch domain
# prefetch-domain [yes|no]
prefetch-domain yes

# List of hosts that supply bogus NX domain results
# bogus-nxdomain [ip/subnet]

# List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
# blacklist-ip [ip/subnet]

# List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
# whitelist-ip [ip/subnet]

# List of IPs that will be ignored
# ignore-ip [ip/subnet]

# speed check mode
# speed-check-mode [ping|tcp:port|none|,]
# example:
speed-check-mode ping,tcp:80
#   speed-check-mode tcp:443,ping
#   speed-check-mode none

# force AAAA query return SOA
# force-AAAA-SOA [yes|no]

# Enable IPV4, IPV6 dual stack IP optimization selection strategy
# dualstack-ip-selection-threshold [num] (0~1000)
# dualstack-ip-selection [yes|no]
# dualstack-ip-selection yes

# edns client subnet
# edns-client-subnet [ip/subnet]
# edns-client-subnet 192.168.1.1/24
# edns-client-subnet [8::8]/56

# ttl for all resource record
# rr-ttl: ttl for all record
# rr-ttl-min: minimum ttl for resource record
# rr-ttl-max: maximum ttl for resource record
# example:
rr-ttl 300
rr-ttl-min 60
rr-ttl-max 600

# set log level
# log-level: [level], level=fatal, error, warn, notice, info, debug
# log-file: file path of log file.
# log-size: size of each log file, support k,m,g
# log-num: number of logs
log-level info
# log-file /var/log/smartdns.log
# log-size 128k
# log-num 2

# dns audit
# audit-enable [yes|no]: enable or disable audit.
# audit-enable yes
# audit-SOA [yes|no]: enable or disalbe log soa result.
# audit-size size of each audit file, support k,m,g
# audit-file /var/log/smartdns-audit.log
# audit-size 128k
# audit-num 2

# remote udp dns server list
# server [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-check-edns] [-group [group] ...] [-exclude-default-group]
# default port is 53
#   -blacklist-ip: filter result with blacklist ip
#   -whitelist-ip: filter result whth whitelist ip,  result in whitelist-ip will be accepted.
#   -check-edns: result must exist edns RR, or discard result.
#   -group [group]: set server to group, use with nameserver /domain/group.
#   -exclude-default-group: exclude this server from default group.
# server 8.8.8.8 -blacklist-ip -check-edns -group g1 -group g2
server 114.114.114.114
server 223.5.5.5
server 180.76.76.76
server 119.29.29.29
server 1.2.4.8
server 117.50.11.11
server 101.101.101.101
server 203.80.96.10
server 168.95.192.1

# remote tcp dns server list
# server-tcp [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-group [group] ...] [-exclude-default-group]
# default port is 53
server-tcp 114.114.114.114
server-tcp 223.5.5.5
server-tcp 180.76.76.76
server-tcp 119.29.29.29
server-tcp 1.2.4.8
server-tcp 117.50.11.11
server-tcp 101.101.101.101
server-tcp 203.80.96.10
server-tcp 168.95.192.1

# remote tls dns server list
# server-tls [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-spki-pin [sha256-pin]] [-group [group] ...] [-exclude-default-group]
#   -spki-pin: TLS spki pin to verify.
#   -tls-host-check: cert hostname to verify.
#   -hostname: TLS sni hostname.
# Get SPKI with this command:
#    echo | openssl s_client -connect '[ip]:853' | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
# default port is 853

# remote https dns server list
# server-https https://[host]:[port]/path [-blacklist-ip] [-whitelist-ip] [-spki-pin [sha256-pin]] [-group [group] ...] [-exclude-default-group]
#   -spki-pin: TLS spki pin to verify.
#   -tls-host-check: cert hostname to verify.
#   -hostname: TLS sni hostname.
#   -http-host: http host.
# default port is 443

# specific nameserver to domain
# nameserver /domain/[group|-]
# nameserver /www.example.com/office, Set the domain name to use the appropriate server group.
# nameserver /www.example.com/-, ignore this domain

# specific address to domain
# address /domain/[ip|-|-4|-6|#|#4|#6]
# address /www.example.com/1.2.3.4, return ip 1.2.3.4 to client
# address /www.example.com/-, ignore address, query from upstream, suffix 4, for ipv4, 6 for ipv6, none for all
# address /www.example.com/#, return SOA to client, suffix 4, for ipv4, 6 for ipv6, none for all

# enable ipset timeout by ttl feature
# ipset-timeout [yes]

# specific ipset to domain
# ipset /domain/[ipset|-]
# ipset /www.example.com/block, set ipset with ipset name of block
# ipset /www.example.com/-, ignore this domain
EOF
touch $HOME/smartdns.service
cat > $HOME/smartdns.service <<EOF
[Unit]
Description=smart dns server
After=network.target 

[Service]
Type=forking
PIDFile=/run/smartdns.pid
EnvironmentFile=/etc/default/smartdns
ExecStart=/usr/sbin/smartdns -c /etc/smartdns/smartdns.conf
KillMode=process
Restart=always
RestartSec=2
StartLimitBurst=0
StartLimitIntervalSec=60

[Install]
WantedBy=multi-user.target
Alias=smartdns.service
EOF
green "正在安装所需软件中，请稍等...."
apt install wget gzip unzip -y > /dev/null 2>&1
COUNT_smartdns=$(ps -ef |grep smartdns |grep -v "grep" |wc -l)
Start_status_smartdns() {
    smartdns_status=$(systemctl status smartdns.service | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$smartdns_status" == "running" ]; then
    echo -e "\033[32m\033[01m smartdns服务已正常启动！ \033[0m"
    else
    echo -e "\033[31m\033[01m 尝试启动smartdns服务未成功，请查找原因！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$smartdns_status \033[0m"
    sleep 5
    fi
}
if [ $COUNT_smartdns -eq 0 ]; then
green "smartdns未安装，开始安装...."
wget -t 0 -S -c https://github.com/pymumu/smartdns/releases/download/Release30/smartdns.1.2020.02.25-2212.x86_64-linux-all.tar.gz -O $HOME/smartdns.tar.gz
tar -zxvf $HOME/smartdns.tar.gz
mkdir /etc/smartdns
mv -f $HOME/smartdns.conf /etc/smartdns/smartdns.conf
mv -f $HOME/smartdns/src/smartdns /usr/sbin/smartdns
mv -f $HOME/smartdns/etc/default/smartdns /etc/default/smartdns
mv -f $HOME/smartdns.service /lib/systemd/system/smartdns.service
chmod 0755 /usr/sbin/smartdns
chmod 0755 /lib/systemd/system/smartdns.service
chmod 0640 /etc/default/smartdns
chmod 0640 /etc/smartdns/smartdns.conf
rm -rf $HOME/smartdns.tar.gz
systemctl daemon-reload > /dev/null 2>&1
systemctl enable smartdns.service > /dev/null 2>&1
systemctl start smartdns.service > /dev/null 2>&1
Start_status_smartdns
sleep 5
else
red "smartdns已安装，跳过安装,更新配置文件中...."
mv -f $HOME/smartdns.conf /etc/smartdns/smartdns.conf
systemctl restart smartdns.service > /dev/null 2>&1
Start_status_smartdns
sleep 5
fi
rm -rf $HOME/smartdns.conf
rm -rf $HOME/smartdns.service
rm -rf $HOME/smartdns
}
#Clash安装
Clash_Install() {
#!/bin/bash
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
green "正在安装所需软件中，请稍等...."
apt install wget gzip unzip net-tools -y > /dev/null 2>&1
COUNT_clash=$(ps -ef |grep clash |grep -v "grep" |wc -l)
touch $HOME/clash.service
cat > $HOME/clash.service <<EOF
[Unit]
Description=a local HTTP/HTTPS/SOCKS server-Clash
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/clash -d /etc/clash/
Restart=always
RestartSec=10
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
Alias=clash.service
EOF
Start_status_clash() {
    clash_status=$(systemctl status clash.service | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$clash_status" == "running" ]; then
    echo -e "\033[32m\033[01m clash服务已正常启动！ \033[0m"
    else
    echo -e "\033[31m\033[01m 尝试启动clash服务未成功，请查找原因！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$clash_status \033[0m"
    sleep 5
    fi
}
#保存用户信息
Clash_Information_Save() {
touch /etc/clash/clash_information.log
echo "Clash 配置信息" > /etc/clash/clash_information.log
echo "代理节点名称（name）：$name" >> /etc/clash/clash_information.log
echo "代理类型（type）：vmess" >> /etc/clash/clash_information.log
echo "地址（address）: $netaddress" >> /etc/clash/clash_information.log
echo "端口（port）: 443" >> /etc/clash/clash_information.log
echo "用户id（UUID）：$UUID" >> /etc/clash/clash_information.log
echo "额外id（alterId）：$alterID" >> /etc/clash/clash_information.log
echo "加密方式（cipher）：auto" >> /etc/clash/clash_information.log
echo "传输协议（network）：ws" >> /etc/clash/clash_information.log
echo "路径（ws-path）：$path" >> /etc/clash/clash_information.log
echo "底层传输安全（tls）：true" >> /etc/clash/clash_information.log
}
if [ $COUNT_clash -eq 0 ]; then
green "clash未安装，开始安装...."
iptables -t nat -F
iptables -t nat -X
wget -t 0 -S -c https://github.com/Dreamacro/clash/releases/download/v0.18.0/clash-linux-amd64-v0.18.0.gz -O $HOME/clash.gz
wget -t 0 -S -c https://github.com/haishanh/yacd/archive/gh-pages.zip -O $HOME/gh-pages.zip
wget -t 0 -S -c https://geolite.clash.dev/Country.mmdb -O $HOME/Country.mmdb
gzip -d $HOME/clash.gz
mv -f $HOME/clash /usr/local/bin/clash
chmod 0755 /usr/local/bin/clash
setcap 'cap_net_admin=eip cap_net_bind_service=+eip' /usr/local/bin/clash
mkdir /etc/clash > /dev/null 2>&1
mv -f $HOME/Country.mmdb /etc/clash/Country.mmdb
unzip $HOME/gh-pages.zip
mv -f $HOME/yacd-gh-pages /etc/clash/dashboard
touch $HOME/config.yaml
green "================================================"
green "              输入V2ray服务器的信息              "
green "        默认使用tls跟WS,端口443，如果需要修改      "
green "      请到/etc/clash/config.yaml这个文件内修改    "
green "================================================="
green "==============================================="
green "为节点取个名字，随便取，只能是英文跟数字，不要带空格"
green "==============================================="
read name

network() {
 net_status=`curl -IL -s --connect-timeout 5 $netaddress -w %{http_code} |tail -n1` 
 if [ $net_status -eq 200 ];then 
 echo -e "\033[32m[ #########网络正常，继续安装############ ]\033[0m" 
 return 0
 else 
 echo -e "\033[31m\033[01m[######$netaddress###### ]\033[0m" 
 return 1
 fi
}


 green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
 green "==============================================="
 green "    服务器的地址：就是你申请的域名"
 green "==============================================="
 read netaddress
 network
while [ $? -eq 1 ]
do
red "===================================================="
red "   网址输入错误，无法ping通，请检测你输入的网址，重新输入"
red "===================================================="
read netaddress
network
done
green "================================"
green "     v2ray的UUID，最长的那一串   "
green "================================"
read UUID

green "==========================================="
green "   alterID，一般采用64，如果不清楚，填的数字  "
green "    一定要小于服务器的，如6、8、20之类的"
green "==========================================="
read alterID

green "========================================="
green "     ws-path，注意查看服务器给出的数值     "
green "        一定要填对，不然上不了网           "
green "========================================="
read path

ethernetnum_clash=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')

cat > $HOME/config.yaml <<EOF
{ port: 7890,
  'socks-port': 7891,
  'redir-port': 7892,
  'allow-lan': true,
  mode: 'Rule',
  'log-level': 'info',
  'external-controller': '0.0.0.0:9090',
  'external-ui': '/etc/clash/dashboard',
  secret: '',
  experimental: { 'ignore-resolve-fail': true },
  dns:
   { enable: true,
     ipv6: false,
     listen: '127.0.0.1:5353',
     'enhanced-mode': 'redir-host',
     nameserver:
      [ 'tls://9.9.9.9:853',
        'tls://9.9.9.10:853',
        'tls://1.1.1.1:853',
        'tls://1.0.0.1:853',
        'tls://8.8.8.8:853',
        'tls://8.8.4.4:853',
        'tls://185.228.168.9:853',
        'tls://185.228.169.9:853',
        'tls://dns.adguard.com:853' ],
     fallback:
      [ 'https://cloudflare-dns.com/dns-query',
        'https://mozilla.cloudflare-dns.com/dns-query',
        'https://dns.google/dns-query',
        'https://dns.quad9.net/dns-query',
        'https://dns9.quad9.net/dns-query',
        'https://dns10.quad9.net/dns-query',
        'https://dns11.quad9.net/dns-query',
        'https://doh.cleanbrowsing.org/doh/security-filter/',
        'https://doh.xfinity.com/dns-query' ],
      fallback-filter:
              { geoip: true, ipcidr: [ '240.0.0.0/4' ] },
      experimental: { 'interface-name': '$ethernetnum_clash' } },
    Proxy:
    [ { name: '$name',
        type: 'vmess',
        server: '$netaddress',
        port: 443,
        uuid: '$UUID',
        alterId: $alterID,
        cipher: 'auto',
        tls: true,
        network: 'ws',
        'ws-path': '$path' },
        #Netease Music VPS
        { name: 'Unblock',
        type: 'ss',
        server: 'music.desperadoj.com',
        port: 30001,
        cipher: 'aes-128-gcm',
        password: 'desperadoj.com' } ],
    'Proxy Group':
    [ { name: 'UrlTest',
        type: 'url-test',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'Fallback',
        type: 'fallback',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'LoadBalance',
        type: 'load-balance',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'PROXY',
        type: 'select',
        proxies:
            [ 'UrlTest',
            '$name' ] },
        { name: 'Final', type: 'select', proxies: [ 'PROXY', 'DIRECT' ] },
        #Netease Music rule
        { name: 'Netease Music',
        type: 'select',
        proxies: [ 'Unblock', 'DIRECT' ] } ],
       Rule: 
        [# Unblock Netease Music
        'IP-CIDR,39.105.63.80/32, Netease Music',
        'IP-CIDR,45.254.48.1/32, Netease Music',
        'IP-CIDR,47.100.127.239/32, Netease Music',
        'IP-CIDR,59.111.160.195/32, Netease Music',
        'IP-CIDR,59.111.160.197/32, Netease Music',
        'IP-CIDR,59.111.181.60/32, Netease Music',
        'IP-CIDR,101.71.154.241/32, Netease Music',
        'IP-CIDR,103.126.92.132/32, Netease Music',
        'IP-CIDR,103.126.92.133/32, Netease Music',
        'IP-CIDR,112.13.119.17/32, Netease Music',
        'IP-CIDR,112.13.122.1/32, Netease Music',
        'IP-CIDR,115.236.118.33/32, Netease Music',
        'IP-CIDR,115.236.121.1/32, Netease Music',
        'IP-CIDR,118.24.63.156/32, Netease Music',
        'IP-CIDR,193.112.159.225/32, Netease Music',
        'IP-CIDR,223.252.199.66/32, Netease Music',
        'IP-CIDR,223.252.199.67/32, Netease Music',
        # Unblock Netease Music End
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,100.64.0.0/10,DIRECT',
        'IP-CIDR,119.28.28.28/32,DIRECT,no-resolve',
        'GEOIP,CN,DIRECT',
        'MATCH,Final' ] }
EOF
Clash_Information_Save
mv -f $HOME/config.yaml /etc/clash/config.yaml
chmod 0640 /etc/clash/config.yaml
mv -f $HOME/clash.service /lib/systemd/system/clash.service
rm -rf $HOME/gh-pages.zip
systemctl daemon-reload > /dev/null 2>&1
systemctl enable clash.service > /dev/null 2>&1
systemctl start clash.service > /dev/null 2>&1
Start_status_clash
sleep 5
else
red "clash已安装，跳过安装,更新配置文件中...."
touch $HOME/config.yaml
green "================================================"
green "              输入V2ray服务器的信息              "
green "        默认使用tls跟WS,端口443，如果需要修改      "
green "      请到/etc/clash/config.yaml这个文件内修改    "
green "================================================="

green "==============================================="
green "服务器的名字，随便取，只能是英文跟数字，不要带空格"
green "==============================================="
read name

network() {
 net_status=`curl -IL -s --connect-timeout 5 $netaddress -w %{http_code} |tail -n1` 
 if [ $net_status -eq 200 ];then 
 echo -e "\033[32m[ #########网络正常，继续安装############ ]\033[0m" 
 return 0
 else 
 echo -e "\033[31m\033[01m[######$netaddress###### ]\033[0m" 
 return 1
 fi
}
 green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
 green "==============================================="
 green "    服务器的地址：就是你申请的域名"
 green "==============================================="
 read netaddress
 network
while [ $? -eq 1 ]
do
red "===================================================="
red "   网址输入错误，无法ping通，请检测你输入的网址，重新输入"
red "===================================================="
read netaddress
network
done
green "================================"
green "     v2ray的UUID，最长的那一串   "
green "================================"
read UUID

green "==========================================="
green "   alterID，一般采用64，如果不清楚，填的数字  "
green "    一定要小于服务器的，如6、8、20之类的"
green "==========================================="
read alterID

green "========================================="
green "     ws-path，注意查看服务器给出的数值     "
green "        一定要填对，不然上不了网           "
green "========================================="
read path

ethernetnum_clash=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')

cat > $HOME/config.yaml <<EOF
{ port: 7890,
  'socks-port': 7891,
  'redir-port': 7892,
  'allow-lan': true,
  mode: 'Rule',
  'log-level': 'info',
  'external-controller': '0.0.0.0:9090',
  'external-ui': '/etc/clash/dashboard',
  secret: '',
  experimental: { 'ignore-resolve-fail': true },
  dns:
   { enable: true,
     ipv6: false,
     listen: '127.0.0.1:5353',
     'enhanced-mode': 'redir-host',
     nameserver:
      [ 'tls://9.9.9.9:853',
        'tls://9.9.9.10:853',
        'tls://1.1.1.1:853',
        'tls://1.0.0.1:853',
        'tls://8.8.8.8:853',
        'tls://8.8.4.4:853',
        'tls://185.228.168.9:853',
        'tls://185.228.169.9:853',
        'tls://dns.adguard.com:853' ],
     fallback:
      [ 'https://cloudflare-dns.com/dns-query',
        'https://mozilla.cloudflare-dns.com/dns-query',
        'https://dns.google/dns-query',
        'https://dns.quad9.net/dns-query',
        'https://dns9.quad9.net/dns-query',
        'https://dns10.quad9.net/dns-query',
        'https://dns11.quad9.net/dns-query',
        'https://doh.cleanbrowsing.org/doh/security-filter/',
        'https://doh.xfinity.com/dns-query' ],
      fallback-filter:
              { geoip: true, ipcidr: [ '240.0.0.0/4' ] },
      experimental: { 'interface-name': '$ethernetnum_clash' } },
    Proxy:
    [ { name: '$name',
        type: 'vmess',
        server: '$netaddress',
        port: 443,
        uuid: '$UUID',
        alterId: $alterID,
        cipher: 'auto',
        tls: true,
        network: 'ws',
        'ws-path': '$path' },
        #Netease Music VPS
        { name: 'Unblock',
        type: 'ss',
        server: 'music.desperadoj.com',
        port: 30001,
        cipher: 'aes-128-gcm',
        password: 'desperadoj.com' } ],
    'Proxy Group':
    [ { name: 'UrlTest',
        type: 'url-test',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'Fallback',
        type: 'fallback',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'LoadBalance',
        type: 'load-balance',
        proxies:
            [ '$name' ],
        url: 'http://www.gstatic.com/generate_204',
        interval: 300 },
        { name: 'PROXY',
        type: 'select',
        proxies:
            [ 'UrlTest',
            '$name' ] },
        { name: 'Final', type: 'select', proxies: [ 'PROXY', 'DIRECT' ] },
        #Netease Music rule
        { name: 'Netease Music',
        type: 'select',
        proxies: [ 'Unblock', 'DIRECT' ] } ],
       Rule: 
        [# Unblock Netease Music
        'IP-CIDR,39.105.63.80/32, Netease Music',
        'IP-CIDR,45.254.48.1/32, Netease Music',
        'IP-CIDR,47.100.127.239/32, Netease Music',
        'IP-CIDR,59.111.160.195/32, Netease Music',
        'IP-CIDR,59.111.160.197/32, Netease Music',
        'IP-CIDR,59.111.181.60/32, Netease Music',
        'IP-CIDR,101.71.154.241/32, Netease Music',
        'IP-CIDR,103.126.92.132/32, Netease Music',
        'IP-CIDR,103.126.92.133/32, Netease Music',
        'IP-CIDR,112.13.119.17/32, Netease Music',
        'IP-CIDR,112.13.122.1/32, Netease Music',
        'IP-CIDR,115.236.118.33/32, Netease Music',
        'IP-CIDR,115.236.121.1/32, Netease Music',
        'IP-CIDR,118.24.63.156/32, Netease Music',
        'IP-CIDR,193.112.159.225/32, Netease Music',
        'IP-CIDR,223.252.199.66/32, Netease Music',
        'IP-CIDR,223.252.199.67/32, Netease Music',
        # Unblock Netease Music End
        'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT',
        'IP-CIDR,172.16.0.0/12,DIRECT',
        'IP-CIDR,127.0.0.0/8,DIRECT',
        'IP-CIDR,100.64.0.0/10,DIRECT',
        'IP-CIDR,119.28.28.28/32,DIRECT,no-resolve',
        'GEOIP,CN,DIRECT',
        'MATCH,Final' ] }
EOF
Clash_Information_Save
rm-rf /etc/clash/config.yaml
mv -f $HOME/config.yaml /etc/clash/config.yaml
chmod 0640 /etc/clash/config.yaml
rm -rf $HOME/clash.service
fi
}
#AdGuardHome安装
AdGuard_Install() {
#!/bin/bash
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
green "正在安装所需软件中，请稍等...."
apt install wget apache2-utils net-tools tar -y > /dev/null 2>&1
COUNT_AdGuard=$(ps -ef |grep AdGuardHome |grep -v "grep" |wc -l)
status_Aduard=$(systemctl status AdGuardHome | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
Start_status_AdGuard() {
    AdGuard_status=$(systemctl status AdGuardHome | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$AdGuard_status" == "running" ]; then
    echo -e "\033[32m\033[01m AdGuardHome服务已正常启动！ \033[0m"
    else
    echo -e "\033[31m\033[01m 尝试启动AdGuardHome服务未成功，请查找原因！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$AdGuard_status \033[0m"
    sleep 5
    fi
}
if [[ $COUNT_AdGuard -eq 0 ]] && [[ "$status_Aduard" != "auto-restart" ]]; then
green "AdGuardHome未安装，开始安装...."
wget -t 0 -S -c https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz -O $HOME/AdGuardHome_linux_amd64.tar.gz
cd $HOME
tar -zxvf $HOME/AdGuardHome_linux_amd64.tar.gz
$HOME/AdGuardHome/AdGuardHome -s install > /dev/null 2>&1
setcap CAP_NET_BIND_SERVICE=+eip $HOME/AdGuardHome/AdGuardHome
ethernetnum_Ad=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
localaddr_Ad=$(ip a | grep "$ethernetnum_Ad" | awk '{print $2}' | awk 'END {print}' | cut -d'/' -f1)
green "===================================="
green "     AdGuardHome的用户名         "
green "===================================="
read adname

green "==================================="
green "     AdGuardHome的用户密码         "
green "==================================="
read adpassword

htpasswd -B -n -b $adname $adpassword > $HOME/tmp
adpasswordhash=$(awk 'BEGIN{ FS=":"} {print $NF}' $HOME/tmp)

cat > $HOME/AdGuardHome/AdGuardHome.yaml <<EOF
bind_host: $localaddr_Ad
bind_port: 80
users:
- name: $adname
  password: $adpasswordhash
language: ""
rlimit_nofile: 0
web_session_ttl: 720
dns:
  bind_host: 0.0.0.0
  port: 53
  statistics_interval: 1
  querylog_enabled: true
  querylog_interval: 90
  querylog_memsize: 0
  protection_enabled: true
  blocking_mode: null_ip
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 60
  ratelimit: 0
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 127.0.0.1:5354
  all_servers: false
  edns_client_subnet: false
  aaaa_disabled: false
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  cache_size: 4194304
  upstream_dns:
  - 127.0.0.1:5354
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  rewrites: []
  blocked_services: []
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  allow_unencrypted_doh: false
  strict_sni_check: false
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://hosts-file.net/ad_servers.txt
  name: hpHosts - Ad and Tracking servers only
  id: 3
- enabled: true
  url: https://www.malwaredomainlist.com/hostslist/hosts.txt
  name: MalwareDomainList.com Hosts List
  id: 4
whitelist_filters: []
user_rules:
- '#netease music unblock'
- '||admusicpic.music.126.net^$important'
- '||iadmat.nosdn.127.net^$important'
- '||iadmusicmat.music.126.net^$important'
- '||iadmusicmatvideo.music.126.net^$important'
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000
clients: []
log_file: ""
verbose: false
schema_version: 6
EOF
chmod 0755 $HOME/AdGuardHome/AdGuardHome.yaml
$HOME/AdGuardHome/AdGuardHome -s restart > /dev/null 2>&1
rm -rf $HOME/AdGuardHome_linux_amd64.tar.gz
rm -rf $HOME/tmp
Start_status_AdGuard
sleep 5
elif [ "$status_Aduard" == "auto-restart" ]; then
red "AdGuardHome服务处于自动重启状态，请查找原因！"
sleep 5
else
ethernetnum_Ad=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
localaddr_Ad=$(ip a | grep "$ethernetnum_Ad" | awk '{print $2}' | awk 'END {print}' | cut -d'/' -f1)
green "AdGuardHome服务处于运行状态，可通过网页界面自动更新！"
green "请登录http://$localaddr_Ad自行更新配置"
green "如提示失败，可尝试输入http://$localaddr_Ad:3000查看能否登录"
sleep 5
fi
}
#更改AdGuardHome用户名及密码
AdGuardHome_PasswordChanged() {
green "正在安装所需软件中，请稍等...."
apt update > /dev/null 2>&1
apt install apache2-utils net-tools -y > /dev/null 2>&1
Start_status_AdGuard_CP() {
    AdGuard_status_CP=$(systemctl status AdGuardHome | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$AdGuard_status_CP" == "running" ]; then
    echo -e "\033[32m\033[01m AdGuardHome用户名及密码已更改！ \033[0m"
    green "请重新登录http://$localaddr_Ad_CP"
    green "如提示失败，可尝试输入http://$localaddr_Ad_CP:3000查看能否登录"
    sleep 5
    else
    echo -e "\033[31m\033[01m 尝试启动AdGuardHome服务未成功，请查找原因！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$AdGuard_status_CP \033[0m"
    sleep 5
    fi
}
ethernetnum_Ad_CP=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
localaddr_Ad_CP=$(ip a | grep "$ethernetnum_Ad_CP" | awk '{print $2}' | awk 'END {print}' | cut -d'/' -f1)

green "===================================="
green "     AdGuardHome的新用户名         "
green "===================================="
read adname_new

green "==================================="
green "     AdGuardHome的用户密码         "
green "==================================="
read adpassword_new

htpasswd -B -n -b $adname_new $adpassword_new > $HOME/tmp_new
adpasswordhash_new=$(awk 'BEGIN{ FS=":"} {print $NF}' $HOME/tmp_new)
chmod 0755 $HOME/AdGuardHome/AdGuardHome.yaml
sed -i "/^- name:/c- name: $adname_new" $HOME/AdGuardHome/AdGuardHome.yaml
sed -i "/^  password:/c\  \password: $adpasswordhash_new" $HOME/AdGuardHome/AdGuardHome.yaml
$HOME/AdGuardHome/AdGuardHome -s restart > /dev/null 2>&1
rm -rf $HOME/tmp_new
Start_status_AdGuard_CP
}
#IP地址变更后更换IP
AdGuardHome_IPChanged() {
green "正在安装所需软件中，请稍等...."
apt update > /dev/null 2>&1
apt install net-tools -y > /dev/null 2>&1
Start_status_AdGuard_CIP() {
    AdGuard_status_CIP=$(systemctl status AdGuardHome | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [ "$AdGuard_status_CIP" == "running" ]; then
    echo -e "\033[32m\033[01m IP地址更换成功，并已切换成静态IP！ \033[0m"
    sleep 5
    else
    echo -e "\033[31m\033[01m 尝试启动服务未成功，IP地址更新失败！ \033[0m"
    echo -e "\033[31m\033[01m 服务目前状态：$AdGuard_status_CIP \033[0m"
    sleep 5
    fi
}
ethernetnum_Ad_CIP=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
localaddr_Ad_CIP=$(ip a | grep "$ethernetnum_Ad_CIP" | awk '{print $2}' | awk 'END {print}' | cut -d'/' -f1)

chmod 0755 $HOME/AdGuardHome/AdGuardHome.yaml
sed -i "/^bind_host: /c bind_host: $localaddr_Ad_CIP" $HOME/AdGuardHome/AdGuardHome.yaml
$HOME/AdGuardHome/AdGuardHome -s restart  > /dev/null 2>&1
Start_status_AdGuard_CIP
}
#配置IP转发\优化软路由性能\更改BASH颜色
IP_Forward() {
green "正在安装所需软件中，请稍等...."
apt install net-tools -y > /dev/null 2>&1
#安装路由表，开启转发
iptables -t nat -N clash
iptables -t nat -A PREROUTING -p tcp -j clash
iptables -t nat -A clash -p tcp -j REDIRECT --to-ports 7892
iptables -t nat -A clash -d 0.0.0.0/8 -j RETURN
iptables -t nat -A clash -d 10.0.0.0/8 -j RETURN
iptables -t nat -A clash -d 127.0.0.0/8 -j RETURN
iptables -t nat -A clash -d 169.254.0.0/16 -j RETURN
iptables -t nat -A clash -d 172.16.0.0/12 -j RETURN
iptables -t nat -A clash -d 192.168.0.0/16 -j RETURN
iptables -t nat -A clash -d 224.0.0.0/4 -j RETURN
iptables -t nat -A clash -d 240.0.0.0/4 -j RETURN
ethernetnum=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')
iptables -t nat -A POSTROUTING -o $ethernetnum -j MASQUERADE
isIptablesPersistentInstalled=$(dpkg-query -l | grep -w "iptables-persistent" |wc -l)
if [ $isIptablesPersistentInstalled -eq 0 ]; then
echo -e "\033[32m\033[01m iptables-persistent未安装，正在安装...\033[0m"
echo -e "\033[32m\033[01m安装过程中跳出确认窗口请直接选择\033[0m\033[31m\033[01m [YES] 确认 \033[0m "
sleep 8
apt install iptables-persistent -y > /dev/null 2>&1
else
echo -e "\033[32m\033[01m iptables-persistent已安装，保存规则中...\033[0m"
sleep 2
netfilter-persistent save > /dev/null 2>&1
fi
cat >/etc/security/limits.conf <<EOF
* soft nofile 655350
* hard nofile 655350
* soft nproc 655350
* hard nproc 655350
EOF
#网络优化
cat >> /etc/sysctl.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 32768 8388608
net.ipv4.tcp_mem = 94500000 91500000 92700000
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.ip_forward = 1
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 873200
net.core.wmem_max = 873200
kernel.panic = 1
net.ipv4.ip_default_ttl = 64
net.ipv4.tcp_window_scaling = 1
EOF
sysctl -p > /dev/null 2>&1
#更改bash颜色
cat > $HOME/.bash_profile <<EOF
export PS1="\e[1;32m[\e[m\e[0;33m\u@\h \e[m\e[0;31m\W \e[m\e[1;32m\A]>\\$" 
EOF
}
network_check() {
 git_status=`curl -I -s --connect-timeout 5 https://github.com/ -w %{http_code} |tail -n1` 
 if [ $git_status -eq 200 ];then 
 return 0
 else 
 return 1
 fi
}
#判断各个服务的运行状态
Service_Status() {
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
cat >/etc/default/locale <<EOF
LANG=en_US.UTF-8
LANGUAGE=en_US.UTF-8
LC_CTYPE="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LC_TIME="en_US.UTF-8"
LC_COLLATE="en_US.UTF-8"
LC_MONETARY="en_US.UTF-8"
LC_MESSAGES="en_US.UTF-8"
LC_PAPER="en_US.UTF-8"
LC_NAME="en_US.UTF-8"
LC_ADDRESS="en_US.UTF-8"
LC_TELEPHONE="en_US.UTF-8"
LC_MEASUREMENT="en_US.UTF-8"
LC_IDENTIFICATION="en_US.UTF-8"
LC_ALL=en_US.UTF-8
EOF
locale-gen en_US.UTF-8 > /dev/null 2>&1

statusGOOD=$(green "✓")
statusBAD=$(red "✕")

if [[ $(systemctl is-active clash.service) = "active" ]]; then
    echo "[$statusGOOD] Clash          [运行正常]"
elif [[ ! -f "/usr/local/bin/clash" ]]; then
    echo "[$statusBAD] Clash           [未安装]"
else
    echo "[$statusBAD] Clash           [启动失败]"
fi

if [[ $(systemctl is-active AdGuardHome) = "active" ]]; then
    echo "[$statusGOOD] AdGuardHome     [运行正常]"
elif [[ ! -f "/root/AdGuardHome/AdGuardHome" ]]; then
    echo "[$statusBAD] AdGuardHome     [未安装]"
else
    echo "[$statusBAD] AdGuardHome     [启动失败]"
fi

if [[ $(systemctl is-active unbound) = "active" ]]; then
    echo "[$statusGOOD] unbound         [运行正常]"
elif [[ ! -f "/usr/sbin/unbound" ]]; then
    echo "[$statusBAD] unbound         [未安装]"
else
    echo "[$statusBAD] unbound         [启动失败]"
fi

if [[ $(systemctl is-active smartdns.service) = "active" ]]; then
    echo "[$statusGOOD] SmartDNS        [运行正常]"
elif [[ ! -f "/usr/sbin/smartdns" ]]; then
    echo "[$statusBAD] SmartDNS        [未安装]"
else
    echo "[$statusBAD] SmartDNS        [启动失败]"
fi
}
#显示Clash配置信息
Clash_Information_Show() {
cat /etc/clash/clash_information.log | while read line
do
	echo -e "\033[32m\033[01m $line \033[0m"
done
}
#脚本由此处开始执行
red() { echo -e "\033[31m\033[01m $1 \033[0m"; }
green() { echo -e "\033[32m\033[01m $1 \033[0m"; }
green "请稍等，正在检测网络环境能否连接github下载相关软件进行安装...."
apt update > /dev/null 2>&1 && apt install curl -y > /dev/null 2>&1
network_check
if [ $? -eq 1 ]; then
red "无法连接github,请检查网络后重试，准备退出脚本"
exit 1
else
green "===================================================================="
green "Clash+AdGuardHome+unbound+smartdns一键安装脚本 by hank 2020-3-17 "
green "        已于Debian 10与Ubuntu 18.04下测试通过"
green "注意：本脚本并不适用于CentOS系统,安装过程中需要root用户，"
green "        如非root用户将自动退出,请切换至root用户安装"                        
green "本脚本使用Clash代理V2ray流量翻墙,只适用于WS+TLS类型，"
green "      需要已注册好域名并可以正常解析"
green "特点：AdGuardHome作为DNS服务器最下游，开放53端口，处理本地DNS请求,"
green "    AdGuardHome上游unbound作为DNS分流服务器，监听5354端口，"
green "如为国内流量,则交给SmartDNS进行查询，SmartDNS监听5355端口，"
green "   如为国外流量则交给Clash进行查询，Clash监听5353端口。" 
green "====================================================================="
green "  各软件当前状态   "
Service_Status
while :
do
    green    "请选择需要安装的功能"
    green "============================================="
    green " 1：一键安装Clash+AdGuradHome+unbound+smartdns"
    green " 2： 显示Clash翻墙配置的具体信息   "
    green " 3： 更新Clash配置文件  "
    green " 4： 忘记AdGuardHome登录用户名及密码，重新设置"
    green " 5:  我的IP地址变动，需要更换IP"
    green " q:  退出脚本"
    green "============================================="
    read -p"请输入：" input
    case $input in
        1)
        green "开始安装"
        pre_Install
        Time_UTC8
        IP_Static
        Clash_Install
        Smartdns_Install
        Unbound_Install
        AdGuard_Install
        IP_Forward
        Service_Status
        ;;
        2)
        Clash_Information_Show
        ;;
        3)
        green "请稍等...."
        apt update -y > /dev/null 2>&1
        Clash_Install
        IP_Forward
        green "Clash配置文件已更新，请输入reboot重启系统生效"
        sleep 5
        ;;
        4)
        AdGuardHome_PasswordChanged
        ;;
        5)
        IP_Static
        AdGuardHome_IPChanged
        ;;
        q|Q) exit
        ;;
    esac
done
fi
#更为UTF-8，显示中文，判断是否为root 判断系统类型，不符合要求不安装，更新国内源，更新软件包，安装wget
#pre_Install
#将时间更新为北京时间，因内含wget，判断wget是否存在，如不存在，则安装
#Time_UTC8
#改为静态IP并回显信息 安装net-tools
#IP_Static
#安装unbound
#Unbound_Install
#安装smartdns
#Smartdns_Install
#安装clash
#Clash_Install
#安装adguradhome
#AdGuard_Install
#配置IP转发\优化软路由性能\更改BASH颜色
#IP_Forward