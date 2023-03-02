#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo "\ Linux emergency response/information collection/vulnerability detection script V2.3/"
echo " ========================================================= "
echo "# Support Centos, Debian system detection"
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo "# Update date: August 5, 2022"
echo "# Reference source: "
echo " #   1.Gscan https://github.com/grayddq/GScan  "
echo " #   2.Lynis https://github.com/CISOfy/lynis  "
echo -e "\n"

# Update log: August 05, 2022
#### Fix too many kernel module check logs
# Update log: March 07, 2022
#### Add SSH soft connection backdoor detection
# Updated date: October 17, 2021
#### Add Ntpclient/WorkMiner/TeamTNT mining Trojan detection
#### Add Rootkit module detection logic
#### Add Python pip poisoning detection
#### Add $HOME/.profile View
#### Add server risk check (Redis)

# WEB Path If you set the web directory by default, the search performance from the / directory is slow
webpath='/'

print_msg() {
  echo -e "\e[00;31m[+]$1\e[00m"
}

### 1. Environment Check###
print_msg "Environment detection"
# Verify that it is root privileges
if [ $UID -ne 0 ]; then
  print_msg "Please run with root privileges!"
  exit 1
else
  print_msg "Currently root authority"
be

# Verify that the operating system is debian or centos
OS='None'

if [ -e "/etc/os-release" ]; then
  source /etc/os-release
  case ${ID} in
  "debian" | "ubuntu" | "devuan")
    OS='Debian'
    ;;
  "centos" | "rhel fedora" | "rhel")
    OS='Hundreds'
    ;;
  *) ;;
  esac
be

if [ $OS = 'None' ]; then
  if command -v apt-get >/dev/null 2>&1; then
    OS='Debian'
  elif command -v yum >/dev/null 2>&1; then
    OS='Hundreds'
  else
    echo -e "\nThis system is not supported\n"
    echo -e "exited"
    exit 1
  be
be

# Install emergency tools
cmdline=(
  "net-tools"
  "telnet"
  "nc"
  "lrzsz"
  "wget"
  "strace"
  "traceroute"
  "htop"
  "tar"
  "lsof"
  "tcpdump"
)
for prog in "${cmdline[@]}"; do

  if [ $OS = 'Centos' ]; then
    soft=$(rpm -q "$prog")
    if echo "$soft" | grep -E 'not installed|not installed|not installed' >/dev/null 2>&1; then
      echo -e "$prog Installing..."
      yum install -y "$prog" >/dev/null 2>&1
      yum install -y the_silver_searcher >/dev/null 2>&1
    be
  else
    if dpkg -L $prog | grep 'does not contain any files' >/dev/null 2>&1; then
      echo -e "$prog Installing..."
      apt install -y "$prog" >/dev/null 2>&1
      apt install -y silversearcher-ag >/dev/null 2>&1
    be

  be
done

echo -e "\n"

# set save file
ipaddress=$(ip address | ag -o '(?<=inet )\d+\.\d+\.\d+\.\d+(?=\/2)' | head -n 1)
filename=$ipaddress'_'$(hostname)'_'$(whoami)'_'$(date +%s)_log'.log'
vuln="$ipaddress_$(hostname)_$(whoami)_$(date +%s)_vuln.log"

base_check() {
  echo -e "############ basic configuration check #############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]system information\e[00m" | tee -a "$filename"
  #Current user
  echo -e "USER:\t\t$(whoami)" 2>/dev/null | tee -a "$filename"
  #Version Information
  echo -e "OS Version:\t$(uname -r)" | tee -a "$filename"
  #CPU name
  echo -e "Hostname: \t$(hostname -s)" | tee -a "$filename"
  #serverSN
  echo -e "服务器SN: \t$(dmidecode -t1 | ag -o '(?<=Serial Number: ).*')" | tee -a "$filename"
  #uptime
  echo -e "Uptime: \t$(uptime | awk -F ',' '{print $1}')" | tee -a "$filename"
  # system load
  echo -e "系统负载: \t$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')" | tee -a "$filename"
  #cpu information
  echo -e "CPU info:\t$(ag -o '(?<=model name\t: ).*' </proc/cpuinfo | head -n 1)" | tee -a "$filename"
  #cpu core
  echo -e "CPU 核心:\t$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)" | tee -a "$filename"
  #ipaddress
  ipaddress=$(ifconfig | ag -o '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1') >/dev/null 2>&1
  echo -e "IPADDR:\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]CPU使用率:  \e[00m" | tee -a "$filename"
  awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
    echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
        print$1" Free "free/total*100"%",\
        "Used " (total-free)/total*100"%"}' | tee -a "$filename"
  done
  echo -e "\n" | tee -a "$filename"
  #login user
  echo -e "\e[00;31m[+] login user\e[00m" | tee -a "$filename"
  who | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #CPU usage TOP 15
  cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -15) 2>/dev/null
  echo -e "\e[00;31m[+]CPU TOP15:  \e[00m\n${cpu}\n" | tee -a "$filename"
  #Memory usage TOP 15
  mem=$(ps aux | grep -v ^'USER' | sort -rn -k4 | head -15) 2>/dev/null
  echo -e "\e[00;31m[+] memory usage TOP15: \e[00m\n${mem}\n" | tee -a "$filename"
  #Memory usage
  echo -e "\e[00;31m[+] memory usage\e[00m" | tee -a "$filename"
  free -mh | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #remaining space
  echo -e "\e[00;31m[+] remaining space\e[00m" | tee -a "$filename"
  df -mh | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]hard disk mount\e[00m" | tee -a "$filename"
  ag -v "#" </etc/fstab | awk '{print $1,$2,$3}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #install software
  echo -e "\e[00;31m[+]Common software\e[00m" | tee -a "$filename"
  cmdline=(
    "which perl"
    "which gcc"
    "which g++"
    "which python"
    "which php"
    "which cc"
    "which go"
    "which node"
    "which nodejs"
    "which bind"
    "which tomcat"
    "which clang"
    "which ruby"
    "which curl"
    "which wget"
    "which mysql"
    "which redis"
    "which ssserver"
    "which vsftpd"
    "which java"
    "which apache"
    "which apache2"
    "which nginx"
    "which git"
    "which mongodb"
    "which docker"
    "which tftp"
    "which psql"
    "which kafka"

  )

  for prog in "${cmdline[@]}"; do
    soft=$($prog)
    if [ "$soft" ] 2>/dev/null; then
      echo -e "$soft" | ag -o '\w+$' --nocolor | tee -a "$filename"
    be
  done
  echo -e "\n" | tee -a "$filename"
  #HOSTS
  echo -e "\e[00;31m[+]/etc/hosts \e[00m" | tee -a "$filename"
  cat /etc/hosts | ag -v "#" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

network_check() {
  echo -e "############ Network/Traffic Check############\n" | tee -a "$filename"
  #ifconfig
  echo -e "\e[00;31m[+]ifconfig\e[00m" | tee -a "$filename"
  /sbin/ifconfig -a | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Network traffic
  echo -e "\e[00;31m[+]network traffic\e[00m" | tee -a "$filename"
  echo "Interface    ByteRec   PackRec   ByteTran   PackTran" | tee -a "$filename"
  awk ' NR>2' /proc/net/dev | while read line; do
    echo "$line" | awk -F ':' '{print "  "$1"  " $2}' |
      awk '{print $1"   "$2 "    "$3"   "$10"  "$11}' | tee -a "$filename"
  done
  echo -e "\n" | tee -a "$filename"
  #Port monitoring
  echo -e "\e[00;31m[+]port listening\e[00m" | tee -a "$filename"
  netstat -tulpen | ag 'tcp|udp.*' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  # open port
  echo -e "\e[00;31m[+] open port\e[00m" | tee -a "$filename"
  netstat -tulpen | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)|:::\d+' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Internet connection
  echo -e "\e[00;31m[+]network connection\e[00m" | tee -a "$filename"
  netstat -antop | ag ESTAB --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Connection Status
  echo -e "\e[00;31m[+]TCP connection status\e[00m" | tee -a "$filename"
  netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #routing table
  echo -e "\e[00;31m[+]routing table\e[00m" | tee -a "$filename"
  /sbin/route -nee | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #routing forwarding
  echo -e "\e[00;31m[+]routing and forwarding\e[00m" | tee -a "$filename"
  ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
  if [ -n "$ip_forward" ]; then
    echo "/proc/sys/net/ipv4/ip_forward has enabled route forwarding" | tee -a "$filename"
  else
    echo "The server has not enabled routing and forwarding" | tee -a "$filename"
  be
  echo -e "\n" | tee -a "$filename"
  #DNS
  echo -e "\e[00;31m[+]DNS Server\e[00m" | tee -a "$filename"
  ag -o '\d+\.\d+\.\d+\.\d+' --nocolor </etc/resolv.conf | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #ARP
  echo -e "\e[00;31m[+]ARP\e[00m" | tee -a "$filename"
  arp -n -a | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  # promiscuous mode
  echo -e "\e[00;31m[+]Network card promiscuous mode\e[00m" | tee -a "$filename"
  if ip link | ag PROMISC >/dev/null 2>&1; then
    echo "The NIC has promiscuous mode!" | tee -a "$filename"
  else
    echo "NIC does not have promiscuous mode" | tee -a "$filename"

  be
  echo -e "\n" | tee -a "$filename"
  #firewall
  echo -e "\e[00;31m[+]IPTABLES firewall\e[00m" | tee -a "$filename"
  iptables -L | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

crontab_check() {
  echo -e "############ Task Plan Check #############\n" | tee -a "$filename" | tee -a "$vuln"
  #crontab
  echo -e "\e[00;31m[+]Crontab\e[00m" | tee -a "$filename"
  crontab -u root -l | ag -v '#' --nocolor | tee -a "$filename"
  ls -alht /etc/cron.*/* | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"

  #crontab Suspicious Commands
  echo -e "\e[00;31m[+]Crontab Backdoor \e[00m" | tee -a "$vuln"
  ag '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' /etc/cron* /var/spool/cron/* --nocolor | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

env_check() {
  echo -e "############ environment variable check #############\n" | tee -a "$filename"
  #env
  echo -e "\e[00;31m[+]env\e[00m" | tee -a "$filename"
  env | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #PATH
  echo -e "\e[00;31m[+]PATH\e[00m" | tee -a "$filename"
  echo "$PATH" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #LD_PRELOAD
  echo -e "\e[00;31m[+]LD_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_ELF_PRELOAD
  echo -e "\e[00;31m[+]LD_ELF_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_ELF_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_AOUT_PRELOAD
  echo -e "\e[00;31m[+]LD_AOUT_PRELOAD\e[00m" | tee -a "$vuln"
  echo ${LD_AOUT_PRELOAD} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #PROMPT_COMMAND
  echo -e "\e[00;31m[+]PROMPT_COMMAND\e[00m" | tee -a "$vuln"
  echo "${PROMPT_COMMAND}" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #LD_LIBRARY_PATH
  echo -e "\e[00;31m[+]LD_LIBRARY_PATH\e[00m" | tee -a "$vuln"
  echo "${LD_LIBRARY_PATH}" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #ld.so.preload
  echo -e "\e[00;31m[+]ld.so.preload\e[00m" | tee -a "$vuln"
  preload='/etc/ld.so.preload'
  if [ -e "${preload}" ]; then
    cat ${preload} | tee -a "$vuln"
  be
  echo -e "\n" | tee -a "$vuln"
}

user_check() {
  echo -e "############ User Information Check #############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+] can log in user\e[00m" | tee -a "$filename"
  cat /etc/passwd | ag -v 'nologin$|false$' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]passwd file modification date: \e[00m" $(stat /etc/passwd | ag -o '(?<=Modify: ).*' --nocolor) | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]sudoers(note NOPASSWD)\e[00m" | tee -a "$filename"
  cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]login information\e[00m" | tee -a "$filename"
  w | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  last | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  lastlog | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo "登陆ip: $(ag -a accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq)" | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

service_check() {
  echo -e "############ Service Status Check #############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]Running Service \e[00m" | tee -a "$filename"
  systemctl -l | grep running | awk '{print $1}' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]Recently added Service \e[00m" | tee -a "$filename"
  ls -alhtR /etc/systemd/system/multi-user.target.wants | tee -a "$filename"
  ls -alht /etc/systemd/system/*.service | ag -v 'dbus-org' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
}

bash_check() {
  echo -e "######Bash Configuration Check ######\n" | tee -a "$filename"
  #View history file
  echo -e "\e[00;31m[+]History\e[00m" | tee -a "$filename"
  ls -alht /root/.*_history | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' --nocolor | ag -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #/etc/profile
  echo -e "\e[00;31m[+]/etc/profile \e[00m" | tee -a "$filename"
  cat /etc/profile | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  # $HOME/.profile
  echo -e "\e[00;31m[+]\$HOME/.profile \e[00m" | tee -a "$filename"
  cat $HOME/.profile | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #/etc/rc.local
  echo -e "\e[00;31m[+]/etc/rc.local \e[00m" | tee -a "$filename"
  cat /etc/rc.local | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #~/.bash_profile
  echo -e "\e[00;31m[+]~/.bash_profile \e[00m" | tee -a "$filename"
  if [ -e "$HOME/.bash_profile" ]; then
    cat ~/.bash_profile | ag -v '#' | tee -a "$filename"
  be
  echo -e "\n" | tee -a "$filename"
  #~/.bashrc
  echo -e "\e[00;31m[+]~/.bashrc \e[00m" | tee -a "$filename"
  cat ~/.bashrc | ag -v '#' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #bash bounce shell
  echo -e "\e[00;31m[+]bash反弹shell \e[00m" | tee -a "$vuln"
  ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print $2}' | xargs -i{} lsof -p{} | ag 'ESTAB' --nocolor | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

file_check() {
  echo -e "############ file check #############\n" | tee -a "$filename"
  echo -e "\e[00;31m[+]system file modification time\e[00m" | tee -a "$vuln"
  cmdline=(
    "/sbin/ifconfig"
    "/bin/ls"
    "/bin/login"
    "/bin/netstat"
    "/bin/top"
    "/bin/ps"
    "/bin/find"
    "/bin/grep"
    "/etc/passwd"
    "/etc/shadow"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/root/.ssh/authorized_keys"
  )
  for soft in "${cmdline[@]}"; do
    echo -e "File: $soft\t\t\tModified date: $(stat $soft | ag -o '(?<=Modify: )[\d-\s:]+')" | tee -a "$vuln"
  done

  echo -e "\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]...hidden file\e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*." | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #tmp directory
  echo -e "\e[00;31m[+]/tmp \e[00m" | tee -a "$filename"
  # shellcheck disable=SC2012
  ls /tmp /var/tmp /dev/shm -alht | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #alias aliases
  echo -e "\e[00;31m[+]alias \e[00m" | tee -a "$filename"
  alias | ag -v 'git' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #SOUTH
  echo -e "\e[00;31m[+]SUID \e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #lsof -L1
  #The process exists but the file is gone
  echo -e "\e[00;31m[+]lsof +L1 \e[00m" | tee -a "$filename"
  lsof +L1 | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Changed in the last 7 days
  echo -e "\e[00;31m[+] file changes in the past seven days mtime \e[00m" | tee -a "$filename"
  find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Changed in the last 7 days
  echo -e "\e[00;31m[+] file changes in the past seven days ctime \e[00m" | tee -a "$filename"
  find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n' | xargs -i{} ls -alh {} | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  #Large file 100mb
  #Some hackers will package the database and website into one file and download it
  echo -e "\e[00;31m[+] large file >200mb \e[00m" | tee -a "$filename"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor | ag -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1' | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"
  # Sensitive documents
  echo -e "\e[00;31m[+]sensitive file\e[00m" | tee -a "$vuln"
  find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | ag -v '/lib/python' | xargs -i{} ls -alh {} | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Suspicious hacker file\e[00m" | tee -a "$vuln"
  find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | ag -v '/pkgs/|/envs/' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

rootkit_check() {
  echo -e "############# Rootkit check ############\n" | tee -a "$vuln"
  #lsmod Suspicious Modules
  echo -e "\e[00;31m[+]lsmod suspicious module\e[00m" | tee -a "$vuln"
  lsmod | ag -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet|ip6table_raw|skx_edac|intel_rapl|wmi|acpi_pad|ast|i40e|ptp|nfit|libnvdimm|bpfilter|failover" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Rootkit Kernel Module\e[00m" | tee -a "$vuln"
  kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
  if [ -n "$kernel" ]; then
    echo "Kernel sensitive function exists! Suspected rootkit kernel module" | tee -a "$vuln"
    echo "$kernel" | tee -a "$vuln"
  else
    echo "kernel sensitive function not found" | tee -a "$vuln"
  be
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Suspicious .ko module\e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/usr/lib/modules/*" ! -path "/lib/modules/*" ! -path "/boot/*" -regextype posix-extended -regex '.*\.ko' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

ssh_check() {
  echo -e "############ SSH检查 ############\n" | tee -a "$filename"
  #SSH blast IP
  echo -e "\e[00;31m[+]SSH爆破\e[00m" | tee -a "$filename"
  if [ $OS = 'Centos' ]; then
    ag -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a "$filename"
  else
    ag -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25 | tee -a "$filename"
  be
  echo -e "\n" | tee -a "$filename"
  #SSHD
  echo -e "\e[00;31m[+]SSHD \e[00m" | tee -a "$filename"
  echo -e "/usr/sbin/sshd"
  stat /usr/sbin/sshd | ag 'Access|Modify|Change' --nocolor | tee -a "$filename"
  echo -e "\n" | tee -a "$filename"

  #ssh backdoor configuration check
  echo -e "\e[00;31m[+]SSH backdoor configuration\e[00m" | tee -a "$vuln"
  if [ -e "$HOME/.ssh/config" ]; then
    grep LocalCommand <~/.ssh/config | tee -a "$vuln"
    grep ProxyCommand <~/.ssh/config | tee -a "$vuln"
  else
    echo -e "No ssh configuration file found" | tee -a "$vuln"
  be
  echo -e "\n" | tee -a "$vuln"

  #ssh backdoor configuration check
  echo -e "\e[00;31m[+]SSH soft connection backdoor\e[00m" | tee -a "$vuln"
  if ps -ef | ag '\s+\-oport=\d+' >/dev/null 2>&1; then
    ps -ef | ag '\s+\-oport=\d+' | tee -a "$vuln"
  else
    echo "SSH soft connection backdoor not detected" | tee -a "$vuln"

  be
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]SSH inetd backdoor check\e[00m" | tee -a "$vuln"
  if [ -e "/etc/inetd.conf" ]; then
    grep -E '(bash -i)' </etc/inetd.conf | tee -a "$vuln"
  be
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]SSH key\e[00m" | tee -a "$vuln"
  sshkey=${HOME}/.ssh/authorized_keys
  if [ -e "${sshkey}" ]; then
    # shellcheck disable=SC2002
    cat ${sshkey} | tee -a "$vuln"
  else
    echo -e "SSH key file does not exist\n" | tee -a "$vuln"
  be
  echo -e "\n" | tee -a "$vuln"
}

webshell_check() {
  echo -e "############# Webshell check ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]PHP webshell killing\e[00m" | tee -a "$vuln"
  ag --php -l -s -i 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath | tee -a "$vuln"
  ag --php -l -s -i '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath | tee -a "$vuln"
  ag --php -l -s -i '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath | tee -a "$vuln"
  ag --php -l -s -i "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  #JSP webshell killing
  echo -e "\e[00;31m[+]JSP webshell killing\e[00m" | tee -a "$vuln"
  ag --jsp -l -s -i '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

poison_check() {
  echo -e "############ supply chain poisoning detection ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Python2 pip detection\e[00m" | tee -a "$vuln"
  pip freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Python3 pip detection\e[00m" | tee -a "$vuln"
  pip3 freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request=" | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

miner_check() {
  echo -e "############ Mining Trojan check ############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]General mining process detection\e[00m" | tee -a "$vuln"
  ps aux | ag "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb" | ag -v 'ag' | tee -a "$vuln" |
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]Ntpclient mining Trojan detection\e[00m" | tee -a "$vuln"
  find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz' | tee -a "$vuln"
  ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"

  echo -e "\e[00;31m[+]WorkMiner mining Trojan detection\e[00m" | tee -a "$vuln"
  ps aux | ag "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | ag -v 'ag'
  ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

risk_check() {
  echo -e "############ server risk/vulnerability check############\n" | tee -a "$vuln"
  echo -e "\e[00;31m[+]Redis weak password detection\e[00m" | tee -a "$vuln"
  cat /etc/redis/redis.conf 2>/dev/null | ag '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)' | tee -a "$vuln"
  echo -e "\n" | tee -a "$vuln"
}

base_check
network_check
crontab_check
env_check
user_check
service_check
bash_check
file_check
rootkit_check
ssh_check
webshell_check
poison_check
miner_check
risk_check
