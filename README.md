# LinuxCheckEng
this is a just english version of linuxcheck.

Linux emergency response/information collection/vulnerability detection tools, support basic configuration/network traffic/task planning/environment variables/user information/Services/bash/malicious files/kernel Rootkit/SSH/Webshell/mining files/mining process/supply 70+ inspections in 13 categories such as chain/server risk
### Function

* Basic configuration check
    * System configuration change check
    * System information (IP address/user/boot time/system version/Hostname/server SN)
    * CPU usage
    * Login user information
    * CPU TOP 15
    * Memory TOP 15
    * Disk free space check
    * Hard disk mount
    * Commonly used software check
    * /etc/hots
* Network/traffic inspection
    * ifconfig
    * Network traffic
    * Port listening
    * Open ports to the outside world
    * Internet connection
    * TCP connection status
    * routing table
    * Route forwarding
    * DNS Server
    * ARP
    * Network card promiscuous mode check
    * iptables firewall
* Task plan check
    * Current user task plan
    * /etc/system task schedule
    * Task plan file creation time
    * crontab backdoor investigation
* Environment variable check
    * env
    * path
    * LD_PRELOAD
    * LD_ELF_PRELOAD
    * LD_AOUT_PRELOAD
    * PROMPT_COMMAND
    * LD_LIBRARY_PATH
    * ld.so.preload
* User information check
    * Can login user
    * passwd file modification date
    * sudoers
    * Login information (w/last/lastlog)
    * Historical login ip
* Services check
    * SystemD running service
    * SystemD service creation time
* bash check
    * History
    * History command audit
    * /etc/profile
    * $HOME/.profile
    * /etc/rc.local
    * ~/.bash_profile
    * ~/.bashrc
    * bash rebound shell
* Document check
    * ...hidden files
    * System file modification time detection
    * Temporary file check (/tmp /var/tmp /dev/shm)
    * alias
    * suid special permission check
    * process exists file not found
    * File change mtime in the past seven days
    * File change ctime in the past seven days
    * Large files >200mb
    * Sensitive file auditing (common tools used by hackers such as nmap/sqlmap/ew/frp/nps)
    * Suspicious hacker files (programs such as wget/curl uploaded by hackers, or changing malicious programs into normal software such as nps files into mysql)
* Kernel Rootkit check
    * lsmod suspicious module
    * Kernel symbol table check
    * rootkit hunter check
    * rootkit .ko module check
* SSH check
    * SSH brute force
    * SSHD detection
    * SSH backdoor configuration
    * SSH inetd backdoor check
    * SSH key
* Webshell inspection
    * php webshell check
    * jsp webshell inspection
* Mining file/process check
    * Mining file check
    * Mining progress check
    * WorkMiner detection
    * Ntpclient detection
* Supply chain poison inspection
    * Python PIP poison check
* Server risk check
    * Redis weak password detection

### Usage

Internet status:
 - apt-get install silversearcher-ag
 - yum -y install the_silver_searcher  

Offline status:   
 - Debian：dpkg -i silversearcher-ag_2.2.0-1+b1_amd64.deb  
 - Centos：rpm -ivh the_silver_searcher-2.1.0-1.el7.x86_64.rpm  

```
git clone https://github.com/al0ne/LinuxCheck.git  
```
```
chmod u+x LinuxCheck.sh
```

```
./LinuxCheck.sh  
```

If ag and rkhunter have been installed, you can directly use the following command

```
bash -c "$(curl -sSL https://raw.githubusercontent.com/al0ne/LinuxCheck/master/LinuxCheck.sh)"  
```

The file will be saved in the format of ipaddr_hostname_username_timestamp.log

### Reference

The writing of this tool mainly refers to the following tools/articles and is completed in combination with personal experience

Linenum    
https://github.com/lis912/Evaluation_tools  
https://ixyzero.com/blog/archives/4.html  
https://github.com/T0xst/linux   
https://github.com/grayddq/GScan  
