#!/bin/bash
#
# Automated Security Testing Script
# Author: Jai Kumar
# Version: 1.0
# Description: This script automates various security testing tasks using a set of tools.
#

set -e

# Tools Used:
# - brutespray: Password spraying tool for various services
#   Installation: sudo apt-get install brutespray

# - httpx: Fast and multi-purpose HTTP toolkit
#   Installation: go get -u github.com/projectdiscovery/httpx/cmd/httpx

# - nuclei: Fast and customizable vulnerability scanner
#   Installation: GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

# - CrackMapExec (cme): Post-exploitation tool to automate the assessment of large Active Directory networks
#   Installation: sudo apt-get install -y libssl-dev libffi-dev python-dev build-essential && sudo pip install cme

# - SMBGhost: Tool to check for the SMBGhost vulnerability
#   Installation: git clone https://github.com/ly4k/SMBGhost.git

# Note: Ensure that Python3 and nmap are already installed on your system.
# If not, you can install Python3 using your system's package manager, and nmap using: sudo apt-get install nmap

# Set variables
IP="$1"
subnet_range=$(echo "$IP" | cut -d. -f1-3)
results_dir="/Users/jai/reconresults/$IP"
mkdir -p "$results_dir"
 
# Function to perform a scan and save results

echo "Performing port scan..."
nmap -p- -sC -sV -oA $results_dir/nmap_tcp_scan "$IP"

echo "Performing UDP Scan..."
nmap -p- -sC -sU -oA $results_dir/nmap_udp_scan "$IP"

echo "Nmap Script Scan On Port Wise"
nmap --script "ftp-anon,ftp-vuln*,ftp-*" -p 21 "$IP"
nmap --script ssh-* -p 22 "$IP"

nmap -n --script "*telnet* and safe" -p 23 "$IP"

nmap --script "smtp-brute,smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-vuln-cve2011-1764,smtp-*" -p 25,465,587 --script-args smtp-ntlm-info.domain=example.com "$IP"

nmap -sU --script "ntp-info,ntp-monlist,ntp*,ntp* and (discovery or vuln) and not (dos or brute)" -p 123 <target-ip>

echo "Scanning for MSRPC TEST CASES"
impacket-rpcdump -port 135 <target-ip> | grep -E 'MS-RPRN|MS-PAR'
impacket-rpcdump -port 135 <target-ip>
nmap --script msrpc-enum -p 135 <target-ip>

echo "Scanning for SMB TEST CASES"
nmap --script "smb-brute,smb-enum-shares.nse,smb-enum-users.nse,smb-enum*,smb-protocols,smb-vuln*" -p 445 <target-ip>
enum4linux -a -v $IP
netexec smb <target-ip> -u '' -p '' -M zerologon -M petitpotam
smbmap -H <target-ip> -
smbclient -N -L <target-ip>
smbmap -u username -p password -H <target-ip> -x 'ipconfig'
crackmapexec smb <target-ip> -u username -p password --users
crackmapexec smb <target-ip> -u users.txt -p password --continue-on-success
impacket-lookupsid example.local/user@<target-ip> 20000
crackmapexec smb <target-ip> -u <username> -H hashes.txt

echo "Scanning for MSRPC"
nmap --script msrpc-enum -p 135 <target-ip>
# rpcdump for dumping RPC endpoints
impacket-rpcdump -port 135 <target-ip>
# Find the Print System Remote Prototol or the Print System Asynchronous Remote Protocol
impacket-rpcdump -port 135 <target-ip> | grep -E 'MS-RPRN|MS-PAR'

echo "Running RPC Login checks..."
rpcclient -U '' -N "$IP" -c enumdomusers 2>&1 | tee $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c querydispinfo 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomains 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomgroups 2>&1 | tee -a $results_dir/rpc-check.txt

echo "Running LDAP checks..."
nmap --script "ldap-brute,ldap-search,ldap-* and not brute" --script-args "ldap.base='cn=users,dc=cqure,dc=net'" -p 389 <target-ip>
# -k: Use Kerberos authentication
netexec ldap <target-ip> -u usernames.txt -p '' -k
# --trusted-for-delegation: Enumerate computers and users with the flag `TRUSTED_FOR_DELEGATION`
netexec ldap <target-ip> -u username -p password --trusted-for-delegation

echo "Running MSSQL checks..."
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
cme mssql "$IP" -u 'users.txt' -p 'password.txt' 2>&1  | tee $results_dir/mssql_results

echo "Running MYSQL checks..."
nmap --script "mysql-info,mysql-enum,mysql-brute,mysql-databases,mysql-users,mysql-*" -p 3306 <target-ip>

echo "AJP"
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 <IP>

echo" Running RDP checks..."
nmap --script "rdp-enum-encryption,rdp-ntlm-info,rdp*" -p 3389 <target-ip>
#Brute Force Credentials
hydra -l username -P passwords.txt <target-ip> rdp

echo "Running SNMP checks ..."
nmap -sU --script "snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp*" -p 161 <target-ip>
#Brute Force the Community Names
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target-ip> snmp
#Snmp-Check is SNMP enumerator.
snmp-check <target-ip> -p 161 -c public

echo "Running NFS check..."
nmap --script=nfs-ls,nfs-statfs,nfs-showmount -p 111,2049 <target-ip>

echo "Running vnc checks..."
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p '5800,5801,5900,5901' <IP>
msf> use auxiliary/scanner/vnc/vnc_none_auth; Spool $results_dir/vncmsf; Set rhosts $IP; run ;Spool off ; exit

echo "Looking for web-related vulnerabilities..."

echo "$IP" | httpx -p '80,81,82,90,443,444,446,447,448,449,450,451,1947,5000,5800,8000,8443,8080,8081,8089,8888,1072,1556,1947,2068,2560,3128,3172,3387,3580,3582,3652,4343,4480,5000, 
5800,5900,5985,5986,8001,8030,8082,8083,8088,8089,8090,8443,8444,8445,8910,9001,9090,9091,20000' --title | tee $results_dir/httpxresults

echo "Using nmap results grabing web service"
cat nmap_tcp_scan.xml | nmapurls | tee nmap_webservice_results

echo "Running Nuclei scanning..."
#cat $results_dir/httpxresults | nuclei | tee $results_dir/nucleiresults

echo "Scanning for SMBv1, signing, and Windows details..."
cme smb "$IP" | tee $results_dir/smb_results

echo "Extracting SMBv1 IPs..."
awk '/smbv1: true/{print $1, $4}' smb_results | tee $results_dir/smbv1_ips

echo "Extracting SMB signing false IPs..."
awk '/signing: false/{print $1, $4}' smb_results | tee $results_dir/smbsigning_ips

echo "Extracting Windows version information..."
awk '{print $3}' smb_results | tee $results_dir/windows_version

echo "Performing SMB enumeration..."
cme smb "$IP" -u '' -p '' --shares 2>&1 | tee $results_dir/null_smb_open_shares
cme smb "$IP" -u 'users.txt' -p 'password.txt' --shares 2>&1  | tee $results_dir/default_shares
cme ssh "$IP" -u 'users.txt' -p 'password.txt' 2>&1  | tee $results_dir/ssh_pwned
cme winrm "$IP" -u 'users.txt' -p 'password.txt' 2>&1 | tee $results_dir/winrm

echo "Running password spraying..."
python3 $HOME/tools/brutespray/brutespray.py --file $results_dir/ -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt -c -o password_spray_results

echo "Checking for BlueKeep vulnerability..."
python3 $HOME/tools/bluekeep.py "$IP"

echo "Checking for SMBGhost vulnerability..."
python3  $HOME/tools/SMBGhost/scanner.py "$IP"

echo "texttohtml"
python3 /users/jai/text2html.py -i $results_dir -o $results_dir/results.html

echo "Script execution completed. Results stored in: $results_dir"
trap - ERR
cleanup
