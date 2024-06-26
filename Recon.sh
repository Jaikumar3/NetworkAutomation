#!/bin/bash

# Automated Security Testing Script
# Author: Jai Kumar
# Version: 1.0
# Description: This script automates various security testing tasks using a set of tools.

# Error Handling
set -e

# Set color variables
GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

RED_LINE="${RED}================================================================================${RESET}"

# Set variables
# Prompt user for target IP address
read -p "Enter the target IP address (e.g., 10.0.2.13): " IP

# Prompt user for project name
read -p "Enter the project name (e.g., Infra): " project_name

# Set variables
results_dir="$HOME/$project_name"
sub_dirs=("SMB" "FTP" "MSSQL" "NMAP" "SSH" "NTP" "LDAP" "MSRPC" "DOCKER" "RDP" "SNMP" "NUCLEI" "AJP" "HTTPX"  "NMAP" "PostgreSQL" "SMTP" "VNC")

# Create main directory
mkdir -p "$results_dir"

# Create subdirectories
for dir in "${sub_dirs[@]}"; do
  mkdir -p "$results_dir/$dir"
done

nmap --script-updatedb
# Check if target_ip is a single IP or a subnet
if [[ $IP == *"/"* ]]; then
    # It's a subnet, use prips
    prips "$IP" > "$results_dir/list_hosts.txt"
else
    # It's a single IP, don't use prips
    echo "$IP" > "$results_dir/list_hosts.txt"
fi
 
# Function to perform a scan and save results

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  +---Nmap Script Scan---+         |${RESET}"
  echo -e "${GREEN}|      Running Nmap                 |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
nmap -p- -sC -sV -oA $results_dir/NMAP/nmap_tcp_scan "$IP"

  echo -e $RED_LINE
  
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  +---Performing UDP Scan---+      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
timeout 3h nmap -sC -sU -oA $results_dir/NMAP/nmap_udp_scan "$IP"

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  +---Nmap enumeration---+         |${RESET}"
  echo -e "${GREEN}|      Script Scan for 21,22,25     |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
timeout 1h nmap --script "ftp-anon,ftp-vuln*,ftp-*" -p 21 "$IP" -oN $results_dir/FTP/ftp_nmap.txt
msfconsole -q -x "use auxiliary/scanner/ftp/anonymous ; spool $results_dir/FTP/ftp_msf.txt; set rhosts $IP; set password anonymous; run ;spool off ; exit"

timeout 1h nmap --script ssh-* -p 22 "$IP" | tee $results_dir/SSH/ssh_nmap.txt
crackmapexec ssh "$IP" -u '/home/vaptadmin/jai/usernames.txt' -p '/home/vaptadmin/jai/password.txt' 2>&1  | tee -a $results_dir/SSH/ssh_cme.txt
nmap -n --script "*telnet* and safe" -p 23 "$IP"  -oN $results_dir/TELNET/telnet_nmap.txt
nmap --script "smtp-brute,smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-vuln-cve2011-1764,smtp-*" -p 25,465,587  "$IP" | tee $results_dir/SMTP/smtp_nmap.txt
nmap -sU --script "ntp-info,ntp-monlist,ntp*,ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $IP | tee -a $results_dir/NTP/ntp.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for MSRPC TEST CASES$   |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

# Find the Print System Remote Prototol or the Print System Asynchronous Remote Protocol
impacket-rpcdump -port 135 $IP | grep -E 'MS-RPRN|MS-PAR' | tee -a $results_dir/MSRPC/MSRPC_PRINT.txt
# rpcdump for dumping RPC endpoints
impacket-rpcdump -port 135 $IP | tee -a $results_dir/MSRPC/RPCDUMP.txt
nmap --script msrpc-enum -p 135 $IP | tee -a $results_dir/MSRPC/nmap.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Running RPC Login checks...      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

#NUll Scan
# Enumerate users
rpcclient -U '' -N "$IP" -c enumdomusers | tee $results_dir/MSRPC/rpc-check.txt
# Domain info
rpcclient -U '' -N "$IP" -c querydispinfo | tee -a $results_dir/MSRPC/rpc-check.txt
# Enumerate domain users
rpcclient -U '' -N "$IP" -c enumdomains  | tee -a $results_dir/MSRPC/rpc-check.txt
# Enumerate domain groups
rpcclient -U '' -N "$IP" -c enumdomgroups | tee -a $results_dir/MSRPC/rpc-check.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for SMB TEST CASES      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

nmap --script "smb-brute,smb-enum-shares.nse,smb-enum-users.nse,smb-enum*,smb-protocols,smb-vuln*" -p 445 $IP | tee $results_dir/SMB/nmap.txt
#-a Do all simple enumeration (users,shares,os,password policy,groups).
enum4linux -a -v $IP | tee -a $results_dir/SMB_overall_results.txt
# -M zerologon: Scan for ZeroLogon
# -M petitpotam: Scan for PetitPotam
#netexec smb $IP -u '' -p '' -M zerologon -M petitpotam | tee -a $results_dir/SMB_overall_results.txt
# Recursive
#smbmap -H $IP -R | tee -a $results_dir/SMB_overall_results.txt
# -N: No password
# -L: List shared directories
#smbclient -N -L $results_dir/list_hosts | tee -a $results_dir/SMB_overall_results.txt
# Execute a command
#smbmap -u username -p password --host-file $results_dir/list_hosts -x 'ipconfig' | tee -a $results_dir/SMB_overall_results.txt
# Find aother user
crackmapexec smb $IP -u /home/vaptadmin/jai/usernames.txt -p /home/vaptadmin/jai/password.txt --users 2>&1 | tee -a $results_dir/SMB/cme.txt
#crackmapexec smb $IP -u /home/vaptadmin/jai/usernames.txt -p /home/vaptadmin/jai/password.txt --continue-on-success | tee -a $results_dir/SMB/SMB_overall_results.txt
#Perform RID cycling attack against a DC with SMB null sessions allowed with impacket-lookupsid
# Anonymous logon
# 20000: Maximum RID to be cycled
#impacket-lookupsid example.local/user@$IP 20000 | tee -a $results_dir/SMB_overall_results.txt
#crackmapexec smb $IP -u <username> -H hashes.txt | tee -a $results_dir/SMB_overall_results.txt
#Null scan for smb shares
crackmapexec smb "$IP" -u '' -p '' --shares | tee -a $results_dir/SMB/Null_smb.txt
crackmapexec smb "$IP" -u '/home/vaptadmin/jai/usernames.txt' -p '' --shares | tee -a $results_dir/SMB/Smb_without_password.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for LDAP TEST CASES     |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

timeout 30m nmap --script "ldap-brute,ldap-search,ldap-* and not brute" --script-args "ldap.base='cn=users,dc=cqure,dc=net'" -p 389 $IP | tee $results_dir/LDAP_overall_results.txt
# -k: Use Kerberos authentication
#netexec ldap $IP -u usernames.txt -p '' -k | tee -a $results_dir/LDAP_overall_results.txt
# --trusted-for-delegation: Enumerate computers and users with the flag `TRUSTED_FOR_DELEGATION`
#netexec ldap $IP -u username -p password --trusted-for-delegation | tee -a $results_dir/LDAP_overall_results.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for MSSQL TEST CASES    |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
timeout 30m nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP | tee $results_dir/mssql_results.txt
crackmapexec mssql "$IP" -u '/home/vaptadmin/jai/usernames.txt' -p '/home/vaptadmin/jai/password.txt' 2>&1  | tee -a $results_dir/mssql_results.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for MYSQL TEST CASES    |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
timeout 30m nmap --script "mysql-info,mysql-enum,mysql-brute,mysql-databases,mysql-users,mysql-*" -p 3306 $IP | tee $results_dir/mysql_results.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for AJP TEST CASES      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 $IP | tee  $results_dir/AJP/apache_ajp_results.txt
msfconsole -q -x "use auxiliary/admin/http/tomcat_ghostcat; spool $results_dir/AJP/apache_ajp_msf.txt; set rhosts $IP; run ;spool off ; exit"


echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for RDP  TEST CASES     |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
nmap --script "rdp-enum-encryption,rdp-ntlm-info,rdp*" -p 3389 $IP | tee $results_dir/RDP/nmap_results.txt
#Brute Force Credentials
timeout 20m hydra -l username -P passwords.txt $IP rdp | tee  $results_dir/RDP/hydra_results.txt
#"Terminal Service without NLA"
msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner ; spool $results_dir/RDP/rdp_nla.txt; set rhosts $IP; run ;spool off ; exit"
#Ms12-020 Scanning
msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check  ; spool $results_dir/RDP/rdp_ms12.txt; set rhosts $IP; run ;spool off ; exit"

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for SNMP TEST CASES     |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  
nmap -sU --script "snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp*" -p 161 $IP | tee  $results_dir/SNMP/snmp.txt
#Brute Force the Community Names
timeout 20m hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $IP snmp |  tee  $results_dir/SNMP/hydra.txt
#Snmp-Check is SNMP enumerator
snmp-check $IP -p 161 -c public | tee - $results_dir/SNMP/snmp-check.txt
#SNMP Fileshare enumeration
msfconsole -q -x "use auxiliary/scanner/snmp/snmp_enum; spool $results_dir/SNMP/snmp_enum.txt; set rhosts $IP; run ;spool off ; exit"

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for NFS  TEST CASES     |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
nmap --script=nfs-ls,nfs-statfs,nfs-showmount -p 111,2049 $IP | tee $results_dir/nfs_results.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for VNC TEST CASES     |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p '5800,5801,5900,5901' $IP | tee  $results_dir/VNC/vnc_results.txt
msfconsole -q -x "use auxiliary/scanner/vnc/vnc_none_auth; spool $results_dir/VNC/vncmsf.txt; set rhosts $IP; run ;spool off ; exit"

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Scanning for DOCKER TEST CASES   |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
#PORT 2375, 2376 Pentesting Docker
nmap -sV --script "docker-*" -p 2375,2376 $IP  | tee  $results_dir/docker_Results.txt
msfconsole -q -x "use exploit/linux/http/docker_daemon_tcp; spool $results_dir/docker_Results; set rhost $IP; run; spool off ; exit"

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}| Scanning for Postgresql TEST CASES|${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
#5432,5433 - Postgresql
nmap --script pgsql-brute -p 5432 $IP |  tee  $results_dir/Postgresql.txt
#Brute Force Credentials
#timeout 20m hydra -l username -P passwords.txt $IP postgres |  tee -a  $results_dir/PostgreSQL/Postgresql.txt
timeout 20m hydra -L/home/vaptadmin/jai/usernames.txt -P /home/vaptadmin/jai/password.txt $IP postgres |  tee -a $results_dir/PostgreSQL/Postgresql.txt
#Argument injection vulnerability (CVE-2013-1899)
msfconsole -q -x "use auxiliary/scanner/postgres/postgres_dbname_flag_injection; spool $results_dir/PostgreSQL/postgresql_msf_cve.txt; set rhost $IP; run; spool off ; exit"

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Running for httpx                |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

echo "$IP" | /home/vaptadmin/jai/tools/./httpx -p '80,81,82,90,443,444,446,447,448,449,450,451,1947,5000,5800,8000,8443,8080,8081,8089,8888,1072,1556,1947,2068,2560,3128,3172,3387,3580,3582,3652,4343,4480,5000, 
5800,5900,5985,5986,8001,8030,8082,8083,8088,8089,8090,8443,8444,8445,8910,9001,9090,9091,20000' --title --status-code --content-type -td -cdn --server| tee $results_dir/HTTPX/httpxresults.txt

#Noise remove from httpx results
cat $results_dir/httpxresults.txt | grep -oP 'https://[^ ]+' | tee $results_dir/HTTPX/httpx_without_noise.txt
echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Using nmap results grabbing      |${RESET}"
  echo -e "${GREEN}|           web service             |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
cat $results_dir/nmap_tcp_scan.xml | nmapurls | tee $results_dir/NMAP/nmap_webservice_results.txt
cat $results_dir/nmap_tcp_scan.xml | /home/vaptadmin/jai/tools/./tew | tee -a n$results_dir/NMAP/map_webservice_results.txt
cat $results_dir/httpx_without_noise.txt nmap_webservice_results.txt | anew | tee $results_dir/HTTPX/httpx.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Running Nuclei scanning...       |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

cat $results_dir/httpx.txt | /home/vaptadmin/jai/tools/./nuclei | tee $results_dir/nucleiresults.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|      Extracting SMBv1 IPs         |${RESET}"
  echo -e "${GREEN}|         and Hostname..            |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

cme smb $IP | grep 'SMBv1:True' | tee $results_dir/SMB/smbv1.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Extracting SMB signing           |${RESET}"
  echo -e "${GREEN}|    false IPs...                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

#awk '/signing: false/{print $1, $4}' smb_results | tee $results_dir/smbsigning_ips.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|   Extracting Windows              |${RESET}"
  echo -e "${GREEN}|    version information...         |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
#awk '{print $3}' smb_results | tee $results_dir/windows_version.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}|    Running password spraying      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"

brutespray --file $results_dir/nmap_tcp_scan.gnmap -U /home/vaptadmin/jai/usernames.txt -P /home/vptadmin/jai/password.txt -c -o $results_dir/password_spray_results.txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Checking for BlueKeep            |${RESET}"
  echo -e "${GREEN}|     vulnerability...              |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
python3 $HOME/tools/bluekeep.py "$IP" | tee -a $results_dir/RDP/rdp_results,txt

echo -e $RED_LINE

  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Checking for SMBGhost            |${RESET}"
  echo -e "${GREEN}|     vulnerability...              |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
#python3  $HOME/tools/SMBGhost/scanner.py "$IP" | tee -a $results_dir/SMB/smbghost.txt

echo -e $RED_LINE

echo -e "${GREEN}Report generating into html${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
  echo -e "${GREEN}|  Report generating into html      |${RESET}"
  echo -e "${GREEN}|                                   |${RESET}"
  echo -e "${GREEN}+-----------------------------------+${RESET}"
python3 /users/jai/text2html.py -i $HOME/$results_dir -o $results_dir/results.html
#namp_parser $results_dir/nmap_tcp_scan.gnmap --summary --unique 

echo -e $RED_LINE
echo -e $RED_LINE
echo -e $RED_LINE

rm -rf $results_dir/httpx_without_noise.txt nmap_webservice_results.txt

trap - ERR
cleanup
echo -e "${GREEN}Script execution completed. Results stored in: $results_dir${RESET}"
