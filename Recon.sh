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
#nmap -p- -sC -sV -oA $results_dir/nmap_tcp_scan "$IP"

echo "Performing UDP Scan..."
#nmap -p- -sC -sU -oA $results_dir/nmap_udp_scan "$IP"

echo "Looking for web-related vulnerabilities..."

echo "$IP" | httpx -p '80,81,82,90,443,444,446,447,448,449,450,451,1947,5000,5800,8000,8443,8080,8081,8089,8888,1072,1556,1947,2068,2560,3128,3172,3387,3580,3582,3652,4343,4480,5000, 
5800,5900,5985,5986,8001,8030,8082,8083,8088,8089,8090,8443,8444,8445,8910,9001,9090,9091,20000' --title | tee $results_dir/httpxresults

cat nmap_tcp_scan.xml | nmapurls | tee nmap_webservice_results

echo "Running Nuclei scanning..."
cat $results_dir/httpxresults | nuclei | tee $results_dir/nucleiresults

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
cme mssql "$IP" -u 'users.txt' -p 'password.txt' 2>&1  | tee $results_dir/mssql_results
cme winrm "$IP" -u 'users.txt' -p 'password.txt' 2>&1 | tee $results_dir/winrm

echo "Running RPC checks..."
rpcclient -U '' -N "$IP" -c enumdomusers 2>&1 | tee $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c querydispinfo 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomains 2>&1 | tee -a $results_dir/rpc-check.txt
rpcclient -U '' -N "$IP" -c enumdomgroups 2>&1 | tee -a $results_dir/rpc-check.txt

echo "Running password spraying..."
python3 brutespray.py --file $results_dir/ -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt -c -o password_spray_results

echo "Checking for BlueKeep vulnerability..."
python3 bluekeep.py "$IP"

echo "Checking for SMBGhost vulnerability..."
python3 SMBGhost/scanner.py "$IP"

echo "Script execution completed. Results stored in: $results_dir"
trap - ERR
cleanup
