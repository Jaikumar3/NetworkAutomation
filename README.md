# Automated Infra Testing Script

## Author
Jai Kumar

## Version
1.0

## Description
This script automates various security testing tasks using a set of tools. It covers a range of security assessments, including port scanning, vulnerability scanning, and enumeration of different services.

## Dependencies
Make sure you have the following dependencies installed on your system before running the script:
- nmap
- impacket
- CrackMapExec (cme)
- SMBGhost
- hydra
- snmp-check
- enum4linux
- smbmap
- nuclei
- httpx
- brutespray
- python3
- go (for installing some tools)

## Features

- Network scanning with Nmap
- Service enumeration for FTP, SSH, Telnet, SMTP, NTP, MSRPC, RDP, SNMP, NFS, VNC, Docker, MSSQL, MySQL, AJP, LDAP, PostgreSQL, and more.
- Vulnerability scanning for SMBv1, SMB signing, BlueKeep, SMBGhost, and others.
- Web service scanning using httpx.
- Additional scans for SMBv1 IPs, SMB signing false IPs, Windows version information, and password spraying.
- HTML report generation.
  
## Usage
1. Clone the repository: `git clone https://github.com/Jaikumar3/NetworkAutomation.git`
2. Navigate to the script directory: `cd yourrepository`
3. Make the script executable: `chmod +x recon.sh`
4. Run the script: `./recon.sh`
5. Make sure your are the root user

Follow the on-screen prompts to input the target IP address and project name. The script will perform various security tests and store results in a specified directory.

## Results
After the script execution is completed, the results will be stored in the specified directory. Check the directory for detailed results and reports.

## Color Legend
- Green: Information or success messages
- Red: Error or warning messages

## Note
Ensure that you have the required permissions to run the script and execute external tools. Some tools may require additional setup or configurations.

## Disclaimer
This script is provided as-is, and the author takes no responsibility for any misuse or damage caused by its usage. Use it responsibly and only on systems for which you have explicit permission.
