#!/bin/bash

echo "Creating tools folder..."
mkdir -p $HOME/tools
cd tools

echo "Cloning and installing tools..."

git clone https://github.com/x90skysn3k/brutespray.git
git clone https://github.com/chompie1337/SMBGhost_RCE_PoC.git
git clone https://github.com/Barriuso/SMBGhost_AutomateExploitation
git clone https://github.com/Ekultek/BlueKeep.git
git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
sudo apt-get --assume-yes install git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
cd ..

# Assuming you have Go installed and the GOPATH/bin is in your PATH
echo "Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sdcampbell/nmapurls@latest
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

wget -O exploit.py https://www.exploit-db.com/exploits/42315
sudo apt install steghide
apt install pipx git -y
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install git+https://github.com/Tib3rius/AutoRecon.git
python3 -m pipx install impacket
python3 -m pip install --user pipenv
git clone https://github.com/layer8secure/SilentHound.git
cd silenthound
pipenv install

echo "All tools installed in the 'tools' folder."
