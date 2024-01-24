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

# Assuming you have Go installed and the GOPATH/bin is in your PATH
echo "Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sdcampbell/nmapurls@latest

wget -O exploit.py https://www.exploit-db.com/exploits/42315

apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
python3 -m pipx install impacket

echo "All tools installed in the 'tools' folder."
