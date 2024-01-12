# Network and Active Directory Automation Script

## Overview

This script automates various network and Active Directory (AD) tasks using a set of tools. It includes features such as port scanning, web vulnerability scanning, SMB enumeration, password spraying, and checks for specific vulnerabilities like BlueKeep and SMBGhost.

## Table of Contents

- [Tools Used](#tools-used)
- [Requirements](#requirements)
- [Usage](#usage)
- [Installation](#installation)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Tools Used

- [brutespray](https://github.com/x90skysn3k/brutespray): Password spraying tool for various services.
- [httpx](https://github.com/projectdiscovery/httpx): Fast and multi-purpose HTTP toolkit.
- [nuclei](https://github.com/projectdiscovery/nuclei): Fast and customizable vulnerability scanner.
- [SMBGhost_RCE_PoC](https://github.com/chompie1337/SMBGhost_RCE_PoC): Tool to check for the SMBGhost vulnerability.
- [AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010): Automated exploitation tool for MS17-010.
- ... (Include other tools and their GitHub links)

## Requirements

- Bash (Linux/Unix environment)
- Go programming language (for installing httpx and nuclei)
- Python (for running Python scripts)
- Other dependencies as specified by the tools used

## Installation
- git clone https://github.com/yourusername/network-automation.git
- cd network-automation
- Chmod +x Tool.sh
- ./Tool.sh

## Usage

To use this script, provide the target IP address or subnet range as a command-line argument. The script will perform various tasks based on the specified tools.

## Run the recon script
- Chmod +x recon.sh
- ./recon.sh TargetIP or subnetrange

## Make sure your root user

## License

This script is licensed under the MIT License.

Make sure to include details specific to your script, such as additional tools used, specific dependencies, and any other relevant information. Adjust the links and descriptions accordingly.

