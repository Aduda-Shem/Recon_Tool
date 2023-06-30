# Recon_Tool - Website Recon Tool

A website reconnaissance tool designed for bug bounty hunters and security researchers. It automates various reconnaissance tasks to gather information about a target domain, IP address, or URL.

## Features

- Subdomain enumeration using popular tools like Amass, Subfinder, Findomain, Assetfinder, and CRT.sh.
- Live subdomain identification by checking for active subdomains using httprobe.
- URL and parameter discovery using tools like gau, waybackurls, and paramspider.
- Port scanning of a target IP address using Nmap.
- Directory and file enumeration using Dirb and Gobuster.
- Analysis of results through regex pattern matching, keyword searching, and statistical analysis.
- Summary display to provide a consolidated view of the obtained results.

## Prerequisites

Before using EAGLES EYE, ensure that you have the following tools installed on your system:

- Amass
- Subfinder
- Findomain
- Assetfinder
- CRT.sh
- Httprobe
- Gau
- Waybackurls
- Paramspider
- Nmap
- Dirb
- Gobuster

Make sure these tools are accessible via the command line.

## Usage

1. Clone the repository:

   ```shell
   git clone https://github.com/Aduda-Shem/bug-bounty.git
2. Usage
   ```shell
   python3 eagles_eye.py [domain] [target_ip] [url]

