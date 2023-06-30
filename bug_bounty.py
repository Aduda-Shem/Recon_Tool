#!/usr/bin/env python3

import argparse
import asyncio
import os
import re

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
NC = "\033[0m"

def print_banner():
    ascii_banner = r'''
 _____    _    ____ _     _____ ____    _______   _______
| ____|  / \  / ___| |   | ____/ ___|  | ____\ \ / / ____|
|  _|   / _ \| |  _| |   |  _| \___ \  |  _|  \ V /|  _|
| |___ / ___ \ |_| | |___| |___ ___) | | |___  | | | |___
|_____/_/   \_\____|_____|_____|____/  |_____| |_| |_____|
    '''
    print(f"{GREEN}{ascii_banner}{NC}")

async def subdomain_enum(domain):
    print(f"\n{YELLOW}Running subdomain enumeration for domain: {domain}...{NC}")
    subdomains_file = "subdomains.txt"
    tools = [
        f"amass enum -d {domain} -o {subdomains_file}",
        f"subfinder -d {domain} >> {subdomains_file}",
        f"findomain -t {domain} >> {subdomains_file}",
        f"assetfinder --subs-only {domain} >> {subdomains_file}",
        f"crtsh {domain} >> {subdomains_file}",
    ]
    for tool in tools:
        os.system(tool)
    
    with open(subdomains_file, "r") as file:
        return file.read().splitlines()

async def find_live_subdomains(subdomains):
    print(f"\n{YELLOW}Checking for live subdomains...{NC}")
    live_subdomains_file = "live_subdomains.txt"
    os.system(f"cat {subdomains} | httprobe -c 50 -t 3000 -p https,http > {live_subdomains_file}")
    
    with open(live_subdomains_file, "r") as file:
        return file.read().splitlines()

def find_urls_params(domain):
    print(f"\n{YELLOW}Finding all URLs and parameters for domain: {domain}...{NC}")
    urls_file = "urls.txt"
    tools = [
        f"gau {domain} | anew {urls_file}",
        f"waybackurls {domain} | anew {urls_file}",
        f"paramspider --domain {domain} --exclude woff,css,js >> {urls_file}",
        # Add more URL enumeration tools here
    ]
    for tool in tools:
        os.system(tool)
    
    with open(urls_file, "r") as file:
        return file.read().splitlines()

def port_scan(target_ip):
    print(f"\n{YELLOW}Running port scanning for IP: {target_ip}...{NC}")
    port_scan_results_file = "port_scan_results.txt"
    os.system(f"nmap -p- -A -T4 {target_ip} > {port_scan_results_file}")
    
    with open(port_scan_results_file, "r") as file:
        return file.read()

def dirb_gobuster_enum(url):
    print(f"\n{YELLOW}Running directory and file enumeration for URL: {url}...{NC}")
    dir_enum_results_file = "dir_enum_results.txt"
    os.system(f"dirb {url} > {dir_enum_results_file}")
    os.system(f"gobuster dir -u {url} -w /path/to/wordlist.txt -o {dir_enum_results_file}")
    
    with open(dir_enum_results_file, "r") as file:
        return file.read()

def analyze_results(results):
    print(f"\n{YELLOW}Analysis:{NC}")
    print("------------\n")

    regex_patterns = ["API_KEY=[A-Za-z0-9]+", "password=[A-Za-z0-9]+", "secret=[A-Za-z0-9]+"]
    print(f"{YELLOW}Regex Pattern Matching:{NC}")
    print("----------------------")
    for pattern in regex_patterns:
        matches = re.findall(pattern, results)
        if matches:
            print("\n".join(matches))
    print()

    keywords = ["vulnerable", "misconfiguration", "insecure", "weak"]
    print(f"{YELLOW}Keyword Searching:{NC}")
    print("-----------------")
    for keyword in keywords:
        if re.search(keyword, results, re.IGNORECASE):
            print(keyword)
    print()

    headers = ["Server", "X-Powered-By", "Content-Security-Policy"]
    print(f"{YELLOW}Statistical Analysis:{NC}")
    print("--------------------")
    for header in headers:
        occurrences = len(re.findall(header, results, re.IGNORECASE))
        print(f"Occurrences of {header}: {occurrences}")
    print()

def display_summary(results):
    print(f"\n{YELLOW}Summary:{NC}")
    print("--------\n")

    sections = {
        "Subdomain Enumeration": results["subdomains"],
        "Live Subdomains": results["live_subdomains"],
        "URLs and Parameters": results["urls"],
        "Port Scan Results": results["port_scan"],
        "Directory and File Enumeration Results": results["dir_enum"],
    }

    for section, data in sections.items():
        print(f"{YELLOW}{section}:{NC}")
        print("---------------------")
        if data:
            print("\n".join(data))
        else:
            print("No results found.")
        print()

    analyze_results("\n".join(results.values()))

async def main(args):
    results = {
        "subdomains": [],
        "live_subdomains": [],
        "urls": [],
        "port_scan": "",
        "dir_enum": "",
    }

    if args.domain:
        results["subdomains"] = await subdomain_enum(args.domain)
        results["live_subdomains"] = await find_live_subdomains("subdomains.txt")

    if args.target_ip:
        results["port_scan"] = port_scan(args.target_ip)

    if args.url:
        results["urls"] = find_urls_params(args.url)
        results["dir_enum"] = dirb_gobuster_enum(args.url)

    display_summary(results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EAGLES EYE - Website Recon Tool")
    print_banner()
    print("Website Recon Tool")
    print("-----------------")
    parser.add_argument("domain", nargs="?", type=str, help="Target domain")
    parser.add_argument("target_ip", nargs="?", type=str, help="Target IP address")
    parser.add_argument("url", nargs="?", type=str, help="Target URL")
    args = parser.parse_args()
    asyncio.run(main(args))
