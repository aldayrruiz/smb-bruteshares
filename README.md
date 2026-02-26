# SMB BruteShares 🔓

> **SMB Share Enumerator / Brute-Forcer** — dictionary-based share discovery over SMB with Active Directory support.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Metasploit](https://img.shields.io/badge/Metasploit-Module-red.svg)](https://www.metasploit.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

---

## 📖 Description

**SMB BruteShares** is a tool for enumerating SMB/CIFS share names on a target host using a wordlist.  
It supports both **null/anonymous sessions** and **authenticated access**, as well as **Active Directory domain** scoping.

The project ships two files serving different purposes:

| File | Purpose |
|---|---|
| `smb_bruteshares.py` | Standalone Python 3 script — run it directly from your terminal |
| `smb_bruteshares.rb` | Ruby module — designed to be **imported into Metasploit Framework** as an auxiliary scanner |

---

## 🚀 Features

- 🔑 Authenticated and anonymous (null session) modes
- 🏢 Active Directory domain / workgroup support (`-d`)
- 📋 Custom share-name wordlist
- 💾 Save results to an output file
- 🎨 Coloured terminal output (green = accessible, red = denied)
- 🖼️ ASCII banner (suppressed with `--no-banner`)
- 🔇 Verbose mode to show raw `smbclient` commands
- 🧩 Metasploit module with loot storage and multi-host scanning
- 🐳 Docker support — run with zero local setup required

---

## 📋 Requirements

### Python script (`smb_bruteshares.py`)

| Dependency | Notes |
|---|---|
| Python ≥ 3.8 | Standard library used |
| `smbclient` | System tool — install via your package manager |
| `colorama` | Optional — for coloured output |

```bash
# Install system dependency (Debian/Ubuntu)
sudo apt install smbclient

# Install Python dependency
pip install -r requirements.txt
```

### Metasploit module (`smb_bruteshares.rb`)

| Dependency | Notes |
|---|---|
| Metasploit Framework | Full installation required |
| `ruby_smb` gem | Bundled with Metasploit |

### Docker

| Dependency | Notes |
|---|---|
| Docker ≥ 20.10 | Engine or Docker Desktop |

No other local dependencies needed — `smbclient` and `colorama` are installed inside the image.

---

## ⚙️ Installation

### Python script

```bash
git clone https://github.com/aldayrruiz/smb-bruteshares.git
cd smb-bruteshares
pip install -r requirements.txt
python3 smb_bruteshares.py --help
```

### Docker

```bash
git clone https://github.com/aldayrruiz/smb-bruteshares.git
cd smb-bruteshares
docker build -t smb-bruteshares .
```

### Metasploit module

```bash
cp smb_bruteshares.rb ~/.msf4/modules/auxiliary/scanner/smb/smb_share_brute.rb
msfconsole -q -x "reload_all"
use auxiliary/scanner/smb/smb_share_brute
```

---

## 🖥️ Usage

### Python script

```
python3 smb_bruteshares.py -t <TARGET> -w <WORDLIST> [OPTIONS]

Options:
  -t, --target      Target IP address or hostname
  -d, --domain      Active Directory domain / workgroup (e.g. corp.local)
  -u, --username    SMB username
  -p, --password    SMB password
  -a, --anonymous   Use null/anonymous session (overrides -u / -p)
  -w, --wordlist    Path to share-name wordlist (one share per line)
  -o, --output      Save results to file
  -v, --verbose     Show denied shares and raw smbclient commands
      --no-banner   Suppress the ASCII art banner
```

**Examples:**

```bash
# Anonymous session
python3 smb_bruteshares.py -t 192.168.1.10 -w wordlists/shares.txt -a

# Authenticated with domain
python3 smb_bruteshares.py -t 192.168.1.10 -w wordlists/shares.txt \
    -u Administrator -p 'P@ssw0rd' -d corp.local -o results.txt

# Verbose mode
python3 smb_bruteshares.py -t 192.168.1.10 -w wordlists/shares.txt -a -v
```

### Docker

Wordlists on the host are mounted with `-v`. Results can also be saved inside the container and copied out, or piped to a host path.

```bash
# Anonymous session (wordlist on host)
docker run --rm \
  -v /path/to/wordlists:/wordlists \
  smb-bruteshares \
  -t 192.168.1.10 -w /wordlists/shares.txt -a

# Authenticated with domain, save results to host
docker run --rm \
  -v /path/to/wordlists:/wordlists \
  -v $(pwd)/output:/output \
  smb-bruteshares \
  -t 192.168.1.10 -w /wordlists/shares.txt \
  -u Administrator -p 'P@ssw0rd' -d corp.local \
  -o /output/results.txt

# Show help
docker run --rm smb-bruteshares
```

> **Note:** Because Docker networking is host-agnostic, make sure the container can reach the target.
> On Linux you can add `--network host` to use the host's network stack directly.

### Metasploit module

```
msf6 > use auxiliary/scanner/smb/smb_share_brute
msf6 auxiliary(smb_share_brute) > set RHOSTS 192.168.1.10
msf6 auxiliary(smb_share_brute) > set WORDLIST /usr/share/wordlists/smbshares.txt
msf6 auxiliary(smb_share_brute) > set SMBUser Administrator
msf6 auxiliary(smb_share_brute) > set SMBPass P@ssw0rd
msf6 auxiliary(smb_share_brute) > set SMBDomain corp.local
msf6 auxiliary(smb_share_brute) > run
```

---

## ⚠️ Disclaimer

> This tool is intended for **legal penetration testing and security research only**.  
> Always obtain **explicit written permission** from the target system owner before use.  
> The author assumes **no liability** for any misuse or damage caused by this tool.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙌 Credits

Developed by **[xSmaky](https://github.com/xSmaky)**
