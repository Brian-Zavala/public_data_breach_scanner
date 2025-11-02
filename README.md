# 🚀 Ultra Breach Reconnaissance System

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

**The most comprehensive personal data exposure checker on Earth**

Scan every digital corner to find where your data has been compromised

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Usage](#usage) • [FAQ](#faq)

</div>

---

## 📖 What Does This Do?

Ultra Breach Reconnaissance System is an automated security tool that checks if your personal information has been exposed in data breaches across the internet. It combines multiple data sources and OSINT techniques to give you a complete picture of your digital footprint.

### 🎯 Key Capabilities

- **Breach Detection**: Checks emails against Have I Been Pwned's database of 12+ billion compromised accounts
- **Password Verification**: Securely checks if your passwords have been leaked (using k-anonymity)
- **Username Tracking**: Scans 30+ social media platforms and services for your username
- **Paste Monitoring**: Searches for your data in public paste sites
- **Phone Intelligence**: Analyzes phone number exposure across data broker sites
- **Social Media Exposure**: Identifies your public profiles and data leakage
- **Dark Web Monitoring**: Provides guidance for checking dark web marketplaces
- **Risk Assessment**: Calculates an overall risk score with actionable recommendations

## ✨ Features

### Automated Checks

- ✅ Have I Been Pwned breach database (12B+ accounts)
- ✅ Pwned Passwords database (850M+ passwords)
- ✅ Public paste sites (Pastebin, etc.)
- ✅ 30+ social media platforms
- ✅ Username exposure tracking
- ✅ Data broker identification
- ✅ NPD (National Public Data) breach lookup

### Manual Check Guidance

- 🔍 Dark web monitoring services
- 🔍 Public records databases
- 🔍 Credit monitoring setup
- 🔍 Identity theft protection services

### Advanced Features

- 📊 Comprehensive risk scoring
- 📝 Detailed breach timeline analysis
- 💾 Result caching for faster re-scans
- 🔐 Tor support for anonymous scanning
- 📄 Exportable reports (TXT, CSV, JSON)
- 🔄 Comparison with previous scans

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Linux OS (tested on Arch, Ubuntu, Debian)
- Internet connection
- HIBP API key (see [Getting an API Key](#getting-an-api-key))

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ultra-breach-scanner.git
cd ultra-breach-scanner

# Install required packages
pip install requests --break-system-packages

# Make the script executable
chmod +x ultra_breach_scanner.py

# Run the scanner
./ultra_breach_scanner.py
```

### Getting an API Key

The Have I Been Pwned API requires a key for breach and paste checks:

1. Visit [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
2. Sign up or log in
3. Purchase an API key ($3.50/month for personal use)
4. Key will be emailed to you
5. Enter it when the script prompts you

**Note**: Password checks work WITHOUT an API key using the free Pwned Passwords API.

## 📚 Usage

### Basic Scan

```bash
./ultra_breach_scanner.py
```

The script will guide you through an interactive setup:

1. **Target Information**: Enter email, name, username, phone, etc.
2. **Scan Mode**: Choose from Quick, Standard, Deep, or ULTRA
3. **Privacy Settings**: Optional Tor routing
4. **API Key**: Enter your HIBP API key (saved for future scans)
5. **Automated Checks**: Sit back while the tool scans
6. **Manual Checks**: Follow guidance for additional verification
7. **Final Report**: Review findings and recommendations

### Scan Modes

| Mode         | Duration   | Description                          |
| ------------ | ---------- | ------------------------------------ |
| **Quick**    | 5-10 mins  | Essential checks only                |
| **Standard** | 15-20 mins | Comprehensive automated checks       |
| **Deep**     | 30-45 mins | Maximum automation + manual guidance |
| **ULTRA**    | 60+ mins   | Everything possible                  |

### Command Line Options

```bash
# Basic scan
./ultra_breach_scanner.py

# With Tor (for privacy)
# Enable Tor routing during setup wizard

# Clear cache
# Delete ~/.ultra_breach_scan/cache/
```

## 📁 Output

Results are saved to `~/.ultra_breach_scan/`:

```
~/.ultra_breach_scan/
├── cache/              # Cached API results
├── config.txt          # Saved API key
├── scan_YYYYMMDD_HHMMSS.json  # Full scan results
└── report_[scan_id].txt       # Human-readable report
```

## 🔐 Privacy & Security

### What We Send

- **Email addresses**: Sent to HIBP API (encrypted in transit)
- **Passwords**: Only first 5 characters of SHA-1 hash sent (k-anonymity)
- **Usernames**: Checked via public HTTP requests

### What We DON'T Send

- Full passwords (only hashed)
- Payment information
- Sensitive personal data

### Tor Support

Route all traffic through Tor for additional anonymity:

- Hides your IP address
- Prevents tracking
- Note: HIBP may block Tor; script auto-falls back to direct connection

### Data Storage

- All results stored locally in `~/.ultra_breach_scan/`
- Files are chmod 600 (read/write for owner only)
- No cloud uploads or external logging

## 🛠️ Troubleshooting

### "Network Error" for HIBP Checks

**Problem**: Getting network errors for breach/paste checks, but password checks work.

**Solution**: You need an HIBP API key. Breach and paste checks require authentication, but password checks don't.

```bash
# Get a key at:
https://haveibeenpwned.com/API/Key

# The script will prompt you to enter it
```

### Tor Connection Issues

**Problem**: Tor fails to start or connect.

**Solutions**:

```bash
# Install Tor
sudo pacman -S tor  # Arch
sudo apt install tor  # Debian/Ubuntu

# Start Tor service
sudo systemctl start tor

# Check Tor status
systemctl status tor
```

### Rate Limiting

**Problem**: Getting 429 errors from APIs.

**Solutions**:

- The script has built-in retry logic with exponential backoff
- For HIBP: Wait 1.6 seconds between requests (built-in)
- If persistent: Wait a few hours and try again

### Permission Denied on Output Files

**Problem**: Cannot write to `~/.ultra_breach_scan/`.

**Solution**:

```bash
# Ensure directory exists and has correct permissions
mkdir -p ~/.ultra_breach_scan
chmod 700 ~/.ultra_breach_scan
```

## 🎨 Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚀 ULTRA BREACH RECONNAISSANCE SYSTEM 🚀
  🌍 Scanning Every Digital Corner of Planet Earth 🌍
  ⚡ Maximum Automation • Zero Missed Details ⚡
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════════════════════╗
║                     RISK ASSESSMENT                              ║
╚══════════════════════════════════════════════════════════════════╝

Risk Score: 67/100
[████████████████████████████████████░░░░░░░░░] HIGH RISK

EXPOSURE SUMMARY
────────────────────────────────────────────────────────────────────
🔥 Data Breaches: 8
📄 Public Pastes: 2
🔑 Compromised Passwords: 1
🔍 Automated Checks Completed: 23
👀 Manual Checks Required: 15

RECOMMENDED ACTIONS
════════════════════════════════════════════════════════════════════

  ⚠️ HIGH RISK: Significant exposure detected

  → Set up fraud alerts with credit bureaus
  → Enable 2FA on important accounts
  → Change passwords for exposed accounts
  → Monitor credit reports monthly
  → Review account statements regularly
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Ideas for Contributions

- Additional data source integrations
- Improved caching mechanisms
- GUI/web interface
- Docker containerization
- Automated remediation suggestions
- Integration with password managers
- More detailed reporting options

## 📋 FAQ

### Q: Is this tool free?

**A**: The tool itself is free and open source. However, the HIBP API requires a paid key ($3.50/month) for breach/paste checks. Password checking is completely free.

### Q: Will this expose my passwords?

**A**: No. Passwords are hashed using SHA-1, and only the first 5 characters of the hash are sent to the API. This is called k-anonymity and ensures your actual password never leaves your machine.

### Q: How often should I run this?

**A**: Monthly scans are recommended. Set up a cron job if you want automation:

```bash
# Run on the 1st of every month at 3am
0 3 1 * * /path/to/ultra_breach_scanner.py
```

### Q: Can I scan multiple emails at once?

**A**: Yes! During setup, you'll be asked if you have additional emails to check.

### Q: What's the difference between this and going to haveibeenpwned.com?

**A**: This tool provides:

- Automated checking across multiple services
- Username tracking across 30+ platforms
- Risk scoring and recommendations
- Result caching and historical comparison
- Dark web monitoring guidance
- Privacy via Tor routing

### Q: Is my data uploaded anywhere?

**A**: No. All results are stored locally in `~/.ultra_breach_scan/`. The only data sent externally is to the HIBP API (for breach checks) and public websites (for username checks).

## ⚠️ Disclaimer

This tool is for **educational and personal security purposes only**.

- Use responsibly and ethically
- Only scan your own data or data you have permission to check
- The author is not responsible for misuse of this tool
- Results are based on publicly available data and may not be 100% complete
- This tool does not guarantee protection against identity theft

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com) by Troy Hunt
- [Sherlock Project](https://github.com/sherlock-project/sherlock) for username enumeration inspiration
- The open-source security community

## 📧 Contact

- **Author**: Brian Zavala
- **Location**: Victoria, TX
- **GitHub**: [@yourusername](https://github.com/yourusername)

---

<div align="center">

**⭐ If you find this tool useful, please star the repository! ⭐**

Made with ❤️ and ☕ in South Texas

</div>
