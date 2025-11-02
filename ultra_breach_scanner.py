#!/usr/bin/env python3
"""
ULTRA BREACH RECONNAISSANCE SYSTEM v3.0
The most comprehensive personal data exposure checker on Earth
Checks every digital nook and cranny across the planet
"""

import requests
import time
import sys
import os
import subprocess
import hashlib
import re
import getpass
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse


class Style:
    """Ultra modern styling with Unicode"""

    # Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Symbols
    ROCKET = "🚀"
    SHIELD = "🛡️"
    WARNING = "⚠️"
    CHECK = "✓"
    CROSS = "✗"
    SEARCH = "🔍"
    LOCK = "🔒"
    KEY = "🔑"
    FIRE = "🔥"
    SKULL = "💀"
    EYES = "👀"
    GLOBE = "🌍"
    SATELLITE = "🛰️"
    DATABASE = "🗄️"
    FINGERPRINT = "👆"
    CAMERA = "📸"
    PHONE = "📱"
    EMAIL = "📧"
    USER = "👤"
    CLOCK = "⏱️"
    ARROW = "→"
    STAR = "⭐"
    LIGHTNING = "⚡"
    TARGET = "🎯"
    BRAIN = "🧠"
    CHART = "📊"
    DOCUMENT = "📄"


class UltraBreachScanner:
    def __init__(self):
        self.session = None
        self.use_tor = False
        self.aggressive_mode = False
        self.output_dir = os.path.join(os.path.expanduser("~"), ".ultra_breach_scan")
        self.cache_dir = os.path.join(self.output_dir, "cache")
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "scan_id": hashlib.sha256(
                str(datetime.now().timestamp()).encode()
            ).hexdigest()[:12],
            "target_info": {},
            "automated_checks": [],
            "manual_checks": [],
            "breaches_found": [],
            "pastes_found": [],
            "social_media_exposure": [],
            "phone_intel": [],
            "username_intel": [],
            "dark_web_mentions": [],
            "public_records": [],
            "risk_assessment": {},
            "recommendations": [],
        }
        self.checks_completed = 0
        self.total_checks = 0

        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

    def _validate_email(self, email: str) -> Tuple[bool, str]:
        """Validate email format - returns (is_valid, error_message)"""
        if not email:
            return False, "Email cannot be empty"

        if "@" not in email:
            return False, "Email must contain @"

        if email.count("@") > 1:
            return False, "Email contains too many @ symbols"

        local, domain = email.rsplit("@", 1)

        if not local or not domain:
            return False, "Invalid email format"

        if "." not in domain:
            return False, "Domain must contain at least one dot"

        # Basic character validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return False, "Email contains invalid characters"

        return True, ""

    def _validate_phone(self, phone: str) -> Tuple[bool, str]:
        """Validate phone number - returns (is_valid, error_message)"""
        if not phone:
            return False, "Phone cannot be empty"

        # Remove all non-digit characters for validation
        digits = re.sub(r"\D", "", phone)

        if len(digits) < 10:
            return False, "Phone number too short (need at least 10 digits)"

        if len(digits) > 15:
            return False, "Phone number too long (max 15 digits)"

        return True, ""

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username - returns (is_valid, error_message)"""
        if not username:
            return False, "Username cannot be empty"

        if len(username) < 2:
            return False, "Username too short (min 2 characters)"

        if len(username) > 50:
            return False, "Username too long (max 50 characters)"

        # Check for valid characters (alphanumeric, underscore, hyphen)
        if not re.match(r"^[a-zA-Z0-9_-]+$", username):
            return (
                False,
                "Username contains invalid characters (only letters, numbers, _, - allowed)",
            )

        return True, ""

    def _sanitize_input(self, text: str) -> str:
        """Sanitize user input to prevent injection"""
        if not text:
            return ""

        # Strip whitespace
        text = text.strip()

        # Remove any null bytes
        text = text.replace("\x00", "")

        # Remove control characters except newline and tab
        text = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", "", text)

        return text

    def _get_cache_path(self, cache_key: str) -> str:
        """Get cache file path for a given key"""
        # Hash the key for consistent filename
        key_hash = hashlib.md5(cache_key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{key_hash}.cache")

    def _cache_get(self, cache_key: str, max_age_hours: int = 24) -> Optional[Dict]:
        """Get cached result if exists and not expired"""
        cache_path = self._get_cache_path(cache_key)

        try:
            if not os.path.exists(cache_path):
                return None

            # Check if cache is expired
            file_age = time.time() - os.path.getmtime(cache_path)
            if file_age > (max_age_hours * 3600):
                os.remove(cache_path)
                return None

            # Load cache
            with open(cache_path, "r") as f:
                import json

                return json.load(f)

        except Exception as e:
            self._status(f"Cache read error: {e}", "warning")
            return None

    def _cache_set(self, cache_key: str, data: Dict):
        """Save result to cache"""
        cache_path = self._get_cache_path(cache_key)

        try:
            import json

            with open(cache_path, "w") as f:
                json.dump(data, f)
            os.chmod(cache_path, 0o600)
        except Exception as e:
            self._status(f"Cache write error: {e}", "warning")

    def _cache_clear(self):
        """Clear all cached results"""
        try:
            for filename in os.listdir(self.cache_dir):
                filepath = os.path.join(self.cache_dir, filename)
                if os.path.isfile(filepath) and filename.endswith(".cache"):
                    os.remove(filepath)
            self._status("Cache cleared", "success")
        except Exception as e:
            self._status(f"Cache clear error: {e}", "warning")

    def _generate_email_permutations(self, email: str) -> List[str]:
        """Generate common email permutations for comprehensive checking"""
        if not email or "@" not in email:
            return []

        local, domain = email.rsplit("@", 1)
        permutations = []

        # Common dot variations
        if "." in local:
            # Remove dots (some services ignore dots in local part)
            permutations.append(f"{local.replace('.', '')}@{domain}")

        # Plus addressing variations (Gmail style)
        if "+" in local:
            # Base email without plus addressing
            base_local = local.split("+")[0]
            permutations.append(f"{base_local}@{domain}")

        # Common number variations if email ends with numbers
        import re

        if re.search(r"\d+$", local):
            base = re.sub(r"\d+$", "", local)
            for i in range(1, 10):
                permutations.append(f"{base}{i}@{domain}")

        # Remove duplicates and original
        permutations = list(set(permutations))
        if email in permutations:
            permutations.remove(email)

        return permutations[:5]  # Limit to 5 to avoid rate limiting

    def _analyze_domain(self, email: str) -> Dict:
        """Analyze email domain for intelligence"""
        if not email or "@" not in email:
            return {}

        local, domain = email.rsplit("@", 1)

        analysis = {
            "domain": domain,
            "local_part": local,
            "is_common_provider": False,
            "provider_type": "unknown",
            "privacy_rating": "unknown",
        }

        # Common providers
        common_providers = {
            "gmail.com": {
                "type": "freemail",
                "privacy": "medium",
                "provider": "Google",
            },
            "yahoo.com": {"type": "freemail", "privacy": "medium", "provider": "Yahoo"},
            "outlook.com": {
                "type": "freemail",
                "privacy": "medium",
                "provider": "Microsoft",
            },
            "hotmail.com": {
                "type": "freemail",
                "privacy": "medium",
                "provider": "Microsoft",
            },
            "protonmail.com": {
                "type": "freemail",
                "privacy": "high",
                "provider": "Proton",
            },
            "proton.me": {"type": "freemail", "privacy": "high", "provider": "Proton"},
            "icloud.com": {
                "type": "freemail",
                "privacy": "medium",
                "provider": "Apple",
            },
            "aol.com": {"type": "freemail", "privacy": "low", "provider": "AOL"},
            "mail.com": {
                "type": "freemail",
                "privacy": "medium",
                "provider": "Mail.com",
            },
        }

        domain_lower = domain.lower()
        if domain_lower in common_providers:
            analysis["is_common_provider"] = True
            analysis["provider_type"] = common_providers[domain_lower]["type"]
            analysis["privacy_rating"] = common_providers[domain_lower]["privacy"]
            analysis["provider_name"] = common_providers[domain_lower]["provider"]
        else:
            # Check if it's a custom domain
            analysis["provider_type"] = "custom_domain"
            analysis["privacy_rating"] = "depends_on_config"

        # Check for disposable email indicators
        disposable_keywords = [
            "temp",
            "throw",
            "disposable",
            "guerrilla",
            "10minute",
            "mailinator",
        ]
        if any(keyword in domain_lower for keyword in disposable_keywords):
            analysis["is_disposable"] = True
            analysis["privacy_rating"] = "high"

        return analysis

    def check_email_permutations(self, base_email: str) -> Dict:
        """Check common email permutations for breaches"""
        self._status(f"Generating email permutations for {base_email[:20]}...", "info")

        permutations = self._generate_email_permutations(base_email)

        if not permutations:
            return {"permutations_checked": 0, "results": []}

        self._status(f"Found {len(permutations)} permutations to check", "info")

        results = []
        for perm_email in permutations:
            # Check cache first
            cache_key = f"hibp_breach_{perm_email}"
            cached = self._cache_get(cache_key, max_age_hours=48)

            if cached:
                self._status(f"Using cached result for {perm_email[:20]}", "info")
                results.append({"email": perm_email, "cached": True, **cached})
            else:
                # Check for real
                result = self.check_haveibeenpwned(perm_email)
                result["email"] = perm_email
                results.append(result)

                # Cache result
                self._cache_set(cache_key, result)

                time.sleep(2)  # Rate limiting

        return {"permutations_checked": len(permutations), "results": results}

    def analyze_breach_timeline(self, breaches: List[Dict]) -> Dict:
        """Analyze breach timeline and patterns"""
        if not breaches:
            return {}

        from collections import defaultdict

        timeline = {
            "total_breaches": len(breaches),
            "by_year": defaultdict(int),
            "by_severity": defaultdict(int),
            "data_types_exposed": defaultdict(int),
            "earliest_breach": None,
            "latest_breach": None,
            "most_severe": None,
        }

        for breach in breaches:
            # Parse breach date
            breach_date = breach.get("BreachDate", "")
            if breach_date:
                try:
                    year = breach_date.split("-")[0]
                    timeline["by_year"][year] += 1

                    # Track earliest and latest
                    if (
                        not timeline["earliest_breach"]
                        or breach_date < timeline["earliest_breach"]["date"]
                    ):
                        timeline["earliest_breach"] = {
                            "name": breach.get("Name"),
                            "date": breach_date,
                        }

                    if (
                        not timeline["latest_breach"]
                        or breach_date > timeline["latest_breach"]["date"]
                    ):
                        timeline["latest_breach"] = {
                            "name": breach.get("Name"),
                            "date": breach_date,
                        }
                except:
                    pass

            # Analyze data types
            for data_class in breach.get("DataClasses", []):
                timeline["data_types_exposed"][data_class] += 1

            # Track severity
            pwn_count = breach.get("PwnCount", 0)
            if pwn_count > 100000000:
                timeline["by_severity"]["massive"] += 1
            elif pwn_count > 10000000:
                timeline["by_severity"]["large"] += 1
            elif pwn_count > 1000000:
                timeline["by_severity"]["medium"] += 1
            else:
                timeline["by_severity"]["small"] += 1

            # Track most severe
            if (
                not timeline["most_severe"]
                or pwn_count > timeline["most_severe"]["count"]
            ):
                timeline["most_severe"] = {
                    "name": breach.get("Name"),
                    "count": pwn_count,
                    "date": breach_date,
                }

        return dict(timeline)

    def compare_with_previous_scan(self, current_results: Dict) -> Optional[Dict]:
        """Compare current scan with previous scan if exists"""
        try:
            # Find most recent previous scan
            scan_files = []
            for filename in os.listdir(self.output_dir):
                if filename.startswith("scan_") and filename.endswith(".json"):
                    filepath = os.path.join(self.output_dir, filename)
                    scan_files.append((filepath, os.path.getmtime(filepath)))

            if not scan_files:
                return None

            # Get most recent (excluding current)
            scan_files.sort(key=lambda x: x[1], reverse=True)
            if len(scan_files) < 2:
                return None

            previous_scan_path = scan_files[1][0]

            import json

            with open(previous_scan_path, "r") as f:
                previous_results = json.load(f)

            comparison = {
                "previous_scan_date": previous_results.get("timestamp"),
                "current_scan_date": current_results.get("timestamp"),
                "changes": {
                    "new_breaches": [],
                    "new_pastes": [],
                    "breach_count_change": 0,
                    "paste_count_change": 0,
                },
            }

            # Compare breach counts
            prev_breach_count = sum(
                [
                    r.get("count", 0)
                    for r in previous_results.get("automated_checks", [])
                    if r.get("type") == "breach"
                ]
            )
            curr_breach_count = sum(
                [
                    r.get("count", 0)
                    for r in current_results.get("automated_checks", [])
                    if r.get("type") == "breach"
                ]
            )

            comparison["changes"]["breach_count_change"] = (
                curr_breach_count - prev_breach_count
            )

            # Compare paste counts
            prev_paste_count = sum(
                [
                    r.get("count", 0)
                    for r in previous_results.get("automated_checks", [])
                    if r.get("type") == "paste"
                ]
            )
            curr_paste_count = sum(
                [
                    r.get("count", 0)
                    for r in current_results.get("automated_checks", [])
                    if r.get("type") == "paste"
                ]
            )

            comparison["changes"]["paste_count_change"] = (
                curr_paste_count - prev_paste_count
            )

            return comparison

        except Exception as e:
            self._status(f"Could not compare with previous scan: {e}", "warning")
            return None

    def save_scan_results(self) -> str:
        """Save complete scan results as JSON for future comparison"""
        try:
            import json

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f"scan_{timestamp}.json")

            with open(filename, "w") as f:
                json.dump(self.results, f, indent=2, default=str)

            os.chmod(filename, 0o600)
            return filename
        except Exception as e:
            self._status(f"Could not save scan results: {e}", "error")
            return ""

    def print_header(self):
        """Ultra creative header"""
        print(f"\n{Style.CYAN}{Style.BOLD}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"  {Style.ROCKET} ULTRA BREACH RECONNAISSANCE SYSTEM {Style.ROCKET}")
        print(
            f"  {Style.GLOBE} Scanning Every Digital Corner of Planet Earth {Style.GLOBE}"
        )
        print(
            f"  {Style.LIGHTNING} Maximum Automation • Zero Missed Details {Style.LIGHTNING}"
        )
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Style.RESET}\n")

        self._typewriter(
            f"{Style.DIM}Initializing reconnaissance systems...{Style.RESET}", 0.02
        )
        time.sleep(0.3)

    def _typewriter(self, text: str, delay: float = 0.03):
        """Typewriter effect"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    def _prompt(
        self, question: str, default: str = None, options: List[str] = None
    ) -> str:
        """Modern interactive prompt"""
        if options:
            print(
                f"\n{Style.CYAN}{Style.FINGERPRINT}{Style.RESET} {Style.BOLD}{question}{Style.RESET}"
            )
            for i, option in enumerate(options, 1):
                print(f"  {Style.DIM}{i}.{Style.RESET} {option}")
            choice = input(
                f"\n{Style.CYAN}{Style.ARROW}{Style.RESET} Select (1-{len(options)}): "
            ).strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            except:
                pass
            return options[0] if default is None else default

        if default:
            prompt_text = f"{Style.CYAN}{Style.FINGERPRINT}{Style.RESET} {Style.BOLD}{question}{Style.RESET} {Style.DIM}({default}){Style.RESET}\n{Style.CYAN}{Style.ARROW}{Style.RESET} "
        else:
            prompt_text = f"{Style.CYAN}{Style.FINGERPRINT}{Style.RESET} {Style.BOLD}{question}{Style.RESET}\n{Style.CYAN}{Style.ARROW}{Style.RESET} "

        value = input(prompt_text).strip()
        return value if value else (default or "")

    def _confirm(self, question: str, default: bool = True) -> bool:
        """Confirmation prompt"""
        default_hint = (
            f"{Style.GREEN}Y{Style.RESET}/{Style.DIM}n{Style.RESET}"
            if default
            else f"{Style.DIM}y{Style.RESET}/{Style.RED}N{Style.RESET}"
        )
        prompt_text = f"{Style.CYAN}{Style.TARGET}{Style.RESET} {Style.BOLD}{question}{Style.RESET} ({default_hint})\n{Style.CYAN}{Style.ARROW}{Style.RESET} "

        response = input(prompt_text).strip().lower()

        if not response:
            return default
        return response in ["y", "yes", "yeah", "yep", "sure"]

    def _status(self, message: str, status: str = "info"):
        """Status message"""
        icons = {
            "info": f"{Style.BLUE}{Style.SEARCH}{Style.RESET}",
            "success": f"{Style.GREEN}{Style.CHECK}{Style.RESET}",
            "error": f"{Style.RED}{Style.CROSS}{Style.RESET}",
            "warning": f"{Style.YELLOW}{Style.WARNING}{Style.RESET}",
            "found": f"{Style.RED}{Style.FIRE}{Style.RESET}",
            "secure": f"{Style.GREEN}{Style.SHIELD}{Style.RESET}",
            "critical": f"{Style.RED}{Style.SKULL}{Style.RESET}",
        }
        print(f"{icons.get(status, icons['info'])} {message}")

    def _progress(self, current: int, total: int, message: str = ""):
        """Ultra modern progress bar"""
        bar_length = 50
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        percent = int(100 * current / total)

        sys.stdout.write(
            f"\r{Style.CYAN}[{bar}]{Style.RESET} {percent}% {Style.DIM}{message}{Style.RESET}"
        )
        sys.stdout.flush()

        if current == total:
            print(f" {Style.GREEN}{Style.CHECK}{Style.RESET}")

    def _section_header(self, title: str, icon: str = None):
        """Section header"""
        icon_str = icon if icon else Style.LIGHTNING
        print(f"\n{Style.BOLD}{Style.PURPLE}{'─' * 70}{Style.RESET}")
        print(f"{Style.BOLD}{Style.PURPLE}{icon_str} {title}{Style.RESET}")
        print(f"{Style.BOLD}{Style.PURPLE}{'─' * 70}{Style.RESET}\n")

    def _build_search_url(self, base_url: str, params: Dict[str, str]) -> str:
        """Build properly encoded search URL using urllib.parse"""
        query_string = urllib.parse.urlencode(params)
        return f"{base_url}?{query_string}"

    def _parse_url_components(self, url: str) -> Tuple[str, str, Dict[str, List[str]]]:
        """Parse URL into components using urllib.parse - returns (scheme, netloc, params)"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return parsed.scheme, parsed.netloc, params

    def setup_wizard(self) -> Dict[str, Any]:
        """Interactive setup wizard with input validation"""
        self._section_header("RECONNAISSANCE CONFIGURATION", Style.BRAIN)

        config = {}

        # Basic target info
        self._status("Let's gather information about the target", "info")
        print()

        # Email with validation
        while True:
            email = self._sanitize_input(self._prompt("Primary email address"))
            if email:
                is_valid, error = self._validate_email(email)
                if is_valid:
                    config["email"] = email
                    break
                else:
                    self._status(f"Invalid email: {error}", "error")
            else:
                if self._confirm("Skip email? (not recommended)", False):
                    config["email"] = ""
                    break

        config["additional_emails"] = []

        if config["email"] and self._confirm(
            "Do you have additional email addresses to check?", False
        ):
            while True:
                email = self._sanitize_input(
                    self._prompt("Additional email (leave blank to continue)")
                )
                if not email:
                    break
                is_valid, error = self._validate_email(email)
                if is_valid:
                    config["additional_emails"].append(email)
                else:
                    self._status(f"Invalid email: {error}", "error")

        config["full_name"] = self._sanitize_input(
            self._prompt("Full name (First Last)", "")
        )

        # Username with validation
        username = self._sanitize_input(self._prompt("Common username/handle", ""))
        if username:
            is_valid, error = self._validate_username(username)
            if is_valid:
                config["username"] = username
            else:
                self._status(f"Invalid username: {error}", "warning")
                config["username"] = ""
        else:
            config["username"] = ""

        # Phone with validation
        phone = self._sanitize_input(self._prompt("Phone number", ""))
        if phone:
            is_valid, error = self._validate_phone(phone)
            if is_valid:
                config["phone"] = phone
            else:
                self._status(f"Invalid phone: {error}", "warning")
                config["phone"] = ""
        else:
            config["phone"] = ""

        config["date_of_birth"] = self._sanitize_input(
            self._prompt("Date of birth (YYYY-MM-DD)", "")
        )
        config["address"] = self._sanitize_input(
            self._prompt("Current address (City, State)", "")
        )
        config["previous_addresses"] = self._sanitize_input(
            self._prompt("Previous addresses (comma separated)", "")
        )

        print()
        self._section_header("SCAN CONFIGURATION", Style.SATELLITE)

        # Scan depth
        scan_modes = [
            "Quick Scan (5-10 mins, essential checks only)",
            "Standard Scan (15-20 mins, comprehensive automated checks)",
            "Deep Scan (30-45 mins, maximum automation + manual guidance)",
            "ULTRA Scan (60+ mins, EVERYTHING possible)",
        ]

        config["scan_mode"] = self._prompt("Select scan depth", options=scan_modes)

        # Privacy settings
        print()
        self._status("Note: Have I Been Pwned blocks Tor to prevent abuse", "info")
        self._status(
            "HIBP checks will automatically fallback to direct connection if Tor fails",
            "info",
        )
        config["use_tor"] = self._confirm(
            "Route traffic through Tor for anonymity?", False
        )

        if config["use_tor"]:
            self._status(
                "Tor enabled for username/social checks (HIBP will auto-fallback if blocked)",
                "info",
            )

        config["aggressive_mode"] = self._confirm(
            "Enable aggressive scanning? (faster but more detectable)", False
        )

        # Password checking
        config["check_passwords"] = self._confirm(
            "Check if your passwords have been compromised?", True
        )
        config["passwords"] = []

        if config["check_passwords"]:
            while True:
                if self._confirm("Add a password to check?", True):
                    pwd = getpass.getpass(
                        f"{Style.CYAN}{Style.KEY}{Style.RESET} Enter password (hidden): "
                    )
                    if pwd:
                        config["passwords"].append(pwd)
                else:
                    break

        # Social media
        config["check_social"] = self._confirm(
            "Scan social media platforms for exposure?", True
        )

        if config["check_social"]:
            platforms = []
            social_options = [
                "Twitter/X",
                "Facebook",
                "Instagram",
                "LinkedIn",
                "TikTok",
                "Reddit",
                "GitHub",
                "Discord",
            ]

            print(
                f"\n{Style.DIM}Select platforms to check (comma separated numbers or 'all'):{Style.RESET}"
            )
            for i, platform in enumerate(social_options, 1):
                print(f"  {i}. {platform}")

            selection = (
                input(f"\n{Style.CYAN}{Style.ARROW}{Style.RESET} ").strip().lower()
            )

            if selection == "all":
                platforms = social_options
            else:
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(",")]
                    platforms = [
                        social_options[i]
                        for i in indices
                        if 0 <= i < len(social_options)
                    ]
                except:
                    platforms = social_options

            config["social_platforms"] = platforms

        # Advanced options
        config["check_darkweb"] = self._confirm(
            "Include dark web monitoring? (manual guidance)", True
        )
        config["check_public_records"] = self._confirm(
            "Check public records databases?", True
        )
        config["generate_report"] = self._confirm(
            "Generate detailed PDF report at the end?", True
        )
        config["save_results"] = self._confirm(
            "Save results for future comparison?", True
        )

        self.results["target_info"] = config
        return config

    def _setup_session(self, use_tor: bool = False):
        """Setup HTTP session with Tor support"""
        self.use_tor = use_tor
        self.session = requests.Session()

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "application/json, text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
        }
        self.session.headers.update(headers)

        if use_tor:
            if not self._check_tor():
                self._status("Tor not running, attempting to start...", "warning")
                try:
                    subprocess.run(
                        ["sudo", "systemctl", "start", "tor"],
                        check=True,
                        capture_output=True,
                    )
                    time.sleep(3)
                    if self._check_tor():
                        self._status("Tor started successfully", "success")
                    else:
                        self._status(
                            "Failed to start Tor, continuing without it", "error"
                        )
                        return
                except Exception as e:
                    self._status(f"Could not start Tor: {e}", "error")
                    return

            self.session.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050",
            }

            # Verify Tor
            try:
                test = self.session.get(
                    "https://check.torproject.org/api/ip", timeout=15
                )
                if test.status_code == 200 and test.json().get("IsTor"):
                    self._status("Tor connection verified and active", "success")
                else:
                    self._status("Tor verification failed", "warning")
            except:
                self._status("Could not verify Tor connection", "warning")

    def _check_tor(self) -> bool:
        """Check if Tor is running"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "tor"], capture_output=True, text=True
            )
            return result.stdout.strip() == "active"
        except:
            try:
                result = subprocess.run(["pgrep", "-x", "tor"], capture_output=True)
                return result.returncode == 0
            except:
                return False

    def _retry_request(
        self, url: str, max_retries: int = 3
    ) -> Optional[requests.Response]:
        """Robust retry mechanism"""
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, timeout=20)
                if response.status_code == 429:
                    wait_time = (2**attempt) + (attempt * 0.5)
                    self._status(
                        f"Rate limited, waiting {wait_time:.1f}s...", "warning"
                    )
                    time.sleep(wait_time)
                    continue
                return response
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    self._status(
                        f"Request failed after {max_retries} attempts", "error"
                    )
                    return None
                time.sleep(2**attempt)
        return None

    def calculate_total_checks(self, config: Dict) -> int:
        """Calculate total number of checks based on config"""
        total = 0

        # Email checks
        total += len([config["email"]] + config.get("additional_emails", [])) * 3

        # Password checks
        total += len(config.get("passwords", []))

        # Username checks
        if config.get("username"):
            total += 5

        # Phone checks
        if config.get("phone"):
            total += 3

        # Social media
        if config.get("check_social"):
            total += len(config.get("social_platforms", []))

        # Additional checks based on scan mode
        mode = config.get("scan_mode", "")
        if "Quick" in mode:
            total += 5
        elif "Standard" in mode:
            total += 15
        elif "Deep" in mode:
            total += 30
        elif "ULTRA" in mode:
            total += 50

        return total

    # ═══════════════════════════════════════════════════════════════
    # AUTOMATED CHECKS
    # ═══════════════════════════════════════════════════════════════

    def check_haveibeenpwned(self, email: str, retry_without_tor: bool = True) -> Dict:
        """Check Have I Been Pwned API with robust error handling and intelligent Tor fallback"""
        self._status(f"Checking HIBP for {email[:20]}...", "info")

        try:
            # Validate email format
            if not email or "@" not in email:
                self._status("Invalid email format", "error")
                return {
                    "found": False,
                    "breaches": [],
                    "count": 0,
                    "error": True,
                    "error_type": "invalid_email",
                }

            # Use urllib.parse to properly encode email
            encoded_email = urllib.parse.quote(email)
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"

            response = self._retry_request(url)

            self.checks_completed += 1
            self._progress(
                self.checks_completed, self.total_checks, "HIBP breach check"
            )

            if response and response.status_code == 200:
                try:
                    breaches = response.json()
                    if not isinstance(breaches, list):
                        self._status("Unexpected API response format", "warning")
                        return {
                            "found": False,
                            "breaches": [],
                            "count": 0,
                            "error": True,
                        }

                    self._status(f"Found in {len(breaches)} breaches!", "found")
                    return {
                        "found": True,
                        "breaches": breaches,
                        "count": len(breaches),
                        "checked": True,
                    }
                except ValueError as e:
                    self._status(f"Failed to parse API response: {e}", "error")
                    return {
                        "found": False,
                        "breaches": [],
                        "count": 0,
                        "error": True,
                        "error_type": "parse_error",
                    }

            elif response and response.status_code == 404:
                self._status("Not found in HIBP breaches", "secure")
                return {"found": False, "breaches": [], "count": 0, "checked": True}

            elif response and response.status_code == 400:
                self._status("Invalid email format (API rejected)", "error")
                return {
                    "found": False,
                    "breaches": [],
                    "count": 0,
                    "error": True,
                    "error_type": "bad_request",
                }

            elif response and response.status_code == 429:
                self._status("Rate limited by API (try again later)", "warning")
                return {
                    "found": False,
                    "breaches": [],
                    "count": 0,
                    "error": True,
                    "error_type": "rate_limited",
                }

            else:
                if not response:
                    # Complete request failure - likely Tor blocking
                    if self.use_tor and retry_without_tor:
                        self._status(
                            "HIBP blocking Tor - retrying without Tor...", "warning"
                        )

                        # Temporarily disable Tor
                        original_proxies = self.session.proxies.copy()
                        self.session.proxies = {}

                        # Retry without Tor
                        retry_response = self._retry_request(url)

                        # Restore Tor for other checks
                        self.session.proxies = original_proxies

                        if retry_response and retry_response.status_code == 200:
                            try:
                                breaches = retry_response.json()
                                if isinstance(breaches, list):
                                    self._status(
                                        f"Success! Found in {len(breaches)} breaches (via direct connection)",
                                        "found",
                                    )
                                    return {
                                        "found": True,
                                        "breaches": breaches,
                                        "count": len(breaches),
                                        "checked": True,
                                        "used_tor_fallback": True,
                                    }
                            except:
                                pass
                        elif retry_response and retry_response.status_code == 404:
                            self._status(
                                "Not found in HIBP breaches (via direct connection)",
                                "secure",
                            )
                            return {
                                "found": False,
                                "breaches": [],
                                "count": 0,
                                "checked": True,
                                "used_tor_fallback": True,
                            }

                        # If retry also failed
                        self._status(
                            "HIBP check failed even without Tor (network issue)",
                            "error",
                        )
                        return {
                            "found": False,
                            "breaches": [],
                            "count": 0,
                            "error": True,
                            "error_type": "network_error",
                            "used_tor_fallback": True,
                        }

                    # Tor is being used but no retry
                    elif self.use_tor:
                        self._status(
                            "HIBP blocking Tor (check manually at haveibeenpwned.com)",
                            "error",
                        )
                        return {
                            "found": False,
                            "breaches": [],
                            "count": 0,
                            "error": True,
                            "error_type": "tor_blocked_no_fallback",
                        }
                    else:
                        self._status("API request failed (network issue)", "error")
                        return {
                            "found": False,
                            "breaches": [],
                            "count": 0,
                            "error": True,
                            "error_type": "network_error",
                        }

                status_code = response.status_code if response else "N/A"
                self._status(f"API error (status: {status_code})", "error")
                return {
                    "found": False,
                    "breaches": [],
                    "count": 0,
                    "error": True,
                    "status_code": status_code,
                }

        except Exception as e:
            self._status(f"Unexpected error: {str(e)}", "error")
            return {
                "found": False,
                "breaches": [],
                "count": 0,
                "error": True,
                "exception": str(e),
            }

    def check_hibp_pastes(self, email: str, retry_without_tor: bool = True) -> Dict:
        """Check HIBP for pastes with robust error handling and intelligent Tor fallback"""
        self._status(f"Checking pastes for {email[:20]}...", "info")

        try:
            # Validate email
            if not email or "@" not in email:
                return {
                    "found": False,
                    "pastes": [],
                    "count": 0,
                    "error": True,
                    "error_type": "invalid_email",
                }

            # Use urllib.parse to properly encode email
            encoded_email = urllib.parse.quote(email)
            url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{encoded_email}"

            response = self._retry_request(url)

            self.checks_completed += 1
            self._progress(self.checks_completed, self.total_checks, "Paste check")

            if response and response.status_code == 200:
                try:
                    pastes = response.json()
                    if not isinstance(pastes, list):
                        return {
                            "found": False,
                            "pastes": [],
                            "count": 0,
                            "error": True,
                            "error_type": "parse_error",
                        }

                    self._status(f"Found in {len(pastes)} pastes!", "found")
                    return {
                        "found": True,
                        "pastes": pastes,
                        "count": len(pastes),
                        "checked": True,
                    }
                except ValueError as e:
                    self._status(f"Failed to parse paste data: {e}", "error")
                    return {
                        "found": False,
                        "pastes": [],
                        "count": 0,
                        "error": True,
                        "error_type": "parse_error",
                    }

            elif response and response.status_code == 404:
                self._status("Not found in any pastes", "secure")
                return {"found": False, "pastes": [], "count": 0, "checked": True}

            else:
                if not response:
                    # Complete request failure
                    if self.use_tor and retry_without_tor:
                        self._status(
                            "Paste API blocking Tor - retrying without Tor...",
                            "warning",
                        )

                        # Temporarily disable Tor
                        original_proxies = self.session.proxies.copy()
                        self.session.proxies = {}

                        # Retry without Tor
                        retry_response = self._retry_request(url)

                        # Restore Tor
                        self.session.proxies = original_proxies

                        if retry_response and retry_response.status_code == 200:
                            try:
                                pastes = retry_response.json()
                                if isinstance(pastes, list):
                                    self._status(
                                        f"Found in {len(pastes)} pastes (via direct connection)",
                                        "found",
                                    )
                                    return {
                                        "found": True,
                                        "pastes": pastes,
                                        "count": len(pastes),
                                        "checked": True,
                                        "used_tor_fallback": True,
                                    }
                            except:
                                pass
                        elif retry_response and retry_response.status_code == 404:
                            self._status(
                                "Not found in any pastes (via direct connection)",
                                "secure",
                            )
                            return {
                                "found": False,
                                "pastes": [],
                                "count": 0,
                                "checked": True,
                                "used_tor_fallback": True,
                            }

                    # No fallback or fallback failed
                    if self.use_tor:
                        self._status("Paste API blocking Tor", "warning")
                        return {
                            "found": False,
                            "pastes": [],
                            "count": 0,
                            "error": True,
                            "error_type": "tor_blocked",
                        }
                    else:
                        self._status("Paste API failed (network issue)", "error")
                        return {
                            "found": False,
                            "pastes": [],
                            "count": 0,
                            "error": True,
                            "error_type": "network_error",
                        }

                status_code = response.status_code if response else "N/A"
                return {
                    "found": False,
                    "pastes": [],
                    "count": 0,
                    "error": True,
                    "status_code": status_code,
                }

        except Exception as e:
            self._status(f"Error checking pastes: {str(e)}", "error")
            return {
                "found": False,
                "pastes": [],
                "count": 0,
                "error": True,
                "exception": str(e),
            }

    def check_pwned_passwords(self, password: str) -> Dict:
        """Check password using k-anonymity with robust error handling"""
        self._status("Checking password against breach databases...", "info")

        try:
            # Generate SHA1 hash for k-anonymity
            sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = self._retry_request(url)

            self.checks_completed += 1
            self._progress(self.checks_completed, self.total_checks, "Password check")

            if response and response.status_code == 200:
                # Check if response looks like HTML error page
                response_text = response.text
                if response_text.strip().startswith(
                    "<!DOCTYPE"
                ) or response_text.strip().startswith("<html"):
                    self._status(
                        "Received HTML error page instead of API data (possible Tor block)",
                        "error",
                    )
                    return {
                        "compromised": False,
                        "count": 0,
                        "error": True,
                        "error_type": "html_response",
                    }

                hashes = response_text.splitlines()
                malformed_count = 0

                # Parse each hash line with comprehensive error handling
                for hash_line in hashes:
                    # Skip empty lines
                    if not hash_line or not hash_line.strip():
                        continue

                    # Handle malformed lines that don't contain ':'
                    if ":" not in hash_line:
                        malformed_count += 1
                        continue

                    # Split with maxsplit to handle edge cases
                    parts = hash_line.split(":", 1)
                    if len(parts) != 2:
                        continue

                    hash_suffix, count_str = parts

                    # Validate hash suffix and count
                    if not hash_suffix or not count_str:
                        continue

                    # Strip whitespace
                    hash_suffix = hash_suffix.strip()
                    count_str = count_str.strip()

                    # Check if this is our hash
                    if hash_suffix == suffix:
                        try:
                            count = int(count_str)
                            self._status(
                                f"PASSWORD COMPROMISED! Seen {count:,} times in breaches",
                                "critical",
                            )
                            return {
                                "compromised": True,
                                "count": count,
                                "hash_prefix": prefix,
                                "severity": (
                                    "critical"
                                    if count > 1000
                                    else "high" if count > 100 else "medium"
                                ),
                            }
                        except ValueError:
                            self._status(
                                f"Warning: Invalid count value '{count_str}'", "warning"
                            )
                            return {
                                "compromised": True,
                                "count": 1,
                                "parse_error": True,
                            }

                # Password not found in any breach
                if malformed_count > 0:
                    self._status(
                        f"Note: Skipped {malformed_count} malformed lines in API response",
                        "info",
                    )
                self._status("Password not found in breach databases", "secure")
                return {
                    "compromised": False,
                    "count": 0,
                    "checked": True,
                    "malformed_lines": malformed_count,
                }

            elif response and response.status_code == 404:
                # Prefix not found (very rare, means no breaches with this prefix)
                self._status("Password not found in breach databases", "secure")
                return {"compromised": False, "count": 0, "checked": True}

            else:
                # API error
                self._status("Could not verify password (API error)", "error")
                return {
                    "compromised": False,
                    "count": 0,
                    "error": True,
                    "error_type": "api_error",
                }

        except Exception as e:
            self._status(f"Error checking password: {str(e)}", "error")
            return {
                "compromised": False,
                "count": 0,
                "error": True,
                "error_message": str(e),
            }

    def check_username_sherlock(self, username: str) -> Dict:
        """Check username across platforms using Sherlock logic"""
        self._status(f"Scanning username '{username}' across platforms...", "info")

        # URL-encode username for safety
        encoded_username = urllib.parse.quote(username)

        platforms = [
            {"name": "GitHub", "url": f"https://github.com/{encoded_username}"},
            {"name": "Twitter", "url": f"https://twitter.com/{encoded_username}"},
            {"name": "Instagram", "url": f"https://instagram.com/{encoded_username}"},
            {"name": "Reddit", "url": f"https://reddit.com/user/{encoded_username}"},
            {"name": "Medium", "url": f"https://medium.com/@{encoded_username}"},
            {"name": "YouTube", "url": f"https://youtube.com/@{encoded_username}"},
            {"name": "TikTok", "url": f"https://tiktok.com/@{encoded_username}"},
            {"name": "LinkedIn", "url": f"https://linkedin.com/in/{encoded_username}"},
            {"name": "Pinterest", "url": f"https://pinterest.com/{encoded_username}"},
            {"name": "Tumblr", "url": f"https://{encoded_username}.tumblr.com"},
        ]

        found_on = []

        for platform in platforms:
            try:
                response = self.session.head(
                    platform["url"], timeout=10, allow_redirects=True
                )
                if response.status_code == 200:
                    found_on.append(platform["name"])
                    self._status(f"Found on {platform['name']}", "found")
                time.sleep(0.5 if self.aggressive_mode else 1.5)
            except:
                pass

        self.checks_completed += 1
        self._progress(self.checks_completed, self.total_checks, "Username scan")

        return {
            "found": len(found_on) > 0,
            "platforms": found_on,
            "count": len(found_on),
        }

    def check_username_advanced(self, username: str) -> Dict:
        """Advanced username check across 30+ platforms with parallel execution"""
        self._status(f"Running advanced username scan for '{username}'...", "info")

        encoded_username = urllib.parse.quote(username)

        # Extended platform list
        platforms = [
            # Social Media
            {
                "name": "GitHub",
                "url": f"https://github.com/{encoded_username}",
                "category": "dev",
            },
            {
                "name": "GitLab",
                "url": f"https://gitlab.com/{encoded_username}",
                "category": "dev",
            },
            {
                "name": "Twitter",
                "url": f"https://twitter.com/{encoded_username}",
                "category": "social",
            },
            {
                "name": "Instagram",
                "url": f"https://instagram.com/{encoded_username}",
                "category": "social",
            },
            {
                "name": "Facebook",
                "url": f"https://facebook.com/{encoded_username}",
                "category": "social",
            },
            {
                "name": "Reddit",
                "url": f"https://reddit.com/user/{encoded_username}",
                "category": "social",
            },
            {
                "name": "LinkedIn",
                "url": f"https://linkedin.com/in/{encoded_username}",
                "category": "professional",
            },
            {
                "name": "TikTok",
                "url": f"https://tiktok.com/@{encoded_username}",
                "category": "social",
            },
            {
                "name": "Snapchat",
                "url": f"https://snapchat.com/add/{encoded_username}",
                "category": "social",
            },
            # Content Platforms
            {
                "name": "Medium",
                "url": f"https://medium.com/@{encoded_username}",
                "category": "blogging",
            },
            {
                "name": "YouTube",
                "url": f"https://youtube.com/@{encoded_username}",
                "category": "video",
            },
            {
                "name": "Twitch",
                "url": f"https://twitch.tv/{encoded_username}",
                "category": "streaming",
            },
            {
                "name": "Vimeo",
                "url": f"https://vimeo.com/{encoded_username}",
                "category": "video",
            },
            {
                "name": "Dailymotion",
                "url": f"https://dailymotion.com/{encoded_username}",
                "category": "video",
            },
            # Developer Platforms
            {
                "name": "Stack Overflow",
                "url": f"https://stackoverflow.com/users/{encoded_username}",
                "category": "dev",
            },
            {
                "name": "HackerRank",
                "url": f"https://hackerrank.com/{encoded_username}",
                "category": "dev",
            },
            {
                "name": "CodePen",
                "url": f"https://codepen.io/{encoded_username}",
                "category": "dev",
            },
            {
                "name": "Replit",
                "url": f"https://replit.com/@{encoded_username}",
                "category": "dev",
            },
            # Forums & Communities
            {
                "name": "Discord",
                "url": f"https://discord.com/users/{encoded_username}",
                "category": "gaming",
            },
            {
                "name": "Steam",
                "url": f"https://steamcommunity.com/id/{encoded_username}",
                "category": "gaming",
            },
            {
                "name": "Xbox",
                "url": f"https://xboxgamertag.com/search/{encoded_username}",
                "category": "gaming",
            },
            # Art & Design
            {
                "name": "DeviantArt",
                "url": f"https://deviantart.com/{encoded_username}",
                "category": "art",
            },
            {
                "name": "Behance",
                "url": f"https://behance.net/{encoded_username}",
                "category": "art",
            },
            {
                "name": "Dribbble",
                "url": f"https://dribbble.com/{encoded_username}",
                "category": "design",
            },
            # Music
            {
                "name": "Spotify",
                "url": f"https://open.spotify.com/user/{encoded_username}",
                "category": "music",
            },
            {
                "name": "SoundCloud",
                "url": f"https://soundcloud.com/{encoded_username}",
                "category": "music",
            },
            # Other
            {
                "name": "Pinterest",
                "url": f"https://pinterest.com/{encoded_username}",
                "category": "social",
            },
            {
                "name": "Tumblr",
                "url": f"https://{encoded_username}.tumblr.com",
                "category": "blogging",
            },
            {
                "name": "Flickr",
                "url": f"https://flickr.com/people/{encoded_username}",
                "category": "photos",
            },
            {
                "name": "Patreon",
                "url": f"https://patreon.com/{encoded_username}",
                "category": "creator",
            },
        ]

        found_on = []
        by_category = {}

        def check_platform(platform: Dict) -> Optional[Dict]:
            """Check single platform"""
            try:
                response = self.session.head(
                    platform["url"], timeout=8, allow_redirects=True
                )
                if response.status_code == 200:
                    return platform
            except:
                pass
            return None

        # Use ThreadPoolExecutor for parallel checking
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_platform = {
                executor.submit(check_platform, p): p for p in platforms
            }

            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    result = future.result()
                    if result:
                        found_on.append(result["name"])
                        category = result["category"]
                        if category not in by_category:
                            by_category[category] = []
                        by_category[category].append(result["name"])
                        self._status(f"Found on {result['name']}", "found")
                except Exception as e:
                    pass

        return {
            "username": username,
            "found": len(found_on) > 0,
            "platforms": found_on,
            "by_category": by_category,
            "count": len(found_on),
            "total_checked": len(platforms),
        }

    def bulk_check_emails(self, emails: List[str]) -> List[Dict]:
        """Bulk check multiple emails with progress tracking"""
        self._status(f"Starting bulk check for {len(emails)} emails...", "info")

        results = []
        total = len(emails)

        for i, email in enumerate(emails, 1):
            self._status(f"Checking email {i}/{total}: {email[:20]}...", "info")

            # Check cache first
            cache_key = f"hibp_breach_{email}"
            cached = self._cache_get(cache_key, max_age_hours=48)

            if cached:
                self._status(f"Using cached result", "info")
                results.append({"email": email, "cached": True, **cached})
            else:
                result = self.check_haveibeenpwned(email)
                result["email"] = email
                results.append(result)

                # Cache it
                self._cache_set(cache_key, result)

                time.sleep(1.8)  # Rate limiting

        return results

    def export_to_csv(self, results: List[Dict], filename: str = None) -> str:
        """Export results to CSV file"""
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(self.output_dir, f"export_{timestamp}.csv")

            with open(filename, "w") as f:
                # Header
                f.write("Email,Found in Breaches,Breach Count,Breaches List\n")

                # Data
                for result in results:
                    email = result.get("email", "N/A")
                    found = result.get("found", False)
                    count = result.get("count", 0)
                    breaches = result.get("breaches", [])
                    breach_names = "; ".join([b.get("Name", "") for b in breaches])

                    f.write(f'"{email}",{found},{count},"{breach_names}"\n')

            os.chmod(filename, 0o600)
            self._status(f"Exported to {filename}", "success")
            return filename

        except Exception as e:
            self._status(f"Export error: {e}", "error")
            return ""

    def generate_executive_summary(self, automated_results: List[Dict]) -> str:
        """Generate executive-level summary for reports"""
        breach_count = sum(
            [r.get("count", 0) for r in automated_results if r.get("type") == "breach"]
        )
        paste_count = sum(
            [r.get("count", 0) for r in automated_results if r.get("type") == "paste"]
        )
        pwd_compromised = sum(
            [
                1
                for r in automated_results
                if r.get("type") == "password" and r.get("compromised")
            ]
        )

        risk_score = self.calculate_risk_score()

        if risk_score >= 75:
            threat_level = "CRITICAL"
            summary = "Immediate action required. Your data has been extensively exposed across multiple breaches."
        elif risk_score >= 50:
            threat_level = "HIGH"
            summary = "Significant exposure detected. Prompt remediation recommended."
        elif risk_score >= 25:
            threat_level = "MODERATE"
            summary = "Some exposure detected. Review and update security practices."
        else:
            threat_level = "LOW"
            summary = (
                "Minimal exposure detected. Continue maintaining good security hygiene."
            )

        exec_summary = f"""
EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════

Threat Level: {threat_level}
Risk Score: {risk_score}/100

{summary}

Key Findings:
  • Data Breaches: {breach_count} breach(es) detected
  • Public Pastes: {paste_count} paste(s) found
  • Compromised Passwords: {pwd_compromised} password(s)

Recommendation Priority:
  1. {"Change all compromised passwords immediately" if pwd_compromised > 0 else "Enable 2FA on all accounts"}
  2. {"Place credit freeze" if risk_score >= 50 else "Monitor credit reports"}
  3. {"Consider identity protection service" if risk_score >= 75 else "Review account activity"}
        """

        return exec_summary

    def check_phone_osint(self, phone: str) -> Dict:
        """Phone number OSINT"""
        self._status(f"Running phone number intelligence on {phone}...", "info")

        phone_clean = re.sub(r"\D", "", phone)

        # Build search URLs using urllib.parse
        truecaller_url = self._build_search_url(
            "https://www.truecaller.com/search/us", {"q": phone_clean}
        )
        whitepages_url = f"https://www.whitepages.com/phone/{phone_clean}"

        sources = {
            "truecaller": truecaller_url,
            "whitepages": whitepages_url,
            "numverify": "Requires API key for validation",
        }

        results = {
            "phone": phone,
            "cleaned": phone_clean,
            "manual_sources": sources,
            "recommendations": [],
        }

        self.checks_completed += 1
        self._progress(self.checks_completed, self.total_checks, "Phone OSINT")

        self._status("Phone check requires manual verification", "warning")
        return results

    def check_breach_compilation(self, email: str) -> Dict:
        """Check against known breach compilations"""
        self._status(f"Checking breach compilations for {email[:20]}...", "info")

        # Create hash for privacy
        email_sha256 = hashlib.sha256(email.encode()).hexdigest()
        email_md5 = hashlib.md5(email.encode()).hexdigest()

        compilations = {
            "Collection #1-5": "Check manually at haveibeenpwned.com",
            "Antipublic": "Requires specialized tools",
            "Breach Compilation": "Indexed in major breach databases",
        }

        self.checks_completed += 1
        self._progress(self.checks_completed, self.total_checks, "Breach compilations")

        return {
            "email_hashes": {
                "sha256": email_sha256[:16] + "...",
                "md5": email_md5[:16] + "...",
            },
            "compilations": compilations,
        }

    def parallel_breach_detail_fetch(
        self, breach_names: List[str]
    ) -> List[Tuple[str, Dict]]:
        """Fetch breach details in parallel using ThreadPoolExecutor"""
        self._status("Fetching detailed breach information in parallel...", "info")

        detailed_breaches = []

        def fetch_breach_detail(breach_name: str) -> Tuple[str, Dict]:
            """Fetch single breach detail"""
            try:
                time.sleep(1.6)  # Rate limiting
                encoded_name = urllib.parse.quote(breach_name)
                url = f"https://haveibeenpwned.com/api/v3/breach/{encoded_name}"
                response = self._retry_request(url)

                if response and response.status_code == 200:
                    return (breach_name, response.json())
                return (breach_name, {})
            except Exception as e:
                return (breach_name, {"error": str(e)})

        # Use ThreadPoolExecutor for parallel fetching
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_breach = {
                executor.submit(fetch_breach_detail, name): name
                for name in breach_names
            }

            for future in as_completed(future_to_breach):
                breach_name = future_to_breach[future]
                try:
                    name, details = future.result()
                    if details and "error" not in details:
                        detailed_breaches.append((name, details))
                        self._status(f"Got details for {name}", "success")
                except Exception as e:
                    self._status(f"Error fetching {breach_name}: {e}", "error")

        return detailed_breaches

    def check_social_media_exposure(self, config: Dict) -> Dict:
        """Check social media exposure"""
        self._status("Analyzing social media exposure...", "info")

        platforms = config.get("social_platforms", [])
        username = config.get("username", "")
        email = config.get("email", "")

        exposure = []

        for platform in platforms:
            self._status(f"Checking {platform}...", "info")

            # Platform-specific checks
            if platform == "GitHub" and username:
                try:
                    encoded_username = urllib.parse.quote(username)
                    url = f"https://api.github.com/users/{encoded_username}"
                    response = self.session.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        exposure.append(
                            {
                                "platform": "GitHub",
                                "found": True,
                                "data": {
                                    "public_repos": data.get("public_repos", 0),
                                    "followers": data.get("followers", 0),
                                    "created": data.get("created_at", "Unknown"),
                                },
                            }
                        )
                        self._status("GitHub profile found with public data", "found")
                except:
                    pass

            self.checks_completed += 1
            self._progress(
                self.checks_completed, self.total_checks, f"Checking {platform}"
            )
            time.sleep(0.5 if self.aggressive_mode else 2)

        return {"platforms_checked": len(platforms), "exposure_found": exposure}

    def check_data_broker_sites(self) -> Dict:
        """Check major data broker sites"""
        self._status("Identifying data broker exposure...", "info")

        brokers = [
            {
                "name": "Whitepages",
                "url": "https://www.whitepages.com",
                "opt_out": "https://www.whitepages.com/suppression_requests",
            },
            {
                "name": "Spokeo",
                "url": "https://www.spokeo.com",
                "opt_out": "https://www.spokeo.com/optout",
            },
            {
                "name": "BeenVerified",
                "url": "https://www.beenverified.com",
                "opt_out": "https://www.beenverified.com/faq/opt-out",
            },
            {
                "name": "PeopleFinder",
                "url": "https://www.peoplefinder.com",
                "opt_out": "https://www.peoplefinder.com/optout.php",
            },
            {
                "name": "Intelius",
                "url": "https://www.intelius.com",
                "opt_out": "https://www.intelius.com/optout",
            },
            {
                "name": "MyLife",
                "url": "https://www.mylife.com",
                "opt_out": "https://www.mylife.com/privacy-policy",
            },
            {
                "name": "TruthFinder",
                "url": "https://www.truthfinder.com",
                "opt_out": "https://www.truthfinder.com/opt-out",
            },
            {
                "name": "Instant Checkmate",
                "url": "https://www.instantcheckmate.com",
                "opt_out": "https://www.instantcheckmate.com/opt-out",
            },
        ]

        self.checks_completed += 1
        self._progress(
            self.checks_completed, self.total_checks, "Data broker identification"
        )

        return {"brokers": brokers, "requires_manual": True}

    def check_npd_breach(self) -> Dict:
        """Check National Public Data breach specifically"""
        self._status("Checking National Public Data breach exposure...", "info")

        npd_info = {
            "breach_name": "National Public Data",
            "date": "2024",
            "records": "2.9 billion",
            "data_types": ["SSN", "Full Name", "Address", "Phone", "DOB"],
            "lookup_sites": ["https://npd.pentester.com", "https://checkbreach.com"],
            "severity": "CRITICAL",
        }

        self.checks_completed += 1
        self._progress(self.checks_completed, self.total_checks, "NPD breach check")

        return npd_info

    # ═══════════════════════════════════════════════════════════════
    # MANUAL CHECK GUIDANCE
    # ═══════════════════════════════════════════════════════════════

    def generate_manual_checks(self, config: Dict) -> List[Dict]:
        """Generate comprehensive manual check list"""
        manual_checks = []

        # Dark web monitoring
        if config.get("check_darkweb"):
            manual_checks.append(
                {
                    "category": "Dark Web Monitoring",
                    "priority": "HIGH",
                    "checks": [
                        {
                            "name": "Intelligence X",
                            "url": "https://intelx.io",
                            "description": "Search for email, username, phone on dark web",
                            "cost": "Free tier available",
                        },
                        {
                            "name": "Dehashed",
                            "url": "https://dehashed.com",
                            "description": "Comprehensive breach database",
                            "cost": "Paid ($5/week)",
                        },
                        {
                            "name": "LeakCheck",
                            "url": "https://leakcheck.io",
                            "description": "Leak and breach monitoring",
                            "cost": "Freemium",
                        },
                    ],
                }
            )

        # Aggregated breach databases
        manual_checks.append(
            {
                "category": "Breach Aggregators",
                "priority": "HIGH",
                "checks": [
                    {
                        "name": "Breach Directory",
                        "url": "https://breachdirectory.org",
                        "description": "Free breach search",
                        "cost": "Free",
                    },
                    {
                        "name": "Snusbase",
                        "url": "https://snusbase.com",
                        "description": "Premium breach database",
                        "cost": "Paid (invite only)",
                    },
                    {
                        "name": "Hudson Rock",
                        "url": "https://cavalier.hudsonrock.com",
                        "description": "Infostealer malware database",
                        "cost": "Free",
                    },
                ],
            }
        )

        # Public records
        if config.get("check_public_records"):
            manual_checks.append(
                {
                    "category": "Public Records",
                    "priority": "MEDIUM",
                    "checks": [
                        {
                            "name": "County Records",
                            "url": 'Search "[your county] public records"',
                            "description": "Property, court, marriage records",
                            "cost": "Usually free",
                        },
                        {
                            "name": "Voter Registration",
                            "url": "Search state voter registration database",
                            "description": "Voting history and registration",
                            "cost": "Free",
                        },
                        {
                            "name": "Corporate Registrations",
                            "url": "Secretary of State websites",
                            "description": "Business registrations",
                            "cost": "Free",
                        },
                    ],
                }
            )

        # Social media deep dive
        if config.get("check_social"):
            manual_checks.append(
                {
                    "category": "Social Media Deep Dive",
                    "priority": "MEDIUM",
                    "checks": [
                        {
                            "name": "Facebook Graph Search",
                            "url": "https://www.facebook.com",
                            "description": "Old posts, photos, tagged content",
                            "cost": "Free",
                        },
                        {
                            "name": "Twitter Advanced Search",
                            "url": "https://twitter.com/search-advanced",
                            "description": "Historical tweets and interactions",
                            "cost": "Free",
                        },
                        {
                            "name": "Google Dorking",
                            "url": 'site:facebook.com|twitter.com|instagram.com "[your name]"',
                            "description": "Find indexed social content",
                            "cost": "Free",
                        },
                    ],
                }
            )

        # Specialized searches
        manual_checks.append(
            {
                "category": "Specialized OSINT",
                "priority": "LOW",
                "checks": [
                    {
                        "name": "Pipl",
                        "url": "https://pipl.com",
                        "description": "People search engine",
                        "cost": "Paid",
                    },
                    {
                        "name": "Shodan",
                        "url": "https://shodan.io",
                        "description": "Search for exposed devices/services",
                        "cost": "Freemium",
                    },
                    {
                        "name": "Wayback Machine",
                        "url": "https://archive.org/web",
                        "description": "Historical website data",
                        "cost": "Free",
                    },
                    {
                        "name": "Google Alerts",
                        "url": "https://google.com/alerts",
                        "description": "Set up monitoring for your name/email",
                        "cost": "Free",
                    },
                ],
            }
        )

        # Phone-specific
        if config.get("phone"):
            phone_clean = re.sub(r"\D", "", config["phone"])
            manual_checks.append(
                {
                    "category": "Phone Number Intelligence",
                    "priority": "MEDIUM",
                    "checks": [
                        {
                            "name": "Truecaller",
                            "url": f"https://www.truecaller.com/search/us/{phone_clean}",
                            "description": "Caller ID and spam detection",
                            "cost": "Freemium",
                        },
                        {
                            "name": "PhoneInfoga",
                            "url": "https://github.com/sundowndev/phoneinfoga",
                            "description": "Local OSINT tool for phone numbers",
                            "cost": "Free (requires install)",
                        },
                        {
                            "name": "Sync.ME",
                            "url": "https://sync.me",
                            "description": "Reverse phone lookup",
                            "cost": "Free",
                        },
                    ],
                }
            )

        # National Public Data specific
        manual_checks.append(
            {
                "category": "National Public Data Breach",
                "priority": "CRITICAL",
                "checks": [
                    {
                        "name": "NPD Pentester",
                        "url": "https://npd.pentester.com",
                        "description": "Search NPD breach by name/SSN",
                        "cost": "Free",
                    },
                    {
                        "name": "CheckBreach NPD",
                        "url": "https://checkbreach.com",
                        "description": "Alternative NPD lookup",
                        "cost": "Free",
                    },
                ],
            }
        )

        return manual_checks

    def display_manual_checks(self, manual_checks: List[Dict]):
        """Display manual check instructions"""
        self._section_header("MANUAL VERIFICATION REQUIRED", Style.EYES)

        print(
            f"{Style.YELLOW}{Style.WARNING} The following checks require manual verification{Style.RESET}"
        )
        print(
            f"{Style.DIM}Automated scanning cannot access these sources directly{Style.RESET}\n"
        )

        for check_group in manual_checks:
            priority_color = {
                "CRITICAL": Style.RED,
                "HIGH": Style.YELLOW,
                "MEDIUM": Style.BLUE,
                "LOW": Style.GRAY,
            }.get(check_group["priority"], Style.WHITE)

            print(
                f"\n{Style.BOLD}{priority_color}[{check_group['priority']}] {check_group['category']}{Style.RESET}"
            )
            print(f"{Style.DIM}{'─' * 60}{Style.RESET}")

            for check in check_group["checks"]:
                print(f"\n  {Style.BOLD}{Style.TARGET} {check['name']}{Style.RESET}")
                print(
                    f"  {Style.CYAN}{Style.ARROW}{Style.RESET} URL: {Style.DIM}{check['url']}{Style.RESET}"
                )
                print(
                    f"  {Style.CYAN}{Style.ARROW}{Style.RESET} Info: {check['description']}"
                )
                print(f"  {Style.CYAN}{Style.ARROW}{Style.RESET} Cost: {check['cost']}")

        print(f"\n{Style.BOLD}{'─' * 70}{Style.RESET}\n")

    # ═══════════════════════════════════════════════════════════════
    # ANALYSIS & REPORTING
    # ═══════════════════════════════════════════════════════════════

    def calculate_risk_score(self) -> int:
        """Calculate overall risk score"""
        score = 0

        # Breach count (0-40 points)
        breach_count = sum(
            [
                r.get("count", 0)
                for r in self.results["automated_checks"]
                if "breach" in r.get("type", "")
            ]
        )
        score += min(breach_count * 2, 40)

        # Paste count (0-20 points)
        paste_count = sum(
            [
                r.get("count", 0)
                for r in self.results["automated_checks"]
                if "paste" in r.get("type", "")
            ]
        )
        score += min(paste_count * 5, 20)

        # Compromised passwords (0-30 points)
        pwd_compromised = sum(
            [
                1
                for r in self.results["automated_checks"]
                if r.get("type") == "password" and r.get("compromised")
            ]
        )
        score += min(pwd_compromised * 15, 30)

        # Social media exposure (0-10 points)
        social_exposure = len(
            [r for r in self.results["automated_checks"] if r.get("type") == "social"]
        )
        score += min(social_exposure, 10)

        return min(score, 100)

    def generate_recommendations(self, risk_score: int) -> List[str]:
        """Generate personalized recommendations"""
        recommendations = []

        if risk_score >= 75:
            recommendations.extend(
                [
                    f"{Style.RED}{Style.SKULL} CRITICAL: Your data exposure is severe. Take immediate action!{Style.RESET}",
                    "Place a credit freeze with all 3 bureaus (Equifax, Experian, TransUnion)",
                    "Enable 2FA on ALL accounts immediately",
                    "Change all passwords to unique, strong passwords",
                    "Consider identity theft protection service",
                    "File a report with FTC at identitytheft.gov",
                ]
            )
        elif risk_score >= 50:
            recommendations.extend(
                [
                    f"{Style.YELLOW}{Style.WARNING} HIGH RISK: Significant exposure detected{Style.RESET}",
                    "Set up fraud alerts with credit bureaus",
                    "Enable 2FA on important accounts",
                    "Change passwords for exposed accounts",
                    "Monitor credit reports monthly",
                    "Review account statements regularly",
                ]
            )
        elif risk_score >= 25:
            recommendations.extend(
                [
                    f"{Style.BLUE}{Style.SHIELD} MODERATE RISK: Some exposure detected{Style.RESET}",
                    "Enable 2FA on key accounts",
                    "Update passwords for affected services",
                    "Set up credit monitoring",
                    "Be vigilant for phishing attempts",
                ]
            )
        else:
            recommendations.extend(
                [
                    f"{Style.GREEN}{Style.CHECK} LOW RISK: Minimal exposure detected{Style.RESET}",
                    "Maintain good security hygiene",
                    "Use unique passwords for each service",
                    "Enable 2FA where available",
                    "Monitor accounts periodically",
                ]
            )

        # Universal recommendations
        recommendations.extend(
            [
                "",
                f"{Style.BOLD}UNIVERSAL SECURITY PRACTICES:{Style.RESET}",
                "Use a password manager (Bitwarden, 1Password, KeePassXC)",
                "Never reuse passwords across services",
                "Be wary of phishing emails and SMS",
                "Keep software and OS updated",
                "Use email aliases for signups (SimpleLogin, AnonAddy)",
                "Regularly review connected apps and permissions",
            ]
        )

        return recommendations

    def generate_report(
        self, config: Dict, automated_results: List[Dict], manual_checks: List[Dict]
    ):
        """Generate comprehensive final report"""
        self._section_header("COMPREHENSIVE RECONNAISSANCE REPORT", Style.DOCUMENT)

        # Header
        scan_id = self.results["scan_id"]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"{Style.BOLD}Scan ID:{Style.RESET} {scan_id}")
        print(f"{Style.BOLD}Timestamp:{Style.RESET} {timestamp}")
        print(f"{Style.BOLD}Target:{Style.RESET} {config.get('email', 'N/A')}")
        print(f"{Style.BOLD}Scan Mode:{Style.RESET} {config.get('scan_mode', 'N/A')}")
        print()

        # Risk Score
        risk_score = self.calculate_risk_score()
        risk_color = (
            Style.RED
            if risk_score >= 75
            else (
                Style.YELLOW
                if risk_score >= 50
                else Style.BLUE if risk_score >= 25 else Style.GREEN
            )
        )

        print(f"{Style.BOLD}{'═' * 70}{Style.RESET}")
        print(f"{Style.BOLD}RISK ASSESSMENT{Style.RESET}")
        print(f"{Style.BOLD}{'═' * 70}{Style.RESET}\n")

        # Risk meter
        bar_length = 50
        filled = int(bar_length * risk_score / 100)
        bar = "█" * filled + "░" * (bar_length - filled)

        print(f"{risk_color}{Style.BOLD}Risk Score: {risk_score}/100{Style.RESET}")
        print(f"{risk_color}[{bar}]{Style.RESET}\n")

        # Summary statistics
        print(f"{Style.BOLD}{'─' * 70}{Style.RESET}")
        print(f"{Style.BOLD}EXPOSURE SUMMARY{Style.RESET}")
        print(f"{Style.BOLD}{'─' * 70}{Style.RESET}\n")

        breach_count = sum(
            [
                r.get("count", 0)
                for r in automated_results
                if "breach" in r.get("type", "")
            ]
        )
        paste_count = sum(
            [
                r.get("count", 0)
                for r in automated_results
                if "paste" in r.get("type", "")
            ]
        )
        pwd_compromised = sum(
            [
                1
                for r in automated_results
                if r.get("type") == "password" and r.get("compromised")
            ]
        )

        print(
            f"{Style.RED}{Style.FIRE}{Style.RESET} Data Breaches: {Style.BOLD}{breach_count}{Style.RESET}"
        )
        print(
            f"{Style.YELLOW}{Style.DOCUMENT}{Style.RESET} Public Pastes: {Style.BOLD}{paste_count}{Style.RESET}"
        )
        print(
            f"{Style.RED}{Style.KEY}{Style.RESET} Compromised Passwords: {Style.BOLD}{pwd_compromised}{Style.RESET}"
        )
        print(
            f"{Style.BLUE}{Style.SEARCH}{Style.RESET} Automated Checks Completed: {Style.BOLD}{self.checks_completed}{Style.RESET}"
        )
        print(
            f"{Style.PURPLE}{Style.EYES}{Style.RESET} Manual Checks Required: {Style.BOLD}{sum([len(mc['checks']) for mc in manual_checks])}{Style.RESET}\n"
        )

        # Detailed findings
        if breach_count > 0:
            print(f"\n{Style.BOLD}{'─' * 70}{Style.RESET}")
            print(f"{Style.BOLD}{Style.RED}BREACH DETAILS{Style.RESET}")
            print(f"{Style.BOLD}{'─' * 70}{Style.RESET}\n")

            for result in automated_results:
                if result.get("type") == "breach" and result.get("found"):
                    for breach in result.get("breaches", [])[:10]:
                        print(
                            f"{Style.RED}{Style.FIRE}{Style.RESET} {Style.BOLD}{breach.get('Name', 'Unknown')}{Style.RESET}"
                        )
                        print(f"  Date: {breach.get('BreachDate', 'Unknown')}")
                        print(f"  Records: {breach.get('PwnCount', 0):,}")
                        data_classes = breach.get("DataClasses", [])
                        if data_classes:
                            print(f"  Exposed: {', '.join(data_classes[:5])}")
                        print()

        # Recommendations
        print(f"\n{Style.BOLD}{'═' * 70}{Style.RESET}")
        print(f"{Style.BOLD}RECOMMENDED ACTIONS{Style.RESET}")
        print(f"{Style.BOLD}{'═' * 70}{Style.RESET}\n")

        recommendations = self.generate_recommendations(risk_score)
        for rec in recommendations:
            if rec:
                if any(
                    keyword in rec
                    for keyword in ["CRITICAL", "HIGH", "MODERATE", "LOW"]
                ):
                    print(f"\n{rec}")
                else:
                    print(f"  {Style.CYAN}{Style.ARROW}{Style.RESET} {rec}")

        print(f"\n{Style.BOLD}{'═' * 70}{Style.RESET}\n")

        # Save to file
        if config.get("save_results"):
            filename = os.path.join(self.output_dir, f"report_{scan_id}.txt")
            with open(filename, "w") as f:
                f.write(f"ULTRA BREACH RECONNAISSANCE REPORT\n")
                f.write(f"{'=' * 70}\n\n")
                f.write(f"Scan ID: {scan_id}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Risk Score: {risk_score}/100\n\n")
                f.write(f"Breaches: {breach_count}\n")
                f.write(f"Pastes: {paste_count}\n")
                f.write(f"Compromised Passwords: {pwd_compromised}\n\n")
                f.write("\nRecommendations:\n")
                for rec in recommendations:
                    f.write(f"{rec}\n")

            os.chmod(filename, 0o600)
            self._status(f"Report saved to: {filename}", "success")

    # ═══════════════════════════════════════════════════════════════
    # MAIN EXECUTION
    # ═══════════════════════════════════════════════════════════════

    def run(self):
        """Main execution flow"""
        self.print_header()

        # Setup wizard
        config = self.setup_wizard()

        # Calculate total checks
        self.total_checks = self.calculate_total_checks(config)

        # Setup session
        print()
        self._section_header("INITIALIZING SCAN SYSTEMS", Style.SATELLITE)
        self._setup_session(config.get("use_tor", False))

        # Run automated checks
        self._section_header("AUTOMATED RECONNAISSANCE", Style.SEARCH)
        automated_results = []

        # Email checks
        if config.get("email"):
            emails_to_check = [config["email"]] + config.get("additional_emails", [])

            for email in emails_to_check:
                # HIBP breach check
                result = self.check_haveibeenpwned(email)
                result["type"] = "breach"
                result["email"] = email
                automated_results.append(result)
                time.sleep(1.6)

                # HIBP paste check
                result = self.check_hibp_pastes(email)
                result["type"] = "paste"
                result["email"] = email
                automated_results.append(result)
                time.sleep(1.6)

                # Breach compilation check
                result = self.check_breach_compilation(email)
                result["type"] = "compilation"
                result["email"] = email
                automated_results.append(result)

                # Parallel fetch breach details if breaches found
                breach_result = [
                    r
                    for r in automated_results
                    if r.get("type") == "breach" and r.get("email") == email
                ]
                if breach_result and breach_result[0].get("found"):
                    breach_names = [
                        b["Name"] for b in breach_result[0].get("breaches", [])[:5]
                    ]
                    if breach_names:
                        detailed_breaches = self.parallel_breach_detail_fetch(
                            breach_names
                        )
                        for name, details in detailed_breaches:
                            print(
                                f"  {Style.DIM}└─ {name}: {details.get('PwnCount', 0):,} records{Style.RESET}"
                            )

        # Password checks
        if config.get("check_passwords"):
            for pwd in config.get("passwords", []):
                result = self.check_pwned_passwords(pwd)
                result["type"] = "password"
                automated_results.append(result)
                time.sleep(1.6)

        # Username checks
        if config.get("username"):
            result = self.check_username_sherlock(config["username"])
            result["type"] = "username"
            automated_results.append(result)

        # Phone checks
        if config.get("phone"):
            result = self.check_phone_osint(config["phone"])
            result["type"] = "phone"
            automated_results.append(result)

        # Social media
        if config.get("check_social"):
            result = self.check_social_media_exposure(config)
            result["type"] = "social"
            automated_results.append(result)

        # Data brokers
        result = self.check_data_broker_sites()
        result["type"] = "data_brokers"
        automated_results.append(result)
        self.checks_completed += 1

        # NPD specific
        result = self.check_npd_breach()
        result["type"] = "npd"
        automated_results.append(result)

        self.results["automated_checks"] = automated_results

        # Generate manual checks
        manual_checks = self.generate_manual_checks(config)
        self.results["manual_checks"] = manual_checks

        # Display manual checks
        self.display_manual_checks(manual_checks)

        # Wait for user
        input(
            f"\n{Style.CYAN}{Style.FINGERPRINT}{Style.RESET} Press Enter to continue to final report..."
        )

        # Generate final report
        self.generate_report(config, automated_results, manual_checks)

        # Completion
        print(
            f"\n{Style.GREEN}{Style.BOLD}{Style.ROCKET} SCAN COMPLETE! {Style.ROCKET}{Style.RESET}\n"
        )

        if self._confirm("Open output directory?", True):
            subprocess.run(["xdg-open", self.output_dir], check=False)


def main():
    """Entry point"""
    try:
        scanner = UltraBreachScanner()
        scanner.run()
    except KeyboardInterrupt:
        print(
            f"\n\n{Style.YELLOW}{Style.WARNING} Scan interrupted by user{Style.RESET}"
        )
        sys.exit(0)
    except Exception as e:
        print(f"\n{Style.RED}{Style.CROSS} Fatal error: {e}{Style.RESET}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
