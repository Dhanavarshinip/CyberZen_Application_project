"""
Real-Time Domain & URL Reputation Evaluator for CyberThreat AI System.

Evaluates websites opened by the user or reported by the Chrome extension:
- High-risk TLD analysis (.top, .xyz, .zip, .click, .tk, etc.)
- Raw IP-based navigations (e.g. http://185.220.101.45)
- Domain Name Shannon Entropy (DGA / algorithmic domain detection)
- Phishing keyword & credential spoofing heuristics
- Suspicious ad redirects & malicious tracking links (Req 14)
- Phishing link / suspicious message links (Req 15)
- Controlled security testing domains (EICAR, malware-test)
- Standard legitimate domain verification (Req 11)
"""

import math
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

try:
    from .threat_intelligence import threat_intel
except ImportError:
    threat_intel = None

class DomainEvaluator:
    """Evaluates security reputation of domains, navigations, and links."""

    WELL_KNOWN_LEGITIMATE = {
        "google.com", "www.google.com", "youtube.com", "www.youtube.com",
        "microsoft.com", "www.microsoft.com", "apple.com", "github.com",
        "amazon.com", "wikipedia.org", "netflix.com", "stackoverflow.com",
        "reddit.com", "linkedin.com", "twitter.com", "x.com", "cloudflare.com",
        "spotify.com", "zoom.us", "pypi.org", "npmjs.com", "python.org",
        "example.com", "www.example.com", "example.org", "www.example.org",
        "example.net", "www.example.net", "httpbin.org", "mozilla.org",
        "w3.org", "iana.org", "bbc.com", "www.bbc.com", "cnn.com", "www.cnn.com",
        "nytimes.com", "www.nytimes.com", "yahoo.com", "bing.com", "duckduckgo.com",
        "chatgpt.com", "openai.com", "anthropic.com", "huggingface.co", "gitlab.com",
        "medium.com", "facebook.com", "instagram.com", "twitch.tv", "whatsapp.com",
        "telegram.org", "vitejs.dev", "vercel.app", "render.com", "replit.com",
        "react.dev", "nodejs.org", "docker.com", "ubuntu.com", "debian.org",
        "archlinux.org", "oracle.com", "ibm.com", "salesforce.com", "adobe.com"
    }

    STANDARD_LEGITIMATE_TLDS = {
        ".com", ".org", ".net", ".edu", ".gov", ".mil", ".io", ".dev", ".app",
        ".ai", ".co", ".in", ".uk", ".de", ".fr", ".ca", ".jp", ".au", ".ch",
        ".nl", ".se", ".no", ".es", ".it", ".me", ".tv", ".cc", ".tech", ".info",
        ".biz", ".agency", ".digital", ".cloud", ".global", ".world", ".so"
    }

    KNOWN_TEST_THREATS = {
        "example-dangerous.com", "malware-test-eicar.com", "malware-test.com",
        "suspicious-domain.test", "eicar.org", "phishing-simulator.example",
        "unknown-c2.com", "evil-site.test", "trojan-download.example"
    }

    SUSPICIOUS_TLDS = {
        ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".fit", ".zip", ".mov", ".loan", ".work"
    }

    PHISHING_KEYWORDS = [
        "login-verify", "account-update", "secure-banking", "paypal-auth", "bank-login",
        "wallet-connect", "credential-reset", "mfa-bypass", "security-alert", "verify-account",
        "signin-update", "recover-account", "auth-token", "security-check", "apple-security"
    ]

    MALWARE_KEYWORDS = [
        "malware", "trojan", "ransomware", "payload", "c2-server", "exploit-kit", "stealer", "backdoor", "keylogger"
    ]

    AD_REDIRECT_PATTERNS = [
        "adclick", "clicktrack", "traffic-direct", "adservice", "popunder", "rotator-link",
        "affiliate-redir", "track-user-click", "doubleclick-fake", "ad-network-jump"
    ]

    PIRACY_PATTERNS = [
        "thepiratebay", "1337x", "rarbg", "yts.", "fitgirl-repacks", "torrent", "piratebay",
        "nyaa.si", "rutracker", "eztv", "kickasstorrents", "magnetdl"
    ]

    @staticmethod
    def _calculate_entropy(domain: str) -> float:
        """Calculates Shannon entropy to detect algorithmically generated domains (DGA)."""
        if not domain:
            return 0.0
        prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
        return -sum([p * math.log(p, 2) for p in prob])

    @classmethod
    def evaluate_url(cls, raw_url: str) -> Dict[str, Any]:
        """
        Evaluates a raw URL or domain string.
        Returns:
            - status: "SAFE", "SUSPICIOUS", "DANGEROUS", "UNKNOWN"
            - risk_score: float or None (None for UNKNOWN/unverified domains where evidence is insufficient)
            - reasons: list of strings
            - domain: extracted domain name
            - category: descriptive category
            - description: human-readable action summary
        """
        if not raw_url or not raw_url.strip():
            return {
                "url": "",
                "domain": "unknown",
                "status": "UNKNOWN",
                "risk_score": None,
                "reasons": ["Reputation lookup unavailable: no URL or domain provided."],
                "category": "Insufficient Evidence",
                "description": "Insufficient evidence to evaluate.",
                "is_test_intent": False
            }

        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        hostname = parsed.hostname or raw_url.split('/')[0].split(':')[0]
        hostname_lower = hostname.lower().strip()
        
        # Truly unresolvable or missing hostname
        if not hostname_lower or hostname_lower in ("unknown", "localhost", "127.0.0.1") or "." not in hostname_lower:
            return {
                "url": raw_url,
                "domain": hostname_lower or "unknown",
                "status": "UNKNOWN",
                "risk_score": None,
                "reasons": ["Reputation lookup unavailable: unresolvable or local internal host without public domain intelligence."],
                "category": "Insufficient Evidence",
                "description": f"Insufficient evidence to evaluate host '{hostname_lower}'.",
                "is_test_intent": False
            }

        full_path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
        combined_text = (hostname_lower + full_path).lower()

        reasons = []
        risk_score = 0.0
        category = "Normal Web Traffic"
        is_test_intent = False
        is_piracy_advisory = False

        # 0. Real-time Threat Intelligence Feed Check (URLhaus & OpenPhish)
        if threat_intel and (threat_intel.is_malicious_domain(hostname_lower) or threat_intel.is_malicious_url(raw_url)):
            reasons.append("Flagged by URLhaus/OpenPhish threat intelligence feeds: active verified malware distribution or phishing.")
            risk_score = 96.0
            category = "Confirmed Malicious Domain / URL"

        # 1. Controlled Threat Test Domain Detection & Active Malware Signatures
        matched_malware = [sig for sig in cls.MALWARE_KEYWORDS + ["eicar", "malware-test", "example-dangerous"] if sig in hostname_lower]
        if hostname_lower in cls.KNOWN_TEST_THREATS or matched_malware:
            matched_term = matched_malware[0] if matched_malware else hostname_lower
            reasons.append(f"Matches known malware/threat signature '{matched_term}'.")
            risk_score = 92.0
            category = "High-Risk Threat"
            is_test_intent = any(sig in hostname_lower for sig in ["eicar", "malware-test", "example-dangerous"])

        # 2. Raw IP Host Navigation (often C2 or phishing without domain registration)
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname_lower))
        if is_ip and not is_test_intent:
            reasons.append(f"Connection to raw numeric IP address ({hostname_lower}) without domain name.")
            risk_score += 45.0
            category = "Suspicious Navigation"

        # 3. High-Abuse TLDs
        for tld in cls.SUSPICIOUS_TLDS:
            if hostname_lower.endswith(tld):
                reasons.append(f"Domain uses high-abuse top-level domain ({tld}).")
                risk_score += 35.0
                category = "Suspicious Navigation"
                break

        # 4. Phishing / Credential Harvesting Indicators
        for kw in cls.PHISHING_KEYWORDS:
            if kw in combined_text:
                reasons.append(f"Contains high-risk credential spoofing keyword '{kw}'.")
                risk_score += 45.0
                category = "Phishing Link"
                break

        # 5. Suspicious Ad Redirect / Click Tracker Chains (Req 14)
        for ad_kw in cls.AD_REDIRECT_PATTERNS:
            if ad_kw in combined_text:
                reasons.append(f"Suspicious advertising redirect pattern identified ('{ad_kw}').")
                risk_score += 40.0
                category = "Suspicious Advertisement / Redirect"
                break

        # 6. Suspected Piracy / Torrent Site (Separate content policy advisory)
        for p_kw in cls.PIRACY_PATTERNS:
            if p_kw in hostname_lower:
                reasons.append(f"Domain '{hostname_lower}' matches suspected piracy/torrent indexing patterns. (Content policy advisory — piracy alone is not proof of malware.)")
                risk_score = max(risk_score, 35.0)
                category = "Content Policy Advisory — Suspected Piracy"
                is_piracy_advisory = True
                break

        # 7. Deep Open Redirect Parameter Check
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param in ["redirect", "redir", "url", "target", "dest", "next"]:
                if param in qs:
                    target_val = qs[param][0].lower()
                    if any(target_val.endswith(tld) for tld in cls.SUSPICIOUS_TLDS) or "login" in target_val:
                        reasons.append(f"Suspicious external redirect destination in query parameter '{param}'.")
                        risk_score += 35.0
                        category = "Suspicious Advertisement / Redirect"
                        break

        # 8. Algorithmic Domain Randomness (DGA Entropy)
        domain_parts = hostname_lower.split('.')
        domain_core = domain_parts[0] if len(domain_parts) <= 2 else domain_parts[-2]
        if len(domain_core) >= 12:
            entropy = cls._calculate_entropy(domain_core)
            if entropy >= 3.8:
                reasons.append(f"High domain entropy ({entropy:.2f}), indicative of algorithmic domain generation.")
                risk_score += 35.0
                category = "Algorithmic DGA Domain"

        # Check Well-Known Legitimate
        is_well_known = (threat_intel and threat_intel.is_known_safe_domain(hostname_lower)) or any(
            hostname_lower == legit or hostname_lower.endswith(f".{legit}")
            for legit in cls.WELL_KNOWN_LEGITIMATE
        )

        has_standard_tld = any(
            hostname_lower.endswith(tld)
            for tld in cls.STANDARD_LEGITIMATE_TLDS
        )

        risk_score = round(max(0.0, min(100.0, risk_score)), 1)

        # Final Status determination based on evidence
        if risk_score >= 70.0:
            status = "DANGEROUS"
            description = f"Dangerous website detected: {hostname_lower}"
            final_risk = risk_score
        elif risk_score >= 35.0:
            status = "SUSPICIOUS"
            final_risk = risk_score
            if is_piracy_advisory:
                description = f"Content policy advisory: {hostname_lower} associated with suspected piracy."
            elif category == "Suspicious Advertisement / Redirect":
                description = f"Suspicious advertisement/redirect detected: {hostname_lower}"
            elif category == "Phishing Link":
                description = f"Suspicious message/link detected: {hostname_lower}"
            else:
                description = f"Suspicious indicators detected on {hostname_lower}"
        elif is_well_known or (has_standard_tld and risk_score == 0.0 and len(domain_parts) >= 2):
            # Sufficient evidence supporting clean safety: established domain structure, standard TLD, 0 threat signatures
            status = "SAFE"
            category = "No Known Threat"
            final_risk = 0.0
            description = f"No known threat detected on {hostname_lower}."
            if not reasons:
                reasons.append(f"Security analysis completed for '{hostname_lower}': verified clean domain structure. No known threat signatures, phishing keywords, or malicious redirect patterns detected.")
        else:
            # Genuinely unrated or obscure TLD with insufficient evidence
            status = "UNKNOWN"
            category = "Unverified Website"
            final_risk = None  # None indicates unrated/unverified — never show 0/100 as proof of safety
            description = f"Unverified website: {hostname_lower}. Proceed with caution."
            if not reasons:
                reasons.append(f"Unverified website '{hostname_lower}' with limited reputation intelligence. No known threat signatures found, but complete safety cannot be guaranteed.")

        return {
            "url": raw_url,
            "domain": hostname_lower,
            "status": status,
            "risk_score": final_risk,
            "reasons": reasons,
            "category": category,
            "description": description,
            "is_test_intent": is_test_intent,
            "is_piracy_advisory": is_piracy_advisory
        }
