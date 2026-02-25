from __future__ import annotations

import re

TECHNIQUE_PATTERNS = [
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "confidence": 0.88,
        "patterns": [
            r"\bnmap\b",
            r"\bactive scan\b",
            r"\bscan finding\b",
            r"\bopen ports?\b",
        ],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "confidence": 0.9,
        "patterns": [
            r"sql injection",
            r"rce",
            r"remote code execution",
            r"confluence",
            r"log4j",
            r"moveit",
            r"citrix",
            r"exchange",
            r"forti",
            r"screenconnect",
        ],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "confidence": 0.84,
        "patterns": [
            r"brute force",
            r"password spray",
            r"credential stuffing",
        ],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "confidence": 0.78,
        "patterns": [
            r"credential",
            r"token",
            r"session",
            r"account takeover",
        ],
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "confidence": 0.8,
        "patterns": [
            r"\bport\b",
            r"\bservice\b",
            r"\bdiscovery\b",
            r"\bsmb\b",
            r"\bsmbv[1-3]?\b",
            r"\brdp\b",
            r"\bssh\b",
        ],
    },
]


def _search(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text, flags=re.IGNORECASE) is not None
    except re.error:
        return pattern.lower() in text.lower()


def infer_attack_mapping(*, source: str, message: str) -> dict:
    text = f"{source or ''} {message or ''}".strip()
    if not text:
        return {
            "attack_tactic": None,
            "attack_technique_id": None,
            "attack_technique_name": None,
            "attack_confidence": None,
        }

    best = None
    best_score = 0
    for technique in TECHNIQUE_PATTERNS:
        matches = sum(1 for pattern in technique["patterns"] if _search(pattern, text))
        if matches > best_score:
            best = technique
            best_score = matches

    if not best or best_score == 0:
        return {
            "attack_tactic": None,
            "attack_technique_id": None,
            "attack_technique_name": None,
            "attack_confidence": None,
        }

    confidence = min(0.99, round(float(best["confidence"]) + (best_score - 1) * 0.03, 2))
    return {
        "attack_tactic": best["tactic"],
        "attack_technique_id": best["id"],
        "attack_technique_name": best["name"],
        "attack_confidence": confidence,
    }
