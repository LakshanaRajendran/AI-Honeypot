"""
Provisional Labeling Engine for Module 3 (AI Decision & XAI Engine).

Defines transparent, inspectable, and auditable rules to assign provisional
ground-truth labels to raw honeypot sessions:
1. Binary Intrusion Target: `is_weaponized_intrusion` (1 = active weaponization,
   0 = low-interaction probing, 'unresolved' = ambiguous / insufficient evidence).
2. Multi-Label Intent Targets: `reconnaissance`, `credential_access`,
   `persistence`, `defense_evasion`, `execution`.

CRITICAL SCIENTIFIC & SECURITY SAFEGUARDS:
- These are PROVISIONAL, rule-derived heuristic labels, NOT verified ground truth.
- Low command count does NOT equate to benign behavior.
- In honeypots, genuine benign traffic is absent; the binary target distinguishes
  actionable weaponization from passive probing.
- Labeling logic is completely decoupled from the canonical 26 numeric features.
"""

import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Rule Definitions: Binary Classification (is_weaponized_intrusion)
# ---------------------------------------------------------------------------

WEAPONIZATION_RULES = [
    {
        "id": "WEAP_01_CRED_TAMPER",
        "name": "Credential Tampering or Password Change",
        "pattern": r"(chpasswd|passwd\b|/etc/shadow|/etc/sudoers)",
        "description": "Attempting to reset system passwords or tamper with shadow credentials.",
    },
    {
        "id": "WEAP_02_PERSIST_SSH",
        "name": "SSH Authorized Keys Manipulation",
        "pattern": r"(authorized_keys|\.ssh/|chattr\s+[-+]i?a?.*\.ssh|lockr\s+[-+]i?a?.*\.ssh)",
        "description": "Injecting public keys or altering SSH directory attributes for persistence.",
    },
    {
        "id": "WEAP_03_PERSIST_CRON",
        "name": "Scheduled Task / Cron Persistence",
        "pattern": r"(crontab\s+-[eir]|/etc/cron|/var/spool/cron)",
        "description": "Configuring crontab jobs or scheduled tasks to maintain access.",
    },
    {
        "id": "WEAP_04_DEFENSE_EVASION",
        "name": "Process Killing or Host Locking",
        "pattern": r"(pkill\s+-9|killall|echo\s*>\s*/etc/hosts\.deny|history\s+-c|rm\s+-rf\s+/tmp/)",
        "description": "Killing competing miners, wiping hosts.deny, or purging history/temporary files.",
    },
    {
        "id": "WEAP_05_PAYLOAD_DOWNLOAD_EXEC",
        "name": "Chained Download and Execution",
        "pattern": r"((curl|wget|tftp)\b.*[|;&]+.*(sh|bash|chmod|\./))|(chmod\s+\+x\s+.*[;&]+\s*(sh|\./))",
        "description": "Downloading external payload and chaining to immediate execution or chmod +x.",
    },
    {
        "id": "WEAP_06_MALWARE_DROPPER",
        "name": "Known Malware Dropper Signatures",
        "pattern": r"(/bin/busybox\s+cat\s+/proc/self/exe|cat\s+/proc/self/exe)",
        "description": "Exploiting /proc/self/exe to duplicate and execute in-memory malware binary.",
    },
    {
        "id": "WEAP_07_REVERSE_SHELL",
        "name": "Interactive Reverse Shell or Netcat Backdoor",
        "pattern": r"(/dev/tcp/|nc\s+.*-e\s+|bash\s+-i\s+>&)",
        "description": "Attempting interactive reverse shell redirection to an external host.",
    },
]

PROBING_PATTERNS = [
    r"^uname(\s+-[a-zA-Z]+)*$",
    r"^arch$",
    r"^file\s+/sbin/init$",
    r"^cat\s+/proc/cpuinfo(\s*\|\s*grep.*)*$",
    r"^cat\s+/proc/meminfo$",
    r"^free(\s+-[a-zA-Z]+)*(\s*\|\s*.*)*$",
    r"^df(\s+-[a-zA-Z]+)*(\s*\|\s*.*)*$",
    r"^which\s+[a-zA-Z0-9_\-]+$",
    r"^cat\s+/etc/\*release\*(\s*\|\s*grep.*)*$",
    r"^cat\s+/etc/issue$",
    r"^uptime$",
    r"^hostname$",
    r"^id$",
    r"^whoami$",
    r"^w$",
    r"^last(\s+-[0-9]+)*$",
    r"^ls(\s+-[a-zA-Z]+)*$",
    r"^pwd$",
    r"^echo(\s+-[a-zA-Z]+)*\s*.*$",
]

UNRESOLVED_PATTERNS = [
    r"^$",  # Empty command
    r"^sh$",
    r"^bash$",
    r"^shell$",
    r"^enable$",
    r"^system$",
]


# ---------------------------------------------------------------------------
# Rule Definitions: Multi-Label Intent Targets
# ---------------------------------------------------------------------------

INTENT_RULES = {
    "reconnaissance": [
        {
            "id": "INT_RECON_SYSINFO",
            "pattern": r"(uname|arch|cat\s+/proc/cpuinfo|cat\s+/proc/meminfo|free|df|uptime|hostname|file\s+/sbin/init|cat\s+/etc/\*release\*|cat\s+/etc/issue)",
            "description": "System architecture, kernel, CPU, and release discovery.",
        },
        {
            "id": "INT_RECON_IDENTITY",
            "pattern": r"\b(whoami|id|w|last|users|groups)\b",
            "description": "User identity and logged-in account discovery.",
        },
        {
            "id": "INT_RECON_NETWORK",
            "pattern": r"\b(ifconfig|ip\s+addr|ip\s+route|netstat|arp|route)\b",
            "description": "Network configuration and interface enumeration.",
        },
        {
            "id": "INT_RECON_FILES",
            "pattern": r"\b(which\s+[a-zA-Z0-9_\-]+|ls\b|pwd\b|find\b)",
            "description": "File system and binary utility enumeration.",
        },
    ],
    "credential_access": [
        {
            "id": "INT_CRED_PASSWD",
            "pattern": r"(chpasswd|passwd\b|/etc/shadow|/etc/sudoers|grep\s+.*password)",
            "description": "Password modification, shadow file access, or credential keyword grepping.",
        },
        {
            "id": "INT_CRED_SSH_KEY",
            "pattern": r"(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.ssh/id_)",
            "description": "Targeting private SSH identity keys.",
        },
    ],
    "persistence": [
        {
            "id": "INT_PERSIST_SSH_KEY",
            "pattern": r"(authorized_keys|\.ssh/|chattr\s+[-+]i?a?.*\.ssh|lockr\s+[-+]i?a?.*\.ssh)",
            "description": "Writing public keys to authorized_keys or locking SSH directories.",
        },
        {
            "id": "INT_PERSIST_CRON",
            "pattern": r"(crontab|/etc/cron|/var/spool/cron)",
            "description": "Adding recurring cron jobs or scheduled scripts.",
        },
        {
            "id": "INT_PERSIST_USER",
            "pattern": r"\b(useradd|adduser)\b",
            "description": "Creating rogue system user accounts.",
        },
    ],
    "defense_evasion": [
        {
            "id": "INT_EVASION_PROCESS",
            "pattern": r"(pkill|killall|kill\s+-9)",
            "description": "Killing competing malware, security scripts, or system tasks.",
        },
        {
            "id": "INT_EVASION_LOGS",
            "pattern": r"(history\s+-c|unset\s+HISTFILE|rm\s+-rf\s+/tmp/|echo\s*>\s*/etc/hosts\.deny)",
            "description": "Clearing bash history, deleting temporary execution logs, or disabling hosts.deny.",
        },
        {
            "id": "INT_EVASION_CHATTR",
            "pattern": r"\b(chattr\s+[-+]i|lockr)\b",
            "description": "Setting immutable file attributes to prevent removal or modification.",
        },
    ],
    "execution": [
        {
            "id": "INT_EXEC_SCRIPT",
            "pattern": r"(\bsh\s+[a-zA-Z0-9_\-\./]+\.sh|\bbash\s+[a-zA-Z0-9_\-\./]+\.sh|\./[a-zA-Z0-9_\-]+)",
            "description": "Direct execution of shell scripts or local binaries.",
        },
        {
            "id": "INT_EXEC_CHMOD",
            "pattern": r"(chmod\s+\+x)",
            "description": "Making dropped files executable.",
        },
        {
            "id": "INT_EXEC_DOWNLOAD_PIPE",
            "pattern": r"((curl|wget|tftp)\b.*[|;&]+.*(sh|bash|python|perl))",
            "description": "Piping downloaded web content directly into an interpreter.",
        },
        {
            "id": "INT_EXEC_DROPPER",
            "pattern": r"(/bin/busybox\s+cat\s+/proc/self/exe|cat\s+/proc/self/exe)",
            "description": "Executing in-memory binary copy via procfs self-extraction.",
        },
        {
            "id": "INT_EXEC_SHELL_ESCAPE",
            "pattern": r"^(/bin/)?(sh|bash|shell|enable|system)$",
            "description": "Interactive shell or administrative privilege escape commands.",
        },
    ],
}


class ProvisionalLabeler:
    """Evaluates raw session commands and generates auditable provisional labels."""

    def label_session(self, commands: List[str]) -> Dict[str, Any]:
        """Generate binary weaponization and multi-label intent labels for a session.

        Parameters
        ----------
        commands : list[str]
            List of command strings observed in the session.

        Returns
        -------
        dict
            Contains:
            - is_weaponized_intrusion: 1, 0, or "unresolved"
            - binary_evidence: matched rule details or rationale
            - intents: dict of {intent_name: 0 or 1}
            - intent_evidence: dict of {intent_name: list of matched rules and commands}
        """
        # 1. Output A: Binary Label Evaluation
        binary_label, binary_evidence = self._evaluate_binary_label(commands)

        # 2. Output B: Multi-Label Intent Evaluation
        intents, intent_evidence = self._evaluate_intents(commands)

        return {
            "is_weaponized_intrusion": binary_label,
            "binary_evidence": binary_evidence,
            "intents": intents,
            "intent_evidence": intent_evidence,
        }

    def _evaluate_binary_label(self, commands: List[str]) -> Tuple[Any, Dict[str, Any]]:
        """Evaluate is_weaponized_intrusion (1, 0, or 'unresolved')."""
        if not commands:
            return "unresolved", {"reason": "NO_COMMANDS_OBSERVED"}

        clean_cmds = [c.strip() for c in commands]

        # Check weaponization rules
        matched_weap = []
        for cmd in clean_cmds:
            for rule in WEAPONIZATION_RULES:
                if re.search(rule["pattern"], cmd, re.IGNORECASE):
                    matched_weap.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "command": cmd,
                    })

        if matched_weap:
            return 1, {
                "rule_type": "WEAPONIZED_ACTIONABLE_INTRUSION",
                "matched_count": len(matched_weap),
                "matched_rules": matched_weap,
            }

        # Check if strictly low-interaction probing
        all_probing = True
        probing_matches = []
        for cmd in clean_cmds:
            if not cmd:
                continue
            is_probe_cmd = any(re.search(pat, cmd, re.IGNORECASE) for pat in PROBING_PATTERNS)
            if is_probe_cmd:
                probing_matches.append(cmd)
            else:
                all_probing = False
                break

        if all_probing and probing_matches:
            return 0, {
                "rule_type": "LOW_INTERACTION_PROBE",
                "observed_count": len(probing_matches),
                "sample_commands": probing_matches[:5],
            }

        # Check if ambiguous or unresolved
        is_only_unresolved = all(
            any(re.search(pat, cmd, re.IGNORECASE) for pat in UNRESOLVED_PATTERNS)
            for cmd in clean_cmds
        )

        if is_only_unresolved:
            return "unresolved", {
                "rule_type": "AMBIGUOUS_SHELL_INVOCATION",
                "commands": clean_cmds,
            }

        return "unresolved", {
            "rule_type": "UNCLASSIFIED_NON_STANDARD_BEHAVIOR",
            "commands": clean_cmds[:5],
        }

    def _evaluate_intents(
        self, commands: List[str]
    ) -> Tuple[Dict[str, int], Dict[str, List[Dict[str, Any]]]]:
        """Evaluate multi-label indicators across the 5 intent categories."""
        intents = {
            "reconnaissance": 0,
            "credential_access": 0,
            "persistence": 0,
            "defense_evasion": 0,
            "execution": 0,
        }
        evidence: Dict[str, List[Dict[str, Any]]] = {k: [] for k in intents}

        clean_cmds = [c.strip() for c in commands if c.strip()]

        for cmd in clean_cmds:
            for category, rules in INTENT_RULES.items():
                for rule in rules:
                    if re.search(rule["pattern"], cmd, re.IGNORECASE):
                        intents[category] = 1
                        evidence[category].append({
                            "rule_id": rule["id"],
                            "command": cmd,
                            "description": rule["description"],
                        })

        return intents, evidence

