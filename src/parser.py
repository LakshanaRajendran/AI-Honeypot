from typing import Dict


def parse_command(command: str) -> Dict:
    """Parse a command string to extract basic structural indicators.

    Returns a dict with keys:
      - command_name
      - contains_path (1/0)
      - credential_keyword (1/0)
      - is_network_utility (1/0)
      - download_utility (1/0)
      - arg_count (int)
      - has_pipe (1/0)
      - has_redirect (1/0)
      - command_length (int)
    """
    out = {
        "command_name": None,
        "contains_path": 0,
        "credential_keyword": 0,
        "is_network_utility": 0,
        "download_utility": 0,
        "arg_count": 0,
        "has_pipe": 0,
        "has_redirect": 0,
        "command_length": 0,
    }
    if not command or not isinstance(command, str):
        return out

    cmd = command.strip()
    out["command_length"] = len(cmd)
    # detect pipe/redirect
    if "|" in cmd:
        out["has_pipe"] = 1
    if ">" in cmd:
        out["has_redirect"] = 1
    # basic tokenization
    parts = cmd.split()
    if parts:
        name = parts[0]
        out["command_name"] = name
        out["arg_count"] = max(0, len(parts) - 1)
        # contains path if any arg contains '/'
        if any("/" in p for p in parts):
            out["contains_path"] = 1

        lower = name.lower()
        credential_keywords = ["passwd", "shadow", "credential", "ssh", "id_rsa"]
        file_inspect = ["cat", "less", "more", "head", "tail"]
        network_utils = ["curl", "wget", "nc", "netcat", "ssh", "scp"]
        download_utils = ["wget", "curl", "scp"]

        if any(kw in cmd.lower() for kw in credential_keywords):
            out["credential_keyword"] = 1
        if lower in network_utils:
            out["is_network_utility"] = 1
        if lower in download_utils:
            out["download_utility"] = 1

    return out


if __name__ == "__main__":
    examples = ["cat /etc/passwd", "wget http://example.com/file", "ls -l | grep foo"]
    for e in examples:
        print(e, parse_command(e))
