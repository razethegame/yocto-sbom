"""Git submodule parsing."""

import os
import re
import subprocess


def parse_gitmodules(gitmodules_path):
    """Parse .gitmodules file to extract submodule info.

    Args:
        gitmodules_path: Path to .gitmodules file.

    Returns:
        List of dicts with submodule metadata (name, path, url).
    """
    submodules = []
    if not os.path.isfile(gitmodules_path):
        return submodules

    current = {}
    with open(gitmodules_path, 'r') as f:
        for line in f:
            line = line.strip()
            section = re.match(r'^\[submodule\s+"(.+)"\]$', line)
            if section:
                if current:
                    submodules.append(current)
                current = {'name': section.group(1)}
                continue
            kv = re.match(r'^(\w+)\s*=\s*(.+)$', line)
            if kv and current:
                current[kv.group(1)] = kv.group(2).strip()
    if current:
        submodules.append(current)

    # Sanitise URLs: strip deploy-token credentials
    for sub in submodules:
        url = sub.get('url', '')
        url = re.sub(r'https://[^@]+@', 'https://', url)
        sub['url'] = url

    return submodules


def get_submodule_commits():
    """Run `git submodule status` and return {path: commit_sha}.

    Returns:
        Dict mapping submodule path to commit SHA.
    """
    commits = {}
    try:
        result = subprocess.run(
            ['git', 'submodule', 'status'],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.strip().splitlines():
            # Format: " <sha> <path> (<describe>)" or "+<sha> <path> (<describe>)"
            m = re.match(r'^[+ -]?([0-9a-f]+)\s+(\S+)', line)
            if m:
                commits[m.group(2)] = m.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return commits
