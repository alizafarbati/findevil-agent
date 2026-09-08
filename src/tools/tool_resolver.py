"""
Cross-Platform Tool Resolution
Finds forensic tools on any OS (Linux, macOS, Windows).
"""

import shutil
import sys
from pathlib import Path
from typing import Optional

# Known tool locations per platform
TOOL_LOCATIONS = {
    "fls": {
        "linux": ["/usr/bin/fls", "/usr/local/bin/fls", "/bin/fls"],
        "darwin": ["/usr/local/bin/fls", "/opt/homebrew/bin/fls", "/usr/bin/fls"],
        "win32": ["C:\\sleuthkit\\bin\\fls.exe", "C:\\Program Files\\sleuthkit\\bin\\fls.exe"],
    },
    "icat": {
        "linux": ["/usr/bin/icat", "/usr/local/bin/icat"],
        "darwin": ["/usr/local/bin/icat", "/opt/homebrew/bin/icat"],
        "win32": ["C:\\sleuthkit\\bin\\icat.exe"],
    },
    "mmls": {
        "linux": ["/usr/bin/mmls", "/usr/local/bin/mmls"],
        "darwin": ["/usr/local/bin/mmls", "/opt/homebrew/bin/mmls"],
        "win32": ["C:\\sleuthkit\\bin\\mmls.exe"],
    },
    "fsstat": {
        "linux": ["/usr/bin/fsstat", "/usr/local/bin/fsstat"],
        "darwin": ["/usr/local/bin/fsstat", "/opt/homebrew/bin/fsstat"],
        "win32": ["C:\\sleuthkit\\bin\\fsstat.exe"],
    },
    "istat": {
        "linux": ["/usr/bin/istat", "/usr/local/bin/istat"],
        "darwin": ["/usr/local/bin/istat", "/opt/homebrew/bin/istat"],
        "win32": ["C:\\sleuthkit\\bin\\istat.exe"],
    },
    "foremost": {
        "linux": ["/usr/bin/foremost", "/usr/local/bin/foremost"],
        "darwin": ["/usr/local/bin/foremost", "/opt/homebrew/bin/foremost"],
        "win32": [],
    },
    "yara": {
        "linux": ["/usr/bin/yara", "/usr/local/bin/yara"],
        "darwin": ["/usr/local/bin/yara", "/opt/homebrew/bin/yara"],
        "win32": ["C:\\yara\\yara.exe", "C:\\Program Files\\yara\\yara.exe"],
    },
    "tshark": {
        "linux": ["/usr/bin/tshark", "/usr/local/bin/tshark"],
        "darwin": ["/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"],
        "win32": ["C:\\Program Files\\Wireshark\\tshark.exe"],
    },
    "md5sum": {
        "linux": ["/usr/bin/md5sum"],
        "darwin": ["/sbin/md5"],
        "win32": ["C:\\Windows\\System32\\certutil.exe"],
    },
    "sha1sum": {
        "linux": ["/usr/bin/sha1sum"],
        "darwin": ["/usr/bin/shasum"],
        "win32": ["C:\\Windows\\System32\\certutil.exe"],
    },
    "sha256sum": {
        "linux": ["/usr/bin/sha256sum"],
        "darwin": ["/usr/bin/shasum"],
        "win32": ["C:\\Windows\\System32\\certutil.exe"],
    },
    "sha512sum": {
        "linux": ["/usr/bin/sha512sum"],
        "darwin": ["/usr/bin/shasum"],
        "win32": ["C:\\Windows\\System32\\certutil.exe"],
    },
    "strings": {
        "linux": ["/usr/bin/strings", "/usr/local/bin/strings"],
        "darwin": ["/usr/bin/strings"],
        "win32": [],
    },
    "python3": {
        "linux": ["/usr/bin/python3", "/usr/local/bin/python3"],
        "darwin": ["/usr/bin/python3", "/opt/homebrew/bin/python3"],
        "win32": [
            r"C:\Python314\python.exe",
            r"C:\Python313\python.exe",
            r"C:\Python312\python.exe",
            r"C:\Python311\python.exe",
            r"C:\Python310\python.exe",
        ],
    },
    "debugfs": {
        "linux": ["/usr/bin/debugfs", "/usr/local/bin/debugfs"],
        "darwin": ["/usr/local/bin/debugfs"],
        "win32": [],
    },
    "vol.py": {
        "linux": [
            "/usr/local/bin/vol.py",
            "/usr/bin/vol.py",
            str(Path.home() / ".local" / "bin" / "vol.py"),
            str(Path.home() / "vol.py"),
        ],
        "darwin": [
            "/usr/local/bin/vol.py",
            str(Path.home() / ".local" / "bin" / "vol.py"),
        ],
        "win32": [
            "C:\\volatility3\\vol.py",
            "C:\\Python311\\Scripts\\vol.py",
        ],
    },
    "bulk_extractor": {
        "linux": ["/usr/bin/bulk_extractor", "/usr/local/bin/bulk_extractor"],
        "darwin": ["/usr/local/bin/bulk_extractor", "/opt/homebrew/bin/bulk_extractor"],
        "win32": [],
    },
    "binwalk": {
        "linux": ["/usr/bin/binwalk", "/usr/local/bin/binwalk"],
        "darwin": ["/usr/local/bin/binwalk"],
        "win32": [],
    },
    "reglookup": {
        "linux": ["/usr/bin/reglookup", "/usr/local/bin/reglookup"],
        "darwin": ["/usr/local/bin/reglookup", "/opt/homebrew/bin/reglookup"],
        "win32": [],
    },
    "hashdeep": {
        "linux": ["/usr/bin/hashdeep", "/usr/local/bin/hashdeep"],
        "darwin": ["/usr/local/bin/hashdeep"],
        "win32": [],
    },
}


def find_tool(name: str) -> Optional[str]:
    """
    Find a forensic tool on the current platform.

    Strategy:
    1. Try `shutil.which()` (checks PATH)
    2. Try known locations for the current platform
    3. Try all known locations across platforms

    Returns:
        Full path to tool, or None if not found.
    """
    # Guard: reject non-string, empty, or malformed input
    if not isinstance(name, str) or not name:
        return None
    # Reject null bytes and control characters that could crash shutil.which
    if "\x00" in name or any(ord(c) < 32 for c in name):
        return None

    # 1. PATH lookup
    path = shutil.which(name)
    if path:
        return path

    # 1b. Interpreters: resolve "python3"/"python" to the running interpreter
    #     (covers Windows where the binary is python.exe, and any venv).
    if name in ("python3", "python") and sys.executable:
        return sys.executable

    # 2. Platform-specific known locations
    platform = sys.platform  # 'linux', 'darwin', 'win32'
    locations = TOOL_LOCATIONS.get(name, {})
    platform_locs = locations.get(platform, [])

    for loc in platform_locs:
        if Path(loc).exists():
            return loc

    # 3. Try all locations (cross-platform fallback)
    for locs in locations.values():
        for loc in locs:
            if Path(loc).exists():
                return loc

    return None


def find_tools(*names: str) -> dict[str, Optional[str]]:
    """Find multiple tools at once. Returns dict of {name: path_or_None}."""
    return {name: find_tool(name) for name in names}


def require_tool(name: str) -> str:
    """Like find_tool but raises FileNotFoundError if not found."""
    path = find_tool(name)
    if not path:
        raise FileNotFoundError(
            f"Required forensic tool '{name}' not found. "
            f"Install it or add it to your PATH.\n"
            f"  - Linux: sudo apt-get install {_apt_package(name)}\n"
            f"  - macOS: brew install {_brew_package(name)}\n"
            f"  - Windows: see tool documentation"
        )
    return path


def _apt_package(name: str) -> str:
    """Map tool name to apt package name."""
    mapping = {
        "fls": "sleuthkit",
        "icat": "sleuthkit",
        "mmls": "sleuthkit",
        "fsstat": "sleuthkit",
        "istat": "sleuthkit",
        "foremost": "foremost",
        "yara": "yara",
        "tshark": "tshark",
        "strings": "binutils",
        "debugfs": "e2fsprogs",
        "python3": "python3",
    }
    return mapping.get(name, name)


def _brew_package(name: str) -> str:
    """Map tool name to Homebrew package name."""
    mapping = {
        "fls": "sleuthkit",
        "icat": "sleuthkit",
        "mmls": "sleuthkit",
        "fsstat": "sleuthkit",
        "istat": "sleuthkit",
        "foremost": "foremost",
        "yara": "yara",
        "tshark": "wireshark",
        "strings": "binutils",
        "python3": "python3",
    }
    return mapping.get(name, name)
