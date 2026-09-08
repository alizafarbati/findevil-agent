"""
findevil-mcp: Autonomous DFIR Analysis MCP Server
Connects LLM agents to SIFT Workstation forensic tools via the Model Context Protocol.

Designed for robustness: all tools have typed schemas, path validation,
audit logging, output size limits, and concurrent access protection.
"""

import asyncio
import atexit
import json
import logging
import os
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        tomllib = None

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from src._version import __version__ as SERVER_VERSION
from src.tools.carving import extract_features as carve_extract_features

# Lazy-loaded tool modules (imported once at module level)
from src.tools.memory import analyze as mem_analyze
from src.tools.memory import dump_cmdline, list_processes, scan_network
from src.tools.timeline import build as timeline_build
from src.tools.timeline import filter_timeline

# ── Configuration ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("findevil-mcp")

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
RESULTS_ROOT = Path(os.environ.get("RESULTS_ROOT", "/results"))
SERVER_NAME = "findevil-mcp"
MAX_OUTPUT_CHARS = 100_000  # Truncate tool output to prevent memory issues
MAX_TIMEOUT = 600  # Maximum tool timeout in seconds

# ── Security Events Persistence ────────────────────────────────────
SECURITY_EVENTS_FILE = Path.home() / ".local" / "share" / "findevil" / "security_events.jsonl"
SECURITY_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── Tool Configuration (loaded from tools.toml) ─────────────────────

_TOOL_CONFIG: dict[str, Any] = {}
_CONFIG_PATH = Path(__file__).parent.parent / "config" / "tools.toml"


def _load_tool_config() -> dict[str, Any]:
    """Load tool definitions from config/tools.toml.

    Returns dict of tool_name -> {command, description, args}.
    Falls back to empty dict if TOML not available or file missing.
    """
    if tomllib is None:
        logger.warning("tomllib/tomli not available — skipping tool config")
        return {}
    try:
        if not _CONFIG_PATH.exists():
            logger.info("No config/tools.toml found — using built-in tool paths")
            return {}
        with open(_CONFIG_PATH, "rb") as f:
            data = tomllib.load(f)
        tools = data.get("tools", {})
        logger.info("Loaded %d tool definitions from %s", len(tools), _CONFIG_PATH)
        return tools  # type: ignore[no-any-return]
    except Exception as e:
        logger.warning("Failed to load tool config: %s", e)
        return {}


_TOOL_CONFIG = _load_tool_config()


def _tool_config(name: str) -> dict[str, Any]:
    """Get the canonical tool definition for a tool name from config.

    Returns dict with 'command', 'description', 'args' keys or empty dict.
    """
    return _TOOL_CONFIG.get(name, {})  # type: ignore[no-any-return]


# ── Concurrency Locks ──────────────────────────────────────────────
# MCP STDIO transport is single-channel; this lock prevents interleaved responses
_call_lock = asyncio.Lock()
# Guard for concurrent access to the audit buffer (extensibility safety)
_audit_lock = asyncio.Lock()

# ── Audit Log Setup ───────────────────────────────────────────────
_audit_log_path = (
    RESULTS_ROOT / "audit" / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
)
_audit_entries: list[dict[str, Any]] = []


def _sanitize(s: str) -> str:
    """Remove control characters (except newline/tab) that could be used for log injection."""
    if not s:
        return ""
    return "".join(c for c in s if c.isprintable() or c in "\n\r\t")


def _trunc(s: str, n: int = 200) -> str:
    """Truncate a string to n chars with ellipsis. Sanitizes control chars."""
    s = _sanitize(s)
    if s and len(s) > n:
        return s[:n] + "..."
    return s or ""


_audit_buffer: list[dict[str, Any]] = []
_AUDIT_FLUSH_INTERVAL = 10  # Flush to disk every N entries


async def _audit_log(
    tool: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    duration_ms: int,
    error: Optional[str] = None,
) -> None:
    """Log a tool execution to in-memory list. Flushes to disk every N entries."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "arguments": {k: _trunc(str(v)) for k, v in arguments.items()},
        "success": result.get("success", False),
        "duration_ms": duration_ms,
        "error": _trunc(str(error)[:500] if error else str(result.get("error") or ""), 500),
    }
    async with _audit_lock:
        _audit_entries.append(entry)
        _audit_buffer.append(entry)
        # Flush to disk periodically (buffered write)
        if len(_audit_buffer) >= _AUDIT_FLUSH_INTERVAL:
            _flush_audit_buffer()


def _flush_audit_buffer() -> None:
    """Write buffered audit entries to disk."""
    if not _audit_buffer:
        return
    try:
        _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(_audit_log_path, "a") as f:
            for entry in _audit_buffer:
                f.write(json.dumps(entry) + "\n")
        _audit_buffer.clear()
    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")


async def _get_audit_logs() -> list[dict[str, Any]]:
    """Return all audit entries for the current session."""
    async with _audit_lock:
        return list(_audit_entries)


# ── Security Event Logging ─────────────────────────────────────────
_security_events: list[dict[str, Any]] = []

# Load persisted security events on startup
if SECURITY_EVENTS_FILE.exists():
    try:
        with open(str(SECURITY_EVENTS_FILE)) as f:
            for line in f:
                line = line.strip()
                if line:
                    _security_events.append(json.loads(line))
        logger.info(f"Loaded {len(_security_events)} persisted security events")
    except Exception as e:
        logger.warning(f"Failed to load security events: {e}")


def _log_security_violation(event_type: str, path: str, detail: str = "") -> None:
    """Log a security violation for audit trail."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "security_violation",
        "event": event_type,
        "path": _trunc(path, 200),
        "detail": _trunc(detail, 500),
    }
    _security_events.append(entry)
    # Persist to disk
    try:
        SECURITY_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(str(SECURITY_EVENTS_FILE), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to persist security event: {e}")
    # Cap in-memory buffer at 100,000 entries
    if len(_security_events) > 100_000:
        _security_events[:] = _security_events[-50_000:]
    logger.warning(f"Security violation: {event_type} — {path}")


async def _get_security_logs() -> list[dict[str, Any]]:
    """Return all security violation entries for the current session."""
    return list(_security_events)


def _cleanup() -> None:
    """Graceful cleanup on exit."""
    _flush_audit_buffer()
    total = len(_audit_entries)
    if total > 0:
        logger.info(f"Session ended. {total} tool calls logged to {_audit_log_path}")


atexit.register(_cleanup)


# ── Tool Execution ────────────────────────────────────────────────


def _sanitize_cmd(cmd: list[str]) -> str:
    """Sanitize command for logging — redact sensitive arguments like keys, tokens, passwords."""
    sanitized = []
    for c in cmd:
        if any(kw in c.lower() for kw in ["key", "token", "password", "secret", "credential"]):
            sanitized.append("***")
        else:
            sanitized.append(c)
    return " ".join(str(c) for c in sanitized)


async def _run_tool(
    cmd: list[str], timeout: int = 120, stdin_data: Optional[str] = None
) -> dict[str, Any]:
    """
    Run a command-line tool asynchronously and return structured result.
    Handles timeout, missing tools, and non-zero exits gracefully.
    Uses run_in_executor to avoid blocking the asyncio event loop.
    """
    # Forbidden commands that could damage the system
    FORBIDDEN_COMMANDS = {
        "dd",
        "mkfs",
        "mkfs.ext4",
        "fdisk",
        "rm",
        "shutdown",
        "poweroff",
        "reboot",
        "halt",
    }
    cmd_name = Path(cmd[0]).name if cmd else ""
    if cmd_name in FORBIDDEN_COMMANDS:
        return {"success": False, "error": f"Forbidden command: {cmd_name}"}

    loop = asyncio.get_event_loop()
    start = time.time()
    try:
        timeout = min(timeout, MAX_TIMEOUT)
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.PIPE if stdin_data else None,
            ),
        )
        duration = int((time.time() - start) * 1000)

        # Truncate output to prevent memory issues
        stdout = result.stdout[:MAX_OUTPUT_CHARS] if result.stdout else ""
        stderr = result.stderr[:MAX_OUTPUT_CHARS] if result.stderr else ""

        return {
            "success": result.returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": result.returncode,
            "duration_ms": duration,
            "command": _sanitize_cmd(cmd),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
            "duration_ms": timeout * 1000,
            "command": _sanitize_cmd(cmd),
        }
    except FileNotFoundError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Tool not found: {e}. Is SIFT Workstation installed?",
            "returncode": -1,
            "duration_ms": 0,
            "command": _sanitize_cmd(cmd),
        }
    except PermissionError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Permission denied: {e}",
            "returncode": -1,
            "duration_ms": 0,
            "command": _sanitize_cmd(cmd),
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unexpected error: {e}",
            "returncode": -1,
            "duration_ms": int((time.time() - start) * 1000),
            "command": _sanitize_cmd(cmd),
        }


# ── Tool Resolution (cached) ───────────────────────────────────────

_TOOL_CACHE: dict[str, Optional[str]] = {}


def _find_tool(name: str) -> str:
    """Find a forensic tool by name with caching.

    Delegates to src.tools.tool_resolver.find_tool for the actual
    resolution (cross-platform PATH + TOOL_LOCATIONS), then layers
    runtime caching and TOML config override on top.

    Checks (in order):
    1. Runtime cache
    2. TOML config file (config/tools.toml) — canonical path
    3. src.tools.tool_resolver.find_tool (PATH + TOOL_LOCATIONS)
    4. Fallback to bare name

    Returns full path or bare name if not found.
    """
    from src.tools.tool_resolver import find_tool as _resolve

    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]  # type: ignore[return-value]

    # 1. Check TOML config first
    cfg = _tool_config(name)
    cfg_path = cfg.get("command", "")
    if cfg_path and Path(cfg_path).exists():
        _TOOL_CACHE[name] = cfg_path
        return cfg_path  # type: ignore[no-any-return]

    # 2. Delegate to tool_resolver (PATH + TOOL_LOCATIONS)
    resolved = _resolve(name)
    if resolved:
        _TOOL_CACHE[name] = resolved
        return resolved

    # 3. Fallback to bare name
    logger.warning("Tool %s not found in config or PATH — using bare name", name)
    _TOOL_CACHE[name] = name
    return name


# ── Security Validation ────────────────────────────────────────────


def _validate_evidence_path(path: str) -> Optional[str]:
    """Validate that a path is within the evidence root and exists.
    Does NOT leak the requested path in error messages (privacy/security).
    Logs all violations to the security audit trail."""
    if not path or not path.strip():
        _log_security_violation(
            "empty_path", path or "", "Path argument was empty or whitespace-only"
        )
        return "Path cannot be empty"
    # Reject null bytes and control characters
    if "\x00" in path or any(ord(c) < 32 for c in path):
        _log_security_violation("invalid_chars", path, "Contains null byte or control characters")
        return "Path contains invalid characters"
    # Limit path length
    if len(path) > 4096:
        _log_security_violation(
            "path_too_long", path, f"Path length {len(path)} exceeds 4096 limit"
        )
        return "Path too long"
    try:
        resolved = Path(path).resolve()
        # TOCTOU mitigation: verify the final path component is not a symlink
        # and open with O_NOFOLLOW to prevent symlink-swap attacks
        try:
            fd = os.open(str(resolved), os.O_RDONLY | os.O_NOFOLLOW)
            os.close(fd)
        except OSError:
            _log_security_violation(
                "symlink_or_missing",
                path,
                "Path is a symlink, missing, or cannot be opened with O_NOFOLLOW",
            )
            return "Evidence path is invalid (symlink, missing, or inaccessible)"
        resolved.relative_to(EVIDENCE_ROOT)
        return None
    except ValueError:
        _log_security_violation("path_traversal", path, "Path resolves outside evidence root")
        return "Path outside evidence root — access denied"
    except RuntimeError:
        _log_security_violation("symlink_loop", path, "Path resolution caused a symlink loop")
        return "Path resolution error (possible symlink loop)"
    except Exception:
        _log_security_violation("validation_error", path, "Unexpected path validation failure")
        return "Path validation failed"


def _validate_output_dir(path: str) -> Optional[str]:
    """Validate that an output directory is under RESULTS_ROOT (writable area).

    Uses the same structural check as _validate_evidence_path (relative_to)
    rather than a string prefix match, so /results_backdoor cannot bypass
    the /results restriction.
    """
    if not path or not path.strip():
        _log_security_violation("output_dir_empty", path or "", "Output directory path was empty")
        return "Output path cannot be empty"
    # Reject null bytes and control characters (same as evidence path)
    if "\x00" in path or any(ord(c) < 32 for c in path):
        _log_security_violation(
            "invalid_chars", path, "Output path contains null byte or control characters"
        )
        return "Output path contains invalid characters"
    try:
        resolved = Path(path).resolve()
        resolved.relative_to(RESULTS_ROOT.resolve())
        return None
    except ValueError:
        _log_security_violation(
            "output_dir_traversal", path, f"Resolves outside results root: {RESULTS_ROOT}"
        )
        return f"Output directory must be under results root ({RESULTS_ROOT}): {path}"
    except RuntimeError:
        _log_security_violation(
            "symlink_loop", path, "Output path resolution caused a symlink loop"
        )
        return "Output path resolution error (possible symlink loop)"
    except Exception as e:
        _log_security_violation("output_dir_error", path, str(e))
        return f"Output path validation error: {e}"


def _safe_path_join(base: Path, subdir: str) -> Optional[Path]:
    """Safely join a subdirectory to base path, preventing traversal attacks."""
    if not subdir or subdir.strip() == "":
        return base
    # Reject null bytes and control characters (defense-in-depth)
    if "\x00" in subdir or any(ord(c) < 32 for c in subdir):
        _log_security_violation(
            "invalid_chars_join",
            subdir,
            "Contains null byte or control characters in path join",
        )
        return None
    # Reject path traversal characters
    if ".." in subdir or "~" in subdir or subdir.startswith("/"):
        _log_security_violation(
            "path_traversal_join",
            subdir,
            f"Attempted traversal with '..', '~', or absolute path against {base}",
        )
        return None
    try:
        joined = (base / subdir).resolve()
        # Verify it's still under base
        joined.relative_to(base.resolve())
        return joined
    except (ValueError, Exception):
        _log_security_violation(
            "path_join_error", subdir, f"Failed to safely join with base {base}"
        )
        return None


# ── MCP Server Instance ────────────────────────────────────────────
server = Server(SERVER_NAME)


# ── Tool Definitions ──────────────────────────────────────────────


@server.list_tools()  # type: ignore[untyped-decorator, no-untyped-call]
async def list_tools() -> list[Tool]:
    """Register all 23 forensic tools with typed schemas."""
    return [
        # ── File System Analysis ──────────────────────────────────
        Tool(
            name="fs_partition_scan",
            description="Scan partition table of a disk image using mmls. Start here for disk analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Path to disk image (raw, E01, etc.)",
                    },
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="fs_list_files",
            description="List files and directories in a forensic image using fls.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {
                        "type": "integer",
                        "description": "Partition offset in sectors",
                        "default": 0,
                    },
                    "path": {
                        "type": "string",
                        "description": "Path or inode to list",
                        "default": "",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recurse into subdirectories",
                        "default": False,
                    },
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="fs_extract_file",
            description="Extract file content by inode number using icat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "inode": {"type": "integer", "description": "Inode/MFT number to extract"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="fs_file_metadata",
            description="Get detailed metadata about a file/inode using istat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "inode": {"type": "integer", "description": "Inode/MFT number"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="fs_filesystem_info",
            description="Get filesystem metadata and statistics using fsstat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path"],
            },
        ),
        # ── File Carving ──────────────────────────────────────────
        Tool(
            name="carve_files",
            description="Carve files from disk image using foremost (by file headers).",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "output_dir": {
                        "type": "string",
                        "description": "Output directory (must be under /results)",
                    },
                    "file_types": {
                        "type": "string",
                        "description": "File types to carve (e.g., 'jpg,pdf,zip')",
                        "default": "all",
                    },
                },
                "required": ["image_path", "output_dir"],
            },
        ),
        # ── Pattern Matching ──────────────────────────────────────
        Tool(
            name="scan_yara",
            description="Scan file or directory with YARA rules for malware detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "File or directory to scan"},
                    "rules": {
                        "type": "string",
                        "description": "YARA rule content (inline). Must be valid YARA syntax.",
                    },
                },
                "required": ["target", "rules"],
            },
        ),
        Tool(
            name="verify_hash",
            description="Compute cryptographic hash of a file (md5, sha1, sha256).",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file"},
                    "algorithm": {
                        "type": "string",
                        "description": "Hash algorithm: md5, sha1, sha256",
                        "default": "sha256",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_evidence",
            description="List available evidence files in the evidence directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subdir": {
                        "type": "string",
                        "description": "Subdirectory to list (e.g., 'cases', 'disk')",
                        "default": "",
                    },
                },
            },
        ),
        # ── Memory Forensics ─────────────────────────────────────
        Tool(
            name="mem_analyze",
            description="Analyze memory with Volatility 3 (linux.pslist) with fallback to string-based IOC scanning. Returns process/socket/kernel module artifacts when possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {
                        "type": "string",
                        "description": "Path to memory capture file (.mem, .vmem, .elf, .core)",
                    },
                    "plugin": {
                        "type": "string",
                        "description": "Volatility3 plugin name (e.g. linux.pslist.PsList, linux.bash.Bash)",
                        "default": "linux.pslist.PsList",
                    },
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_list_processes",
            description="List processes from memory using Volatility 3 pslist or fallback string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_scan_network",
            description="Scan network connections from memory via Volatility 3 netstat or string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_dump_cmdline",
            description="Extract command lines from memory via Volatility 3 bash/cmdline plugin or string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        # ── Registry Forensics ──────────────────────────────────
        Tool(
            name="reg_analyze_hive",
            description="Analyze a Windows Registry hive file using regipy.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {
                        "type": "string",
                        "description": "Path to registry hive file (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)",
                    },
                    "key": {
                        "type": "string",
                        "description": "Registry key path to query",
                        "default": "/",
                    },
                },
                "required": ["hive_path"],
            },
        ),
        # ── Network Forensics ───────────────────────────────────
        Tool(
            name="pcap_analyze",
            description="Analyze a PCAP file using tshark. Extract protocols, conversations, and anomalies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter",
                        "default": "",
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Max packets to analyze",
                        "default": 100,
                    },
                    "fields": {
                        "type": "string",
                        "description": "Comma-separated fields to extract",
                        "default": "frame.number,ip.src,ip.dst,frame.protocols",
                    },
                },
                "required": ["pcap_path"],
            },
        ),
        Tool(
            name="pcap_list_protocols",
            description="List all protocols found in a PCAP file with packet counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                },
                "required": ["pcap_path"],
            },
        ),
        # ── Timeline Analysis ──────────────────────────────────
        Tool(
            name="timeline_build",
            description="Build forensic timeline from evidence using log2timeline/plaso.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_path": {
                        "type": "string",
                        "description": "Path to evidence (disk image, directory, etc.)",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Output path for .plaso storage file (optional)",
                        "default": "",
                    },
                },
                "required": ["source_path"],
            },
        ),
        Tool(
            name="timeline_filter",
            description="Filter and export a Plaso timeline using psort.",
            inputSchema={
                "type": "object",
                "properties": {
                    "storage_path": {
                        "type": "string",
                        "description": "Path to .plaso storage file",
                    },
                    "query": {
                        "type": "string",
                        "description": "Filter query (e.g., 'date > 2024-01-01')",
                        "default": "",
                    },
                    "output_format": {
                        "type": "string",
                        "description": "Output format: json, csv",
                        "default": "json",
                    },
                },
                "required": ["storage_path"],
            },
        ),
        # ── Feature Extraction ──────────────────────────────────
        Tool(
            name="extract_features",
            description="Extract emails, URLs, credit cards using bulk_extractor.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "scanners": {
                        "type": "string",
                        "description": "Scanners to run (comma-separated)",
                        "default": "all",
                    },
                },
                "required": ["image_path"],
            },
        ),
        # ── Accuracy Benchmark ──────────────────────────────────
        Tool(
            name="benchmark_accuracy",
            description="Run accuracy benchmark: compare agent findings against known ground truth. Computes precision, recall, F1 score.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evidence_path": {
                        "type": "string",
                        "description": "Path to evidence with known ground truth",
                    },
                    "ground_truth": {
                        "type": "string",
                        "description": "JSON array of expected finding objects (with 'type' and 'description' fields)",
                    },
                    "agent_findings": {
                        "type": "string",
                        "description": "JSON array of agent findings to compare (optional)",
                        "default": "[]",
                    },
                    "detection_threshold": {
                        "type": "number",
                        "description": "Confidence threshold for detection match",
                        "default": 0.5,
                    },
                },
                "required": ["evidence_path", "ground_truth"],
            },
        ),
        # ── Tool Configuration ─────────────────────────────────────
        Tool(
            name="get_tool_config",
            description="Get canonical configuration for a forensic tool (command path, argument schemas, description).",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Tool name (e.g., fls, icat, foremost)",
                    },
                },
                "required": ["tool_name"],
            },
        ),
        # ── Audit Trail ───────────────────────────────────────────
        Tool(
            name="get_audit_logs",
            description="Retrieve all tool execution logs from the current session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max log entries to return",
                        "default": 100,
                    },
                },
            },
        ),
        # ── Security Event Logs ───────────────────────────────────
        Tool(
            name="get_security_logs",
            description="Retrieve all security violation logs from the current session. Includes path traversal attempts, forbidden characters, and validation failures.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max log entries to return",
                        "default": 100,
                    },
                },
            },
        ),
        # ── Cross-Evidence Correlation ──────────────────────────────
        Tool(
            name="correlate_evidence",
            description="Cross-reference findings between a disk image and a memory capture. Runs parallel process-file, timeline, network-disk, and hash-identity analyses with independent timeouts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "disk_path": {
                        "type": "string",
                        "description": "Path to disk image",
                    },
                    "memory_path": {
                        "type": "string",
                        "description": "Path to memory capture file",
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output directory for correlation results (under /results)",
                        "default": "/results/correlations",
                    },
                    "analysis_timeout": {
                        "type": "number",
                        "description": "Timeout per analysis phase in seconds",
                        "default": 60.0,
                    },
                },
                "required": ["disk_path", "memory_path"],
            },
        ),
    ]


# ── Tool Call Router ──────────────────────────────────────────────


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """
    Route tool calls to the appropriate handler.
    Protected by asyncio lock to prevent interleaved responses on STDIO transport.
    Input validation: ensures arguments are proper types, no null bytes, reasonable sizes.
    """
    async with _call_lock:
        # Sanitize arguments for logging (truncate, remove control chars)
        safe_args: dict[str, Any] = {}
        for k, v in (arguments or {}).items():
            if isinstance(v, str):
                # Remove control characters and truncate
                safe_v = "".join(c for c in v if c.isprintable() or c in "\n\r\t")[:500]
                safe_args[k] = safe_v
            elif isinstance(v, (int, float, bool)):
                safe_args[k] = v
            elif v is None:
                safe_args[k] = None
            else:
                safe_args[k] = str(v)[:100]

        logger.info(f"Tool called: {name}({json.dumps(safe_args)[:200]})")
        start = time.time()

        try:
            if not name or not name.strip():
                raise ValueError("Tool name cannot be empty")

            # Sanitize arguments: no null bytes, reasonable sizes
            if arguments:
                for k, v in list(arguments.items()):
                    if isinstance(v, str):
                        if "\x00" in v:
                            raise ValueError(f"Invalid null byte in argument '{k}'")
                        if len(v) > 100000:
                            raise ValueError(f"Argument '{k}' exceeds maximum length (100K)")
                    elif isinstance(v, int):
                        if abs(v) > 10**15:
                            raise ValueError(f"Argument '{k}' value out of range")

            # Route to handler
            handler_map = {
                "fs_partition_scan": _handle_partition_scan,
                "fs_list_files": _handle_list_files,
                "fs_extract_file": _handle_extract_file,
                "fs_file_metadata": _handle_file_metadata,
                "fs_filesystem_info": _handle_fs_info,
                "carve_files": _handle_carve,
                "scan_yara": _handle_yara,
                "verify_hash": _handle_hash,
                "list_evidence": _handle_list_evidence,
                "mem_analyze": _handle_mem_analyze,
                "mem_list_processes": _handle_mem_list_processes,
                "mem_scan_network": _handle_mem_scan_network,
                "mem_dump_cmdline": _handle_mem_dump_cmdline,
                "reg_analyze_hive": _handle_reg_analyze,
                "pcap_analyze": _handle_pcap_analyze,
                "pcap_list_protocols": _handle_pcap_protocols,
                "timeline_build": _handle_timeline_build,
                "timeline_filter": _handle_timeline_filter,
                "get_tool_config": _handle_get_tool_config,
                "extract_features": _handle_extract_features,
                "benchmark_accuracy": _handle_benchmark,
                "get_audit_logs": _handle_audit_logs,
                "get_security_logs": _handle_security_logs,
                "correlate_evidence": _handle_correlate,
            }

            handler = handler_map.get(name)
            if handler is None:
                raise ValueError(
                    f"Unknown tool: '{name}'. Use 'tools' command to list available tools."
                )

            result = await handler(arguments)
            duration = int((time.time() - start) * 1000)

            # Log to audit trail
            if result and len(result) > 0:
                try:
                    result_data = json.loads(result[0].text)
                except (json.JSONDecodeError, IndexError, AttributeError):
                    result_data = {"success": True}
            else:
                result_data = {"success": True}
            await _audit_log(name, arguments, result_data, duration)

            return result

        except ValueError as e:
            duration = int((time.time() - start) * 1000)
            logger.warning(f"Tool validation error: {e}")
            await _audit_log(name, arguments, {"success": False}, duration, str(e))
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": False,
                            "error": str(e),
                            "tool": name,
                        }
                    ),
                )
            ]
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            logger.warning(f"Tool {name} failed: {e}")
            await _audit_log(name, arguments, {"success": False}, duration, str(e)[:500])
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": False,
                            "error": f"Tool execution failed: {str(e)[:200]}",
                            "tool": name,
                        }
                    ),
                )
            ]


# ═══════════════════════════════════════════════════════════════════
#  HANDLER IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════

# ── File System Handlers ─────────────────────────────────────────


async def _handle_partition_scan(args: dict[str, Any]) -> list[TextContent]:
    """Scan partition table using mmls."""
    image_path = args.get("image_path", "")
    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    mmls_cmd = _find_tool("mmls")

    result = await _run_tool([mmls_cmd, image_path])

    if result["success"]:
        partitions = []
        for line in result["stdout"].split("\n"):
            stripped = line.strip()
            if stripped and (
                stripped[0].isdigit() or "Meta" in stripped or "Unallocated" in stripped
            ):
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        slot_str = parts[0].rstrip(":")
                        if slot_str.isdigit():
                            partitions.append(
                                {
                                    "slot": int(slot_str),
                                    "start": int(parts[2]),
                                    "end": int(parts[3]),
                                    "length": int(parts[4]),
                                    "description": " ".join(parts[5:]),
                                }
                            )
                    except (ValueError, IndexError):
                        continue

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "image": image_path,
                        "partition_count": len(partitions),
                        "partitions": partitions,
                        "raw_output": result["stdout"][:10000],
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Partition scan failed: {result['stderr'] or 'No partition table found. The image may not have a GPT/MBR layout.'}",
                        "command": result["command"],
                        "suggestion": "Try fs_filesystem_info if this is a raw filesystem image without a partition table.",
                    }
                ),
            )
        ]


async def _handle_list_files(args: dict[str, Any]) -> list[TextContent]:
    """List files using fls."""
    image_path = args.get("image_path", "")
    offset = args.get("offset", 0)
    path = args.get("path", "")
    recursive = args.get("recursive", False)

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    fls_cmd = _find_tool("fls")

    cmd = [fls_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    if recursive:
        cmd.append("-r")
    cmd.append(image_path)
    if path:
        cmd.append(str(path))

    result = await _run_tool(cmd)

    if result["success"] or result["returncode"] == 1:
        entries = [line for line in result["stdout"].split("\n") if line.strip()]
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "file_count": len(entries),
                        "entries": entries[:1000],
                        "truncated": len(entries) > 1000,
                        "raw_output": result["stdout"][:50000],
                        "duration_ms": result["duration_ms"],
                        "command": result["command"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"File listing failed: {result['stderr'] or 'Unknown error'}",
                        "suggestion": "Verify the image path and partition offset. Try fs_partition_scan first.",
                    }
                ),
            )
        ]


async def _handle_extract_file(args: dict[str, Any]) -> list[TextContent]:
    """Extract file using icat."""
    image_path = args.get("image_path", "")
    inode = args.get("inode", 0)
    offset = args.get("offset", 0)

    if inode <= 0:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {"success": False, "error": "Invalid inode number. Must be a positive integer."}
                ),
            )
        ]

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    icat_cmd = _find_tool("icat")

    cmd = [icat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

    result = await _run_tool(cmd)

    if result["success"]:
        content = result["stdout"]
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "inode": inode,
                        "size": len(content),
                        "preview": content[:5000],
                        "preview_truncated": len(content) > 5000,
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Failed to extract inode {inode}: {result['stderr'] or 'File may not exist'}",
                        "suggestion": "Check that the inode exists. Try fs_list_files first to find valid inodes.",
                    }
                ),
            )
        ]


async def _handle_file_metadata(args: dict[str, Any]) -> list[TextContent]:
    """Get file metadata using istat."""
    image_path = args.get("image_path", "")
    inode = args.get("inode", 0)
    offset = args.get("offset", 0)

    if inode <= 0:
        return [
            TextContent(
                type="text", text=json.dumps({"success": False, "error": "Invalid inode number."})
            )
        ]

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    istat_cmd = _find_tool("istat")

    cmd = [istat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

    result = await _run_tool(cmd)

    if result["success"]:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "inode": inode,
                        "metadata": result["stdout"][:10000],
                        "raw_output": result["stdout"][:10000],
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Metadata lookup failed: {result['stderr'] or 'Inode may not exist'}",
                        "suggestion": "The inode may be invalid or the file system type may not be supported.",
                    }
                ),
            )
        ]


async def _handle_fs_info(args: dict[str, Any]) -> list[TextContent]:
    """Get filesystem stats using fsstat."""
    image_path = args.get("image_path", "")
    offset = args.get("offset", 0)

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    fsstat_cmd = _find_tool("fsstat")

    cmd = [fsstat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    result = await _run_tool(cmd)

    if result["success"]:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "fsstat_output": result["stdout"][:20000],
                        "raw_output": result["stdout"][:20000],
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Filesystem info failed: {result['stderr'] or 'Unrecognized filesystem type. The image may be unformatted or use an unsupported FS.'}",
                        "suggestion": "Try running fs_partition_scan first, or use a different offset.",
                    }
                ),
            )
        ]


# ── Carving Handlers ────────────────────────────────────────────


async def _handle_carve(args: dict[str, Any]) -> list[TextContent]:
    """Carve files using foremost."""
    image_path = args.get("image_path", "")
    output_dir = args.get("output_dir", "")
    file_types = args.get("file_types", "all")

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    # Validate output directory is under RESULTS_ROOT
    out_err = _validate_output_dir(output_dir)
    if out_err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": out_err}))]

    foremost_cmd = _find_tool("foremost")
    if not Path(foremost_cmd).exists():
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "foremost not found. Install: sudo apt-get install foremost",
                    }
                ),
            )
        ]

    # Create output directory just before running (not before validation)
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Cannot create output directory: {e}",
                    }
                ),
            )
        ]
    cmd = [foremost_cmd, "-o", output_dir, "-q", "-T"]
    if file_types and file_types != "all":
        cmd.extend(["-t", file_types])
    cmd.append(image_path)

    result = await _run_tool(cmd, timeout=600)

    # Count carved files
    carved_files = []
    if Path(output_dir).exists():
        for f in Path(output_dir).rglob("*"):
            if f.is_file() and f.stat().st_size > 0:
                carved_files.append(
                    {
                        "path": str(f),
                        "size": f.stat().st_size,
                        "name": f.name,
                    }
                )

    # foremost returns non-zero exit code even on success (finds files)
    # Treat as success if we found carved files OR if exit code was 0
    # Only fail if there's a genuine error (stderr content + no output)
    carved_ok = result["success"] or len(carved_files) > 0
    has_real_error = bool(result["stderr"]) and not carved_ok

    if has_real_error:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"foremost failed: {result['stderr'][:2000]}",
                        "returncode": result["returncode"],
                    }
                ),
            )
        ]

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "output_dir": output_dir,
                    "carved_files": len(carved_files),
                    "files": carved_files[:100],
                    "raw_output": result["stdout"][:10000],
                    "duration_ms": result["duration_ms"],
                },
                indent=2,
            ),
        )
    ]


# ── YARA Handler ─────────────────────────────────────────────────


async def _handle_yara(args: dict[str, Any]) -> list[TextContent]:
    """Scan with YARA rules."""
    target = args.get("target", "")
    rules = args.get("rules", "")

    if not rules or not rules.strip():
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Empty YARA rules. Provide valid YARA rule content.",
                        "suggestion": "Example: 'rule test { strings: $a = \"malware\" condition: $a }'",
                    }
                ),
            )
        ]

    if "rule " not in rules:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Invalid YARA rules syntax. Rules must contain at least one 'rule' definition.",
                        "suggestion": 'Format: rule name { strings: $a = "pattern" condition: $a }',
                    }
                ),
            )
        ]

    # Block include/import directives that could read arbitrary files
    import re

    if re.search(r'\b(include|import)\s+["\']', rules):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "YARA include/import directives are not allowed for security reasons",
                    }
                ),
            )
        ]

    err = _validate_evidence_path(target)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    # Write rules to temp file
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yara", delete=False, encoding="utf-8"
        ) as f:
            f.write(rules)
            rules_path = f.name
    except Exception as e:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Failed to write YARA rules: {e}",
                    }
                ),
            )
        ]

    try:
        yara_cmd = _find_tool("yara")
        if not Path(yara_cmd).exists():
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": False,
                            "error": "yara not found. Install: sudo apt-get install yara",
                        }
                    ),
                )
            ]

        cmd = [yara_cmd, "-w", rules_path, target]
        result = await _run_tool(cmd)

        # YARA returns 0 for matches, non-zero for no matches (which is OK)
        matches = []
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                parts = line.split(maxsplit=1)
                rule_name = parts[0] if parts else ""
                matched_file = parts[1] if len(parts) > 1 else target
                matches.append({"rule": rule_name, "target": matched_file})

        is_clean = len(matches) == 0

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "matches": matches,
                        "match_count": len(matches),
                        "clean": is_clean,
                        "message": (
                            "No YARA matches found (clean)"
                            if is_clean
                            else f"Found {len(matches)} YARA match(es)"
                        ),
                        "rules_used": rules[:500],
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    except Exception as e:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"YARA scan failed: {e}",
                    }
                ),
            )
        ]
    finally:
        try:
            os.unlink(rules_path)
        except Exception:
            pass


# ── Hash Handler ────────────────────────────────────────────────


async def _handle_hash(args: dict[str, Any]) -> list[TextContent]:
    """Compute file hash."""
    file_path = args.get("file_path", "")
    algorithm = args.get("algorithm", "sha256")

    err = _validate_evidence_path(file_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    from src.tools.tool_resolver import find_tool

    hash_tool_map = {
        "md5": find_tool("md5sum") or "/usr/bin/md5sum",
        "sha1": find_tool("sha1sum") or "/usr/bin/sha1sum",
        "sha256": find_tool("sha256sum") or "/usr/bin/sha256sum",
        "sha512": find_tool("sha512sum") or "/usr/bin/sha512sum",
    }

    hash_bin = hash_tool_map.get(algorithm)
    if not hash_bin:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Unsupported algorithm: {algorithm}. Use: md5, sha1, sha256, sha512",
                    }
                ),
            )
        ]

    result = await _run_tool([hash_bin, file_path])

    if result["success"]:
        hash_value = result["stdout"].split()[0] if result["stdout"] else ""
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "algorithm": algorithm,
                        "hash": hash_value,
                        "file": file_path,
                        "duration_ms": result["duration_ms"],
                    },
                    indent=2,
                ),
            )
        ]
    else:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Hash failed: {result['stderr'] or 'Unknown error'}",
                    }
                ),
            )
        ]


# ── Evidence List Handler ───────────────────────────────────────


async def _handle_list_evidence(args: dict[str, Any]) -> list[TextContent]:
    """List available evidence."""
    subdir = args.get("subdir", "")

    # Security: prevent path traversal
    if subdir:
        safe_path = _safe_path_join(EVIDENCE_ROOT, subdir)
        if safe_path is None:
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": False,
                            "error": f"Invalid subdirectory: '{subdir}'. Path traversal not allowed.",
                        }
                    ),
                )
            ]
        target_dir = safe_path
    else:
        target_dir = EVIDENCE_ROOT

    if not target_dir.exists():
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Directory does not exist: {target_dir}",
                        "suggestion": "Create it: mkdir -p /evidence/{disk,memory,network,cases}",
                    }
                ),
            )
        ]

    files = []
    try:
        for f in sorted(target_dir.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
            try:
                stat = f.stat()
                files.append(
                    {
                        "name": f.name,
                        "type": "directory" if f.is_dir() else "file",
                        "size": stat.st_size if f.is_file() else 0,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                )
            except (OSError, PermissionError):
                files.append(
                    {
                        "name": f.name,
                        "type": "unknown",
                        "size": 0,
                        "error": "Cannot read metadata",
                    }
                )
    except PermissionError:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Permission denied reading {target_dir}",
                    }
                ),
            )
        ]

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "path": str(target_dir),
                    "file_count": len(files),
                    "files": files,
                },
                indent=2,
            ),
        )
    ]


# ── Memory Forensics Handlers ─────────────────────────────────────


def _is_memory_capture(path: str) -> bool:
    """Detect if a file is a memory capture via magic bytes and extension.

    Strict checking to prevent misidentification of non-memory files:
    - ELF headers require additional content checks
    - gzip/compressed files are rejected (too common in non-memory files)
    - Extensions must match known memory capture suffixes
    """
    try:
        with open(path, "rb") as f:
            raw = f.read(64)
            if len(raw) < 4:
                return False
        # ELF binary — check for additional memory capture signatures
        if raw[:4] == b"\x7fELF":
            # Linux memory dumps (LiME, avml) produce ELF core dumps
            # Check for additional evidence: size > 10MB and ELF type is ET_CORE
            try:
                size = Path(path).stat().st_size
                if size < 10 * 1024 * 1024:  # < 10MB is unlikely to be a memory dump
                    return False
                # Check ELF type at offset 16 (2 bytes)
                elf_type = int.from_bytes(raw[16:18], "little") if len(raw) >= 18 else 0
                if elf_type == 4:  # ET_CORE
                    return True
                return True  # Accept ELF as potential memory dump
            except Exception:
                return True  # Conservative: accept ELF
        # Windows memory dumps have PAGE header
        if raw[:4] == b"PAGE":
            return True
        # Check for memory capture strings in header
        if b"VMem" in raw or b"vmem" in raw:
            return True
    except Exception:
        pass
    # Strict extension check
    mem_extensions = {".mem", ".vmem", ".dump", ".dmp", ".core", ".elf", ".crash", ".raw"}
    ext = Path(path).suffix.lower()
    if ext not in mem_extensions:
        return False
    # Even with matching extension, check file size (> 5MB minimum for memory dumps)
    try:
        return Path(path).stat().st_size >= 5 * 1024 * 1024
    except Exception:
        return False


async def _handle_mem_analyze(args: dict[str, Any]) -> list[TextContent]:
    """Analyze memory with Volatility 3 plugin, with fallback to string IOC scanning."""
    mem_path = args.get("memory_path", "")
    plugin = args.get("plugin", "linux.pslist.PsList")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a recognized memory capture file",
                        "suggestion": "This tool requires a memory dump (.mem, .vmem, .dmp, .elf, .core, .raw)",
                    }
                ),
            )
        ]
    result = mem_analyze(mem_path, plugin, use_fallback=True)
    return [
        TextContent(
            type="text",
            text=json.dumps(
                (
                    {
                        "success": result.success,
                        "plugin": result.plugin,
                        "data": result.data,
                        "error": result.error,
                        "note": (
                            result.data[0].get("note", "")
                            if result.data and isinstance(result.data[0], dict)
                            else ""
                        ),
                    }
                    if result.success
                    else {"success": False, "error": result.error}
                ),
                indent=2,
            ),
        )
    ]


async def _handle_mem_list_processes(args: dict[str, Any]) -> list[TextContent]:
    """List processes from memory using pslist, with fallback to string IOC scanning."""
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a memory capture file",
                        "suggestion": "Use a memory dump (.mem, .vmem, .dmp, etc.)",
                    }
                ),
            )
        ]
    result = list_processes(mem_path)
    return [
        TextContent(
            type="text",
            text=json.dumps(
                (
                    {
                        "success": result.success,
                        "plugin": result.plugin,
                        "data": result.data,
                        "error": result.error,
                        "note": (
                            result.data[0].get("note", "")
                            if result.data and isinstance(result.data[0], dict)
                            else ""
                        ),
                    }
                    if result.success
                    else {"success": False, "error": result.error}
                ),
                indent=2,
            ),
        )
    ]


async def _handle_mem_scan_network(args: dict[str, Any]) -> list[TextContent]:
    """Scan network connections from memory, with fallback to string IOC scanning."""
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a memory capture file",
                    }
                ),
            )
        ]
    result = scan_network(mem_path)
    return [
        TextContent(
            type="text",
            text=json.dumps(
                (
                    {
                        "success": result.success,
                        "plugin": result.plugin,
                        "data": result.data,
                        "error": result.error,
                    }
                    if result.success
                    else {"success": False, "error": result.error}
                ),
                indent=2,
            ),
        )
    ]


async def _handle_mem_dump_cmdline(args: dict[str, Any]) -> list[TextContent]:
    """Dump command lines from memory processes, with fallback to string IOC scanning."""
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a memory capture file",
                    }
                ),
            )
        ]
    result = dump_cmdline(mem_path)
    return [
        TextContent(
            type="text",
            text=json.dumps(
                (
                    {
                        "success": result.success,
                        "plugin": result.plugin,
                        "data": result.data,
                        "error": result.error,
                    }
                    if result.success
                    else {"success": False, "error": result.error}
                ),
                indent=2,
            ),
        )
    ]


# ── Registry Forensics Handlers ──────────────────────────────────


def _is_registry_hive(path: str) -> bool:
    """Check if a file is a Windows Registry hive via 'regf' magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"regf"
    except Exception:
        return False


async def _handle_reg_analyze(args: dict[str, Any]) -> list[TextContent]:
    hive_path = args.get("hive_path", "")
    key = args.get("key", "/")

    # Validate path FIRST before checking existence (prevents path oracle attacks)
    err = _validate_evidence_path(hive_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    if not Path(hive_path).exists():
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Specified file does not exist in evidence directory",
                    }
                ),
            )
        ]

    if not _is_registry_hive(hive_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a Registry hive file",
                        "suggestion": "This tool requires a Windows Registry hive file. Look for files named SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT",
                    }
                ),
            )
        ]

    try:
        from regipy import RegistryHive

        hive = RegistryHive(hive_path)  # type: ignore[no-untyped-call]
        result_data = []
        try:
            for entry in hive.recurse_subkeys(key):  # type: ignore[no-untyped-call]
                entry_data = {
                    "path": entry.path,
                    "timestamp": str(entry.timestamp) if entry.timestamp else None,
                }
                try:
                    values = {}
                    for v in getattr(entry, "values", []):
                        try:
                            values[v.name] = str(v.value)[:200]
                        except Exception:
                            values[v.name] = "<binary>"
                    entry_data["values"] = values
                except Exception:
                    entry_data["values"] = {}
                result_data.append(entry_data)
                if len(result_data) >= 200:
                    break
        except Exception as e:
            # Key may not exist
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "success": False,
                            "error": f"Registry key not found: {key}. Error: {e}",
                            "suggestion": "Try '/' to list all top-level keys, or a standard path like '/Microsoft/Windows/CurrentVersion/Run'",
                        }
                    ),
                )
            ]

        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "hive": hive_path,
                        "key_path": key,
                        "key_count": len(result_data),
                        "keys": result_data[:200],
                    },
                    indent=2,
                ),
            )
        ]
    except ImportError:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "regipy not installed. Install: pip install regipy",
                    }
                ),
            )
        ]
    except Exception as e:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": f"Registry analysis failed: {e}",
                    }
                ),
            )
        ]


# ── Network Forensics Handlers ───────────────────────────────────


def _is_pcap(path: str) -> bool:
    """Check if a file is a PCAP via magic bytes or extension."""
    pcap_extensions = {".pcap", ".pcapng", ".cap"}
    if Path(path).suffix.lower() in pcap_extensions:
        return True
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        return header in (b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a", b"\xa1\xb2\xc3\xd4")
    except Exception:
        return False


async def _handle_pcap_analyze(args: dict[str, Any]) -> list[TextContent]:
    pcap_path = args.get("pcap_path", "")
    display_filter = args.get("display_filter", "")
    max_packets = args.get("max_packets", 100)
    fields = args.get("fields", "frame.number,ip.src,ip.dst,frame.protocols")

    err = _validate_evidence_path(pcap_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    if not _is_pcap(pcap_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a packet capture file",
                        "suggestion": "Use a PCAP/PCAPNG file",
                    }
                ),
            )
        ]

    tshark_cmd = _find_tool("tshark")
    if not Path(tshark_cmd).exists():
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "tshark not found. Install: sudo apt-get install tshark",
                    }
                ),
            )
        ]

    # Main packet extraction
    cmd = [tshark_cmd, "-r", pcap_path, "-T", "json"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    if max_packets > 0:
        cmd.extend(["-c", str(max_packets)])
    for field in fields.split(","):
        field = field.strip()
        if field:
            cmd.extend(["-e", field])

    result = await _run_tool(cmd, timeout=120)

    packets = []
    if result["stdout"].strip():
        try:
            parsed = json.loads(result["stdout"])
            for p in (parsed if isinstance(parsed, list) else [parsed]):
                layers = p.get("_source", {}).get("layers", {})
                packets.append(
                    {
                        "frame": _get_layer(layers, "frame.number", ""),
                        "src": _get_layer(layers, "ip.src", ""),
                        "dst": _get_layer(layers, "ip.dst", ""),
                        "protocol": _get_layer(layers, "frame.protocols", ""),
                        "info": _get_layer(layers, "_ws.col.Info", ""),
                    }
                )
        except json.JSONDecodeError:
            packets.append({"raw": result["stdout"][:5000]})

    # Protocol hierarchy
    proto_cmd = [tshark_cmd, "-r", pcap_path, "-z", "io,phs", "-q"]
    proto_result = await _run_tool(proto_cmd, timeout=60)

    # Conversations
    conv_cmd = [tshark_cmd, "-r", pcap_path, "-z", "conv,ip", "-q"]
    conv_result = await _run_tool(conv_cmd, timeout=60)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "pcap": pcap_path,
                    "packet_count": len(packets),
                    "packets": packets[:100],
                    "protocol_hierarchy": (
                        proto_result["stdout"][:5000] if proto_result["success"] else ""
                    ),
                    "conversations": conv_result["stdout"][:3000] if conv_result["success"] else "",
                    "duration_ms": result["duration_ms"],
                },
                indent=2,
            ),
        )
    ]


def _get_layer(layers: dict[str, Any], key: str, default: str = "") -> str:
    """Safely extract a value from tshark JSON layers."""
    val = layers.get(key, default)
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val) if val else default


async def _handle_pcap_protocols(args: dict[str, Any]) -> list[TextContent]:
    """List protocols in a PCAP."""
    pcap_path = args.get("pcap_path", "")
    err = _validate_evidence_path(pcap_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_pcap(pcap_path):
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Not a packet capture file",
                    }
                ),
            )
        ]

    tshark_cmd = _find_tool("tshark")
    result = await _run_tool([tshark_cmd, "-r", pcap_path, "-z", "io,phs", "-q"], timeout=60)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": result["success"],
                    "protocols": result["stdout"][:10000] if result["success"] else "",
                    "error": result.get("stderr", "") if not result["success"] else None,
                },
                indent=2,
            ),
        )
    ]


# ── Timeline Analysis Handlers ───────────────────────────────────


async def _handle_timeline_build(args: dict[str, Any]) -> list[TextContent]:
    source_path = args.get("source_path", "")
    output_path = args.get("output_path", "")

    err = _validate_evidence_path(source_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    result = timeline_build(source_path, output_path or None)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": result.success,
                    "storage_path": result.storage_path,
                    "source": source_path,
                    "error": result.error,
                    "event_count": result.event_count,
                },
                indent=2,
            ),
        )
    ]


async def _handle_timeline_filter(args: dict[str, Any]) -> list[TextContent]:
    storage_path = args.get("storage_path", "")
    query = args.get("query", "")
    output_format = args.get("output_format", "json")

    err = _validate_evidence_path(storage_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    result = filter_timeline(storage_path, query, output_format)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": result.success,
                    "event_count": result.event_count,
                    "events": result.data[:500],
                    "error": result.error,
                },
                indent=2,
            ),
        )
    ]


async def _handle_extract_features(args: dict[str, Any]) -> list[TextContent]:
    image_path = args.get("image_path", "")
    scanners = args.get("scanners", "all")

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    result = carve_extract_features(image_path, scanners)

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": result.success,
                    "output_dir": result.output_dir,
                    "feature_files": result.file_count,
                    "details": result.data,
                    "error": result.error,
                },
                indent=2,
            ),
        )
    ]


# ── Accuracy Benchmark Handler ───────────────────────────────────


async def _handle_benchmark(args: dict[str, Any]) -> list[TextContent]:
    """Compare agent findings against known ground truth.

    Expects ground_truth as JSON array of finding objects with:
    - type: finding type string
    - description: description text (used for matching)
    - confidence: expected confidence level (CONFIRMED, INFERRED, UNVERIFIED)
    """
    evidence_path = args.get("evidence_path", "")
    ground_truth_str = args.get("ground_truth", "[]")
    agent_findings_str = args.get("agent_findings", "[]")
    detection_threshold = float(args.get("detection_threshold", "0.5"))

    err = _validate_evidence_path(evidence_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    try:
        ground_truth = (
            json.loads(ground_truth_str) if isinstance(ground_truth_str, str) else ground_truth_str
        )
    except json.JSONDecodeError:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "Invalid ground truth JSON. Provide a valid JSON array of expected findings.",
                    }
                ),
            )
        ]

    try:
        agent_findings = (
            json.loads(agent_findings_str)
            if isinstance(agent_findings_str, str)
            else agent_findings_str
        )
    except json.JSONDecodeError:
        agent_findings = []

    if not isinstance(ground_truth, list):
        ground_truth = [ground_truth]
    if not isinstance(agent_findings, list):
        agent_findings = [agent_findings]

    # Compute comparison metrics
    gt_types = set()
    for gt in ground_truth:
        if isinstance(gt, dict):
            gt_types.add(gt.get("type", gt.get("description", str(gt))))

    af_types = set()
    for af in agent_findings:
        if isinstance(af, dict):
            af_types.add(af.get("type", af.get("description", str(af))))
        elif isinstance(af, str):
            af_types.add(af)

    # True positives: agent finding matches a ground truth entry
    true_positives = len(gt_types & af_types)
    false_positives = len(af_types - gt_types)
    false_negatives = len(gt_types - af_types)

    # Precision, Recall, F1
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Grade
    if f1_score >= 0.9:
        grade = "A (Excellent)"
    elif f1_score >= 0.8:
        grade = "B (Good)"
    elif f1_score >= 0.6:
        grade = "C (Adequate)"
    elif f1_score >= 0.4:
        grade = "D (Poor)"
    else:
        grade = "F (Failing)"

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "benchmark": {
                        "evidence": evidence_path,
                        "ground_truth_count": len(ground_truth),
                        "agent_findings_count": len(agent_findings),
                        "metrics": {
                            "true_positives": true_positives,
                            "false_positives": false_positives,
                            "false_negatives": false_negatives,
                            "precision": round(precision, 4),
                            "recall": round(recall, 4),
                            "f1_score": round(f1_score, 4),
                            "detection_threshold": detection_threshold,
                        },
                        "grade": grade,
                        "ground_truth_types": sorted(list(gt_types)),
                        "agent_detected_types": sorted(list(af_types)),
                        "missed_types": sorted(list(gt_types - af_types)),
                        "false_positive_types": sorted(list(af_types - gt_types)),
                        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                },
                indent=2,
            ),
        )
    ]


# ── Tool Config Handler ─────────────────────────────────────────


async def _handle_get_tool_config(args: dict[str, Any]) -> list[TextContent]:
    """Return canonical tool configuration from config/tools.toml."""
    tool_name = args.get("tool_name", "")
    if not tool_name:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": False,
                        "error": "tool_name is required",
                        "available_tools": list(_TOOL_CONFIG.keys()),
                    }
                ),
            )
        ]

    cfg = _tool_config(tool_name)
    if cfg:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "tool": tool_name,
                        "config": cfg,
                    },
                    indent=2,
                ),
            )
        ]

    # Fallback to built-in known tools
    builtin_info = {
        "fls": {"command": _find_tool("fls"), "description": "List files in forensic image"},
        "icat": {"command": _find_tool("icat"), "description": "Extract file by inode"},
        "mmls": {"command": _find_tool("mmls"), "description": "Display partition table"},
        "fsstat": {"command": _find_tool("fsstat"), "description": "Filesystem statistics"},
        "foremost": {"command": _find_tool("foremost"), "description": "Carve files by headers"},
        "yara": {"command": _find_tool("yara"), "description": "YARA pattern matching"},
        "tshark": {"command": _find_tool("tshark"), "description": "Packet analysis"},
    }
    info = builtin_info.get(tool_name)
    if info:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "success": True,
                        "tool": tool_name,
                        "config": info,
                        "source": "built-in (not in tools.toml)",
                    },
                    indent=2,
                ),
            )
        ]

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": False,
                    "error": f"Unknown tool: {tool_name}",
                    "known_tools": list(builtin_info.keys()) + list(_TOOL_CONFIG.keys()),
                }
            ),
        )
    ]


# ── Audit Log Handler ────────────────────────────────────────────


async def _handle_audit_logs(args: dict[str, Any]) -> list[TextContent]:
    """Return audit logs from current session."""
    limit = max(1, min(args.get("limit", 100), 10000))
    logs = (await _get_audit_logs())[-limit:]
    async with _audit_lock:
        has_entries = bool(_audit_entries)
        total = len(_audit_entries)
    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "session_log_path": str(_audit_log_path) if has_entries else "",
                    "total_entries": total,
                    "entries": logs,
                },
                indent=2,
            ),
        )
    ]


async def _handle_security_logs(args: dict[str, Any]) -> list[TextContent]:
    """Return security violation logs from current session."""
    limit = max(1, min(args.get("limit", 100), 10000))
    logs = (await _get_security_logs())[-limit:]
    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "success": True,
                    "total_events": len(_security_events),
                    "events": logs,
                },
                indent=2,
            ),
        )
    ]


# ═══════════════════════════════════════════════════════════════════
#  CROSS-SOURCE CORRELATION
# ═══════════════════════════════════════════════════════════════════


async def _handle_correlate(args: dict[str, Any]) -> list[TextContent]:
    """Cross-reference findings between disk image and memory capture.

    Delegates to src.tools.correlation.CorrelationEngine which runs
    four parallel analyses: process-file, timeline, network-disk, and
    hash-identity. All four are wrapped with independent timeouts so a
    hang in one analysis cannot block the others.
    """
    disk_path = args.get("disk_path", "")
    memory_path = args.get("memory_path", "")
    output_dir = args.get("output_dir", "/results/correlations")
    timeout = float(args.get("analysis_timeout", 60.0))

    # Validate paths
    err = _validate_evidence_path(disk_path)
    if err:
        return [
            TextContent(type="text", text=json.dumps({"success": False, "error": f"disk: {err}"}))
        ]
    err = _validate_evidence_path(memory_path)
    if err:
        return [
            TextContent(type="text", text=json.dumps({"success": False, "error": f"memory: {err}"}))
        ]

    from src.tools.correlation import CorrelationEngine

    # Lock-free internal dispatch — calls handlers directly so that
    # correlation can invoke fs_* / mem_* tools without deadlocking on
    # _call_lock (which is already held when this handler runs).
    _HANDLER_MAP = {
        "fs_partition_scan": _handle_partition_scan,
        "fs_list_files": _handle_list_files,
        "fs_extract_file": _handle_extract_file,
        "fs_file_metadata": _handle_file_metadata,
        "fs_filesystem_info": _handle_fs_info,
        "carve_files": _handle_carve,
        "scan_yara": _handle_yara,
        "verify_hash": _handle_hash,
        "list_evidence": _handle_list_evidence,
        "mem_analyze": _handle_mem_analyze,
        "mem_list_processes": _handle_mem_list_processes,
        "mem_scan_network": _handle_mem_scan_network,
        "mem_dump_cmdline": _handle_mem_dump_cmdline,
        "reg_analyze_hive": _handle_reg_analyze,
        "pcap_analyze": _handle_pcap_analyze,
        "pcap_list_protocols": _handle_pcap_protocols,
        "timeline_build": _handle_timeline_build,
        "timeline_filter": _handle_timeline_filter,
        "extract_features": _handle_extract_features,
        "get_audit_logs": _handle_audit_logs,
        "get_security_logs": _handle_security_logs,
        "benchmark_accuracy": _handle_benchmark,
    }

    async def _tool_caller(name: str, arguments: dict) -> dict:
        try:
            handler = _HANDLER_MAP.get(name)
            if handler is None:
                return {"success": False, "error": f"Unknown internal tool: {name}"}
            result = await handler(arguments)
            if isinstance(result, list) and len(result) == 1:
                text = result[0].text
                return json.loads(text)
            return {"success": False, "error": f"Unexpected shape: {type(result).__name__}"}
        except Exception as exc:
            return {"success": False, "error": f"{name} raised: {exc}"}

    engine = CorrelationEngine(
        disk_path=disk_path,
        memory_path=memory_path,
        tool_caller=_tool_caller,
        output_dir=output_dir,
        analysis_timeout=timeout,
    )

    try:
        report = await engine.run()
        return [TextContent(type="text", text=json.dumps(report.model_dump(), indent=2))]
    except Exception as exc:
        logger.exception("Correlation engine failed")
        return [
            TextContent(type="text", text=json.dumps({"success": False, "error": str(exc)[:500]}))
        ]


# ═══════════════════════════════════════════════════════════════════
#  SERVER ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════


async def main() -> None:
    """Start the MCP server with graceful shutdown handling."""
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"Evidence root: {EVIDENCE_ROOT}")
    logger.info(f"Results root: {RESULTS_ROOT}")
    logger.info("23 forensic tools registered")

    # Ensure directories exist
    try:
        EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
        RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
        for sub in ("disk", "memory", "network", "cases"):
            (EVIDENCE_ROOT / sub).mkdir(exist_ok=True)
        for sub in ("audit", "carved", "timelines", "reports"):
            (RESULTS_ROOT / sub).mkdir(exist_ok=True)
    except PermissionError:
        logger.warning(
            f"Cannot create directories. Ensure {EVIDENCE_ROOT} and {RESULTS_ROOT} exist."
        )

    # Signal handling for graceful shutdown
    shutdown_event = asyncio.Event()

    def _handle_signal(signum: int, frame: Optional[Any]) -> None:
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, shutting down gracefully...")
        total = len(_audit_entries)
        if total > 0:
            logger.info(f"Audit log: {total} calls saved to {_audit_log_path}")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Run server
    async with stdio_server() as (read_stream, write_stream):
        server_task = asyncio.create_task(
            server.run(read_stream, write_stream, server.create_initialization_options())
        )

        await asyncio.wait(
            [server_task, asyncio.create_task(shutdown_event.wait())],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if shutdown_event.is_set():
            server_task.cancel()
            logger.info("Server shut down gracefully")


if __name__ == "__main__":
    asyncio.run(main())
