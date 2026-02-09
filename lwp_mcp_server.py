#!/usr/bin/env python3

import os
import re
import json
import time
import hashlib
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP  # Official MCP Python SDK

# ---------- ANSI Colors ----------

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_info(msg: str) -> None:
    """Print info message with [*] prefix"""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")

def print_success(msg: str) -> None:
    """Print success message with [+] prefix"""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")

def print_warning(msg: str) -> None:
    """Print warning message with [!] prefix"""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def print_error(msg: str) -> None:
    """Print error message with [x] prefix"""
    print(f"{Colors.RED}[x]{Colors.RESET} {msg}")

def print_banner() -> None:
    """Print the linWinPwn MCP server banner"""
    # ASCII art with escaped backslashes
    ascii_art = r"""
       _        __        ___       ____                  
      | |(_)_ __\ \      / (_)_ __ |  _ \__      ___ __   
      | || | '_  \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \  
      | || | | | |\ V  V / | | | | |  __/ \ V  V /| | | | 
      |_||_|_| |_| \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_| MCP Server
"""
    
    print(ascii_art)
    
    # Then print colored information
    print(f"      {Colors.BLUE}linWinPwn MCP Server: {Colors.CYAN}version 0.1{Colors.RESET}")
    print("      https://github.com/lefayjey/linWinPwn")
    print(f"      {Colors.BLUE}Author: {Colors.CYAN}lefayjey{Colors.RESET}")
    print(f"      {Colors.BLUE}MCP Adaptation: {Colors.CYAN}HTTP Streamable Server{Colors.RESET}")
    print()


# ---------- Config (server/network) ----------

MCP_HOST = os.getenv("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))
MCP_PATH = os.getenv("MCP_PATH", "/mcp")

LOGS_SUBDIR_NAME = "logs"  # All run artifacts go under <output_root>/logs

# ---------- Helpers ----------

def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def extract_tools_section(content: str) -> str:
    """Extract only the Tools section between specific markers."""
    start_pattern = r"^#\s*-{5,}\s*Tools\s*-{5,}\s*$"
    end_pattern = r"^#\s*-{5,}\s*Menu\s*-{5,}\s*$"
    
    start_match = re.search(start_pattern, content, re.MULTILINE)
    if not start_match:
        return ""
    
    start_pos = start_match.end()
    end_match = re.search(end_pattern, content[start_pos:], re.MULTILINE)
    
    if end_match:
        end_pos = start_pos + end_match.start()
        return content[start_pos:end_pos]
    
    return content[start_pos:]

def extract_run_commands_with_functions(content: str) -> List[Dict[str, Any]]:
    """Extract run_command calls and their containing function names."""
    tools_section = extract_tools_section(content)
    if not tools_section:
        print_warning("Could not find Tools section. Searching entire file...")
        tools_section = content
    
    # Find all functions with their bodies
    function_pattern = re.compile(
        r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)\s*\{(.*?)^\}",
        re.MULTILINE | re.DOTALL
    )
    
    seen = set()
    cmds: List[Dict[str, Any]] = []
    idx = 0
    
    for func_match in function_pattern.finditer(tools_section):
        func_name = func_match.group(1)
        func_body = func_match.group(2)
        
        # Find run_command calls within this function
        cmd_pattern = re.compile(r"""run_command\s+((["'])(?:\\.|[^\\])*?\2)""", re.DOTALL)
        
        for cmd_match in cmd_pattern.finditer(func_body):
            raw_quoted = cmd_match.group(1)
            
            if not raw_quoted: continue
            
            q = raw_quoted.strip()
            if (q.startswith('"') and q.endswith('"')) or (q.startswith("'") and q.endswith("'")):
                q = q[1:-1]
            
            # Clean up the command
            raw = re.sub(r"\\\n", " ", q)
            raw = re.sub(r"\s+", " ", raw).strip()
            
            if not raw:
                continue
            
            hid = _sha1(raw)
            if hid in seen:
                continue
            
            seen.add(hid)
            
            cmds.append({
                "id": hid,
                "raw": raw,
                "label": func_name,  # Use function name as label
                "index": idx
            })
            idx += 1
    
    return cmds

def expand_vars(cmd: str, env: Dict[str, str]) -> str:
    def repl_braced(m):
        var = m.group(1)
        return env.get(var, "")
    def repl_unbraced(m):
        var = m.group(1)
        return env.get(var, "")
    cmd = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", repl_braced, cmd)
    cmd = re.sub(r"(?<!\$)\$([A-Za-z_][A-Za-z0-9_]*)", repl_unbraced, cmd)
    return cmd

def run_shell(command: str, cwd: Optional[str] = None, timeout_sec: Optional[int] = None) -> Dict[str, Any]:
    try:
        cp = subprocess.run(
            ["bash", "-lc", command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_sec if timeout_sec and timeout_sec > 0 else None,
        )
        return {"exitCode": cp.returncode, "stdout": cp.stdout, "stderr": cp.stderr}
    except subprocess.TimeoutExpired as e:
        return {"exitCode": None, "stdout": e.stdout or "", "stderr": f"Timeout after {timeout_sec}s"}
    except Exception as e:
        return {"exitCode": 1, "stdout": "", "stderr": str(e)}

# ---------- Resolve tool variables from linWinPwn ----------

def extract_tools_block(content: str) -> str:
    start = None
    for m in re.finditer(r"^\s*#\s*Tools\s+variables\s*$", content, re.IGNORECASE | re.MULTILINE):
        start = m.end()
        break
    if start is None:
        return ""
    end_match = re.search(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{", content[start:], re.MULTILINE)
    if end_match:
        end = start + end_match.start()
    else:
        hdr = re.search(r"^\s*#\s*[A-Z][^\n]*$", content[start:], re.MULTILINE)
        end = start + hdr.start() if hdr else len(content)
    return content[start:end].strip()

def extract_default_vars_block(content: str) -> str:
    m_start = re.search(r"^\s*#\s*Default variables\s*$", content, re.MULTILINE)
    if not m_start:
        return ""
    start = m_start.end()
    m_end = re.search(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{|^\s*#\s*[A-Z][^\n]*$", content[start:], re.MULTILINE)
    end = start + m_end.start() if m_end else len(content)
    return content[start:end].strip()

def extract_assigned_vars(block: str) -> List[str]:
    names = set()
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
        if m:
            names.add(m.group(1))
    return sorted(names)

def resolve_block_vars(block: str) -> Dict[str, str]:
    if not block:
        return {}
    var_names = extract_assigned_vars(block)
    if not var_names:
        return {}
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(block + "\n")
        tmp_path = tf.name
    try:
        shell_code = (
            f"bash -lc 'set +e; source {tmp_path}; "
            + "for v in " + " ".join(repr(v) for v in var_names) + "; do "
            + "printf \"%s=%s\\n\" \"$v\" \"${!v}\"; "
            + "done'"
        )
        cp = subprocess.run(shell_code, shell=True, capture_output=True, text=True)
        defaults: Dict[str, str] = {}
        for line in cp.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                v = v.strip()
                if v:
                    defaults[k] = v
        return defaults
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

def derive_attacker_ip(interface: str) -> Optional[str]:
    try:
        cmd = f"ip -f inet addr show {interface} 2>/dev/null | sed -En -e 's/.*inet ([0-9.]+).*/\\1/p'"
        cp = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=3)
        v = cp.stdout.strip()
        return v or None
    except Exception:
        return None

# ---------- Load script and build catalogs/defaults ----------

LWP_PATH = os.getenv("LWP_PATH", "./linWinPwn.sh")
try:
    with open(LWP_PATH, "r", encoding="utf-8", errors="ignore") as f:
        _content = f.read()
except FileNotFoundError:
    print_error(f"linWinPwn script not found at {LWP_PATH} (set LWP_PATH)")
    raise SystemExit(1)

print_info(f"Loading linWinPwn from: {LWP_PATH}")
CATALOG: List[Dict[str, Any]] = extract_run_commands_with_functions(_content)
print_success(f"Extracted {len(CATALOG)} commands from Tools section")

TOOLS_BLOCK: str = extract_tools_block(_content)
DEFAULTS_BLOCK: str = extract_default_vars_block(_content)

TOOLS_DEFAULTS: Dict[str, str] = resolve_block_vars(TOOLS_BLOCK)
BASE_DEFAULTS: Dict[str, str] = resolve_block_vars(DEFAULTS_BLOCK)

# ---------- Output root: local ./lwp_output by default, or LWP_OUTPUT override ----------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_ROOT = os.getenv("LWP_OUTPUT", os.path.join(SCRIPT_DIR, "lwp_output")).strip()
os.makedirs(OUTPUT_ROOT, exist_ok=True)
LOGS_DIR = os.path.join(OUTPUT_ROOT, LOGS_SUBDIR_NAME)
os.makedirs(LOGS_DIR, exist_ok=True)

print_info(f"Output directory: {OUTPUT_ROOT}")
print_info(f"Logs directory: {LOGS_DIR}")

# ---------- MCP Server ----------

mcp = FastMCP(
    name="linwinpwn-http",
    stateless_http=True,
)

try:
    mcp.settings.host = MCP_HOST
    mcp.settings.port = MCP_PORT
    mcp.settings.path = MCP_PATH
except Exception:
    pass

@mcp.tool("lwp_list")
def lwp_list(filter: Optional[str] = None) -> Dict[str, Any]:
    """List available linWinPwn commands with optional filtering.
    
    Args:
        filter: Optional search term to filter commands by function name or command content
        
    Returns:
        Dictionary with count and list of matching commands
    """
    f = (filter or "").lower()
    items = []
    for c in CATALOG:
        if not f or f in c["raw"].lower() or f in c["label"].lower():
            preview = c["raw"][:180] + ("…" if len(c["raw"]) > 180 else "")
            items.append({
                "id": c["id"],
                "index": c["index"],
                "function": c["label"],
                "preview": preview,
            })
    
    return {
        "count": len(items),
        "total_available": len(CATALOG),
        "items": items
    }

@mcp.tool("lwp_vars")
def lwp_vars() -> Dict[str, Any]:
    """Get current environment variables and server configuration.
    
    Returns:
        Dictionary with tools, defaults, server settings, and paths
    """
    return {
        "tools": TOOLS_DEFAULTS,
        "defaults": BASE_DEFAULTS,
        "server": {
            "host": MCP_HOST,
            "port": MCP_PORT,
            "path": MCP_PATH
        },
        "paths": {
            "output_dir": OUTPUT_ROOT,
            "logs_dir": LOGS_DIR,
        },
    }

@mcp.tool("lwp_help")
def lwp_help(topic: Optional[str] = None) -> Dict[str, Any]:
    """Get help information about linWinPwn MCP server tools and usage.
    
    Args:
        topic: Optional topic for specific help (options: "tools", "vars", "run", "examples")
        
    Returns:
        Help documentation and usage examples
    """
    if topic == "tools":
        return {
            "tool": "lwp_list",
            "description": "Lists all available linWinPwn commands extracted from the Tools section",
            "usage": "lwp_list(filter='dns') - Filter commands by keyword",
            "parameters": {
                "filter": "(optional) Search term to filter by function name or command content"
            },
            "returns": "Dictionary with count and list of commands with their function names",
            "example_output": {
                "count": 2,
                "total_available": 45,
                "items": [
                    {
                        "id": "abc123...",
                        "index": 5,
                        "function": "dns_enum",
                        "preview": "adidnsdump -u \"$domain\\$user\" -p \"$pass\"..."
                    }
                ]
            }
        }
    
    elif topic == "vars":
        return {
            "tool": "lwp_vars",
            "description": "Shows current environment variables and configuration",
            "usage": "lwp_vars() - No parameters needed",
            "returns": "Dictionary containing tools defaults, base defaults, server config, and paths",
            "example_output": {
                "tools": {"impacket_dir": "/opt/impacket"},
                "defaults": {"domain": "", "user": ""},
                "server": {"host": "127.0.0.1", "port": 8000},
                "paths": {"output_dir": "./lwp_output", "logs_dir": "./lwp_output/logs"}
            }
        }
    
    elif topic == "run":
        return {
            "tool": "lwp_run",
            "description": "Executes a linWinPwn command by its ID",
            "usage": "lwp_run(id='abc123...', env={'domain': 'test.local'}, dryRun=True)",
            "parameters": {
                "id": "(required) Command ID from lwp_list",
                "env": "(optional) Dict of environment variables to override",
                "cwd": "(optional) Working directory for execution",
                "dryRun": "(optional) If True, shows command without executing",
                "timeoutSec": "(optional) Timeout in seconds",
                "outputDir": "(optional) Override default output directory",
                "interface": "(optional) Network interface (sets attacker_interface and derives attacker_IP)",
                "ldapPort": "(optional) Override LDAP port"
            },
            "returns": "Execution results including exit code, stdout/stderr, duration, and file paths",
            "workflow": [
                "1. Use lwp_list() to find available commands",
                "2. Copy the 'id' from desired command",
                "3. Test with dryRun=True to see expanded command",
                "4. Execute with lwp_run(id='...', env={...})"
            ],
            "example": {
                "step1": "result = lwp_list(filter='enum')",
                "step2": "command_id = result['items'][0]['id']",
                "step3": "lwp_run(id=command_id, dryRun=True)",
                "step4": "lwp_run(id=command_id, env={'domain': 'corp.local', 'user': 'admin'})"
            }
        }
    
    elif topic == "examples":
        return {
            "common_workflows": {
                "1. List and filter commands": {
                    "description": "Find specific tools by keyword",
                    "code": "lwp_list(filter='bloodhound')"
                },
                "2. Check configuration": {
                    "description": "View current environment and paths",
                    "code": "lwp_vars()"
                },
                "3. Dry run before execution": {
                    "description": "Preview command expansion without executing",
                    "code": "lwp_run(id='command_id', dryRun=True, env={'domain': 'test.local'})"
                },
                "4. Execute with custom environment": {
                    "description": "Run command with specific variables",
                    "code": "lwp_run(id='command_id', env={'domain': 'corp.local', 'user': 'admin', 'pass': 'password'})"
                },
                "5. Execute with timeout": {
                    "description": "Prevent long-running commands from hanging",
                    "code": "lwp_run(id='command_id', timeoutSec=300)"
                },
                "6. Use custom network interface": {
                    "description": "Automatically derive attacker IP from interface",
                    "code": "lwp_run(id='command_id', interface='tun0')"
                }
            },
            "tips": [
                "Always use dryRun=True first to verify command expansion",
                "Check lwp_vars() to see available default variables",
                "Use filter in lwp_list() to quickly find relevant functions",
                "Output files are saved in logs/ subdirectory with function name and timestamp",
                "Commands are extracted only from the Tools section of linWinPwn.sh"
            ]
        }
    
    # Default: general overview
    return {
        "linWinPwn MCP Server": {
            "version": "1.0",
            "description": "HTTP MCP server for executing linWinPwn pentesting commands",
            "source": f"Loaded from: {LWP_PATH}",
            "commands_available": len(CATALOG),
            "output_directory": OUTPUT_ROOT,
            "logs_directory": LOGS_DIR
        },
        "available_tools": {
            "lwp_list": "List all available linWinPwn commands with filtering",
            "lwp_vars": "Show environment variables and configuration",
            "lwp_run": "Execute a command by ID",
            "lwp_help": "Display help information (you are here!)"
        },
        "quick_start": [
            "1. List commands: lwp_list()",
            "2. Find specific tool: lwp_list(filter='bloodhound')",
            "3. Test command: lwp_run(id='...', dryRun=True)",
            "4. Execute: lwp_run(id='...', env={'domain': 'test.local'})"
        ],
        "get_detailed_help": {
            "tools": "lwp_help(topic='tools') - Details about lwp_list",
            "vars": "lwp_help(topic='vars') - Details about lwp_vars",
            "run": "lwp_help(topic='run') - Details about lwp_run",
            "examples": "lwp_help(topic='examples') - Common workflows and tips"
        },
        "server_info": {
            "host": MCP_HOST,
            "port": MCP_PORT,
            "path": MCP_PATH,
            "transport": "streamable-http"
        },
        "environment_variables": {
            "LWP_PATH": "Path to linWinPwn.sh script",
            "LWP_OUTPUT": "Override default output directory",
            "MCP_HOST": "Server host address",
            "MCP_PORT": "Server port",
            "MCP_PATH": "MCP endpoint path"
        }
    }

@mcp.tool("lwp_run")
def lwp_run(
    id: str,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    dryRun: bool = False,
    timeoutSec: Optional[int] = None,
    outputDir: Optional[str] = None,
    interface: Optional[str] = None,
    ldapPort: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a linWinPwn command by ID.
    
    Args:
        id: Command ID from lwp_list
        env: Additional environment variables to override
        cwd: Working directory for command execution
        dryRun: If True, show command without executing
        timeoutSec: Timeout in seconds (None for no timeout)
        outputDir: Override output directory
        interface: Network interface for attacker_interface variable
        ldapPort: LDAP port override
        
    Returns:
        Execution results including exit code, output, and paths
    """
    entry = next((c for c in CATALOG if c["id"] == id), None)
    if not entry:
        return {
            "id": id,
            "error": "Unknown command ID",
            "exitCode": None
        }

    # Merge environment variables
    merged_env = dict(BASE_DEFAULTS)
    merged_env.update(TOOLS_DEFAULTS)
    if env:
        merged_env.update(env)

    # Resolve output_dir from per-run override or default root
    resolved_output = outputDir or OUTPUT_ROOT
    os.makedirs(resolved_output, exist_ok=True)
    merged_env["output_dir"] = resolved_output

    logs_dir = os.path.join(resolved_output, LOGS_SUBDIR_NAME)
    os.makedirs(logs_dir, exist_ok=True)

    if interface:
        merged_env["attacker_interface"] = interface
        if not merged_env.get("attacker_IP"):
            ip_guess = derive_attacker_ip(interface)
            if ip_guess:
                merged_env["attacker_IP"] = ip_guess

    if ldapPort:
        merged_env["ldap_port"] = ldapPort

    expanded = expand_vars(entry["raw"], merged_env)

    started = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()

    if dryRun:
        return {
            "id": id,
            "function": entry["label"],
            "command": expanded,
            "startedAt": started,
            "dryRun": True,
            "envKeys": sorted(list(merged_env.keys())),
            "paths": {
                "output_dir": resolved_output,
                "logs_dir": logs_dir
            },
        }

    print(f"\n{Colors.CYAN}[*]{Colors.RESET} Executing function: {Colors.BOLD}{entry['label']}{Colors.RESET}")
    print(f"{Colors.BLUE}[*]{Colors.RESET} Command: {expanded[:100]}{'...' if len(expanded) > 100 else ''}")
    
    result = run_shell(expanded, cwd=cwd, timeout_sec=timeoutSec)
    duration_ms = int((time.perf_counter() - t0) * 1000)
    finished = datetime.now(timezone.utc).isoformat()

    # Save outputs to files
    stdout_path = None
    stderr_path = None
    try:
        base = f"lwp_{entry['label']}_{int(time.time())}"
        stdout_path = os.path.join(logs_dir, f"{base}.out.txt")
        stderr_path = os.path.join(logs_dir, f"{base}.err.txt")
        
        if result.get("stdout"):
            with open(stdout_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(result["stdout"])
        if result.get("stderr"):
            with open(stderr_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(result["stderr"])
    except Exception as e:
        print_warning(f"Could not save output files: {e}")

    success = result.get("exitCode") == 0
    if success:
        print_success(f"Completed in {duration_ms}ms (exit code: {result.get('exitCode')})")
    else:
        print_error(f"Failed in {duration_ms}ms (exit code: {result.get('exitCode')})")

    return {
        "id": id,
        "function": entry["label"],
        "ok": success,
        "exitCode": result.get("exitCode"),
        "command": expanded,
        "cwd": cwd,
        "startedAt": started,
        "finishedAt": finished,
        "durationMs": duration_ms,
        "stdoutBytes": len(result.get("stdout") or ""),
        "stderrBytes": len(result.get("stderr") or ""),
        "stdoutPreview": (result.get("stdout") or "")[:5000],
        "stderrPreview": (result.get("stderr") or "")[:5000],
        "paths": {
            "output_dir": resolved_output,
            "logs_dir": logs_dir,
            "stdoutPath": stdout_path,
            "stderrPath": stderr_path,
        },
        "envUsed": {
            "attacker_interface": merged_env.get("attacker_interface"),
            "attacker_IP": merged_env.get("attacker_IP"),
            "ldap_port": merged_env.get("ldap_port"),
        },
    }

if __name__ == "__main__":
    print_banner()
    print(f"\n{Colors.CYAN}[*]{Colors.RESET} Starting MCP server at http://{MCP_HOST}:{MCP_PORT}{MCP_PATH}")
    print(f"{Colors.BLUE}[*]{Colors.RESET} Tools available: {len(CATALOG)}")
    print("=" * 60)
    mcp.run(transport="streamable-http")
