#!/usr/bin/env python3
"""
MCP server to parse user intent and run generate_all_stats.py locally.

Endpoints (MCP messages):
- "run_intent" : Accepts either a free-form command string or a structured JSON payload.
    Example structured payloads:
    {
        "mode": "steady",                # or "anomaly"
        "topology": "topology.csv",      # optional, default topology.csv
        "assurance": "assurance.csv",    # optional
        "bgp": "bgp.csv",                # optional
        "tunnel": "tunnel.csv",          # optional
        "anomaly": {"cpuspike": ["nylf01"]}  # only for anomaly. Must be JSON-serializable
    }

- "stop_run" : (optional) attempt to kill a running process started by this server by id.
"""

import json
import shlex
import subprocess
import logging
import os
import uuid
import threading
import signal
from typing import Dict, Any, Optional
from ast import literal_eval

# If you have FastMCP installed use it; otherwise this import will fail.
# The user already used FastMCP in previous convo; if you prefer Flask/HTTP we can switch.
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_exec_server")

# Path to the script to execute (assumed present locally & executable with python)
SCRIPT_DIR = os.environ.get("SCRIPT_DIR", "/root/s2-observability-simulator/")
SCRIPT = os.environ.get("GEN_STATS_SCRIPT", "generate_all_stats.py")
PYTHON_BIN = os.environ.get("PYTHON_BIN", "/root/mcp-sim/.venv/bin/python3")  # allow override e.g. to virtualenv python

# Allowed anomaly action keys (from examples)
ALLOWED_ANOMALY_KEYS = {"trafficprofile", "cpuspike", "memspike", "assurance", "bgpdown", "bgpflap", "tundown", "tunflap", "linkdown", "nodedown","configcommit", "intindisc", "intoutdisc", "intinerr", "intouterr", "intflap"}

# Running processes registry (simple in-memory)
RUNNING_PROCS: Dict[str, subprocess.Popen] = {}

def safe_filename(name: Optional[str]) -> Optional[str]:
    """Allow only simple filenames without path traversal. Return None if invalid or not provided."""
    if not name:
        return None
    # Disallow path separators to avoid directory traversal
    if "/" in name or "\\" in name:
        raise ValueError("Filenames must not contain path separators.")
    # Basic allowed characters: letters, digits, -, _, ., comma allowed
    # Keep simple check
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.csv")
    if not set(name) <= allowed:
        raise ValueError("Filename contains disallowed characters.")
    return name

def parse_anomaly_payload(raw: Any) -> Dict[str, Any]:
    """
    Accept either a dict, or a string containing a dict (single quotes or double quotes).
    Validate keys.
    """
    if raw is None:
        raise ValueError("Anomaly payload required for anomaly mode.")
    if isinstance(raw, dict):
        payload = raw
    elif isinstance(raw, str):
        # allow both JSON and Python dict string (single quotes)
        try:
            payload = json.loads(raw)
        except Exception:
            # fallback to ast.literal_eval to handle single quotes like "{'cpuspike':['nylf01']}"
            try:
                payload = literal_eval(raw)
            except Exception as e:
                raise ValueError(f"Could not parse anomaly payload: {e}")
    else:
        raise ValueError("Unsupported anomaly payload type.")

    if not isinstance(payload, dict):
        raise ValueError("Anomaly payload must be an object/dict.")

    # validate keys
    for k in payload.keys():
        if k not in ALLOWED_ANOMALY_KEYS:
            raise ValueError(f"Anomaly key '{k}' not allowed. Allowed: {sorted(ALLOWED_ANOMALY_KEYS)}")
    return payload

def build_cmd_from_intent(intent: Dict[str, Any]) -> list:
    """
    Build the subprocess command list for subprocess.run based on provided intent dict.
    Returns command list (e.g. ["python3", "generate_all_stats.py", "-t", "topology.csv", ...])
    """
    mode = intent.get("mode")
    if not mode or mode not in ("steady", "anomaly"):
        raise ValueError("mode must be 'steady' or 'anomaly'")

    topology = safe_filename(intent.get("topology") or "topology.csv")
    cmd = [PYTHON_BIN, SCRIPT, "-t", topology, "-a", "steadystate" if mode == "steady" else "anomaly"]

    # For steady state: allow assurance and bgp
    if mode == "steady":
        assurance = safe_filename(intent.get("assurance"))
        if assurance:
            cmd.extend(["-s", assurance])
        bgp = safe_filename(intent.get("bgp"))
        if bgp:
            cmd.extend(["-b", bgp])
        tunnel = safe_filename(intent.get("tunnel"))
        if tunnel:
            cmd.extend(["-tu", tunnel])
        return cmd

    # For anomaly: require -av payload and optional assurance/bgp/tunnel flags depending on payload
    anomaly_raw = intent.get("anomaly")
    anomaly_payload = parse_anomaly_payload(anomaly_raw)

    # Optional assurance/bgp/tunnel files
    assurance = safe_filename(intent.get("assurance"))
    if assurance:
        cmd.extend(["-s", assurance])
    bgp = safe_filename(intent.get("bgp"))
    if bgp:
        cmd.extend(["-b", bgp])
    tunnel = safe_filename(intent.get("tunnel"))
    if tunnel:
        cmd.extend(["-tu", tunnel])

    # produce the -av argument as a single-quoted JSON-string-like arg (example uses single quotes)
    # We'll construct JSON and then wrap in single quotes so it matches your examples.
    av_json = json.dumps(anomaly_payload)
    # The CLI examples used single quotes around the dict; shell will treat them literally.
    # We'll pass the value as a single string argument. No extra shell quoting because we use list form.
    cmd.extend(["-av", av_json])
    logger.info("Final CMD built: %s", " ".join(cmd))
    return cmd

def run_command_blocking(cmd: list, timeout: Optional[int] = None) -> Dict[str, Any]:
    """
    Run the command synchronously (blocking), capture output and return status.
    Use subprocess.run for safety (no shell).
    """
    logger.info("Running command: %s", " ".join(shlex.quote(p) for p in cmd))
    try:
        completed = subprocess.run(cmd, cwd=SCRIPT_DIR, capture_output=True, text=True, check=False, timeout=timeout)
        result = {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        logger.info("Command finished with returncode %s", completed.returncode)
        return result
    except subprocess.TimeoutExpired as e:
        logger.error("Command timed out: %s", e)
        return {"error": "timeout", "stdout": e.stdout, "stderr": e.stderr}
    except Exception as e:
        logger.exception("Failed to run command")
        return {"error": str(e)}


def _monitor_process(proc_id: str, proc: subprocess.Popen):
    """Background thread that waits for process completion and updates status."""
    try:
        stdout, stderr = proc.communicate()
        RUNNING_PROCS[proc_id].update({
            "status": "finished",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        })
        logger.info("Process %s finished with returncode %s", proc_id, proc.returncode)
    except Exception as e:
        RUNNING_PROCS[proc_id].update({
            "status": "error",
            "error": str(e)
        })
        logger.error("Process %s monitor failed: %s", proc_id, e)


def spawn_command_nonblocking(cmd: list) -> Dict[str, Any]:
    """
    Spawn command as background process and return immediately.
    A background thread will monitor it and update status.
    """
    logger.info("Spawning background command: %s", " ".join(shlex.quote(p) for p in cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=SCRIPT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        preexec_fn=os.setpgrp, 
        env=os.environ.copy()
    )

    proc_id = str(uuid.uuid4())
    RUNNING_PROCS[proc_id] = {
        "proc": proc,
        "pid": proc.pid,
        "cmd": cmd,
        "status": "running",
    }

    # Start background watcher thread
    threading.Thread(target=_monitor_process, args=(proc_id, proc), daemon=True).start()

    logger.info("Spawned process %s pid=%s", proc_id, proc.pid)
    return {"proc_id": proc_id, "pid": proc.pid}

def stop_proc(proc_id: str, force: bool = False) -> Dict[str, Any]:
    entry = RUNNING_PROCS.get(proc_id)
    if not entry:
        return {"error": "not_found", "message": f"proc_id {proc_id} not tracked"}

    proc = entry["proc"]
    if entry["status"] not in ("running",):
        return {"error": "not_running", "message": f"Process {proc_id} already finished or stopped."}

    logger.info("Stopping process %s (pid=%s) %s", proc_id, proc.pid, "(force)" if force else "")
    try:
        sig = signal.SIGKILL if force else signal.SIGTERM
        os.killpg(os.getpgid(proc.pid), sig)
        entry["status"] = "terminated"
        return {"proc_id": proc_id, "stopped": True, "signal": "SIGKILL" if force else "SIGTERM"}
    except ProcessLookupError:
        entry["status"] = "not_found"
        return {"proc_id": proc_id, "stopped": False, "error": "process not found"}
    except Exception as e:
        logger.error("Failed to stop process %s: %s", proc_id, e)
        return {"proc_id": proc_id, "stopped": False, "error": str(e)}


# ---------------------------
# MCP server / handlers
# ---------------------------

mcp = FastMCP(name="generate-stats-runner", host="0.0.0.0", port=8050)

# Handler to run intent synchronously and return result
@mcp.tool("simulator_intent", description="do not include the words python generate_stats.py words in arguments. Only pass arguments. Anomalies are in format {'cpuspike':[devices]}, {'memspike':[devices]}, {'trafficprofile':['device_interface_50-5-2']}, {'bgpflap':['device_interface']}, {'tunflap':['device_interface']}, {'bgpdown':['device_interface']}, {'linkdown':['device_itnerface']}, {'nodedown': [devices]}, intinerr, intouterr, intindisc, intoutdisc all follow {type: ['device_interface']}")
def handle_run_intent(ctx, payload: dict):
    print(50*"=")
    print(payload)
    print(50*"=")
    """
    MCP server to parse user intent and run `generate_all_stats.py` locally.

    ---
    ## Overview

    This MCP server provides endpoints to generate **steady-state** and **anomaly** network metrics
    based on topology files. It wraps the local `generate_all_stats.py` tool used in the S2 Observability Simulator.

    when referred to as input files , consider it for keys topology, bgp , tunnel, assurance and mode
    ### Workflow Summary

    **Step 1: Provide a topology file**
    - The topology (e.g. `topology.csv`) defines devices, links, and attributes.

    **Step 2: Generate steady-state metrics**
    - Generate baseline observability metrics from the topology:
        ```
        python generate_all_stats.py -t topology.csv -a steadystate
        ```
    - To add *assurance metrics*:
        ```
        python generate_all_stats.py -t topology.csv -a steadystate -s assurance.csv
        ```
        - Schema: `device,endpoint,latency,loss,jitter`
        - Example:
            ```
            nyfw01,aws,10,0,0
            nyag01,az,10,0,0
            ```
    - To add *BGP metrics*:
        ```
        python generate_all_stats.py -t topology.csv -a steadystate -s assurance.csv -b bgp.csv
        ```
        - Schema: `type,a_device,z_device,local_as,remote_as,interface,provider`
        - Example:
            ```
            E,nyfw01,nype01,1000,2000,et-0/0/2,zayo
            E,nyfw01,nype02,1000,3000,et-0/0/3,level3
            ```

    **Step 3: Inject anomalies**
    - Anomalies modify metrics to simulate network issues or behavior changes.

    ### Supported anomaly types (key → meaning)
    | Key              | Description / Example Usage |
    |------------------|-----------------------------|
    | `trafficprofile` | Modify traffic on a given interface.<br>Example: `{'trafficprofile': ['nylf01_et-0/0/0_50-2-2']}` |
    | `linkdown`       | Mark one or more links down.<br>Example: `{'linkdown': ['nylf01_et-0/0/0', 'nylf02_et-0/0/1']}` |
    | `nodedown`       | Mark one or more nodes down.<br>Example: `{'nodedown': ['nylf01', 'nyag01']}` |
    | `intflap`        | Enable interface flapping.<br>Example: `{'intflap': ['nylf01_et-0/0/0']}` |
    | `intindisc`      | Introduce interface input discards or errors.<br>Example: `{'intindisc': ['nylf01_et-0/0/0']}` |
    | `cpuspike`       | Simulate CPU utilization spike on given nodes.<br>Example: `{'cpuspike': ['nylf01']}` |
    | `memspike`       | Simulate memory spike on given nodes.<br>Example: `{'memspike': ['nylf01']}` |
    | `assurance`      | Inject anomalies into assurance metrics.<br>Example: `{'assurance': ['nylf01']}` |
    | `bgpflap`        | Simulate BGP session flap events.<br>Example: `{'bgpflap': ['nylf01']}` |
    | `tundown`        | Mark a tunnel as down.<br>Example: `{'tundown': ['tun01']}` |
    | `tunflap`        | Simulate tunnel flapping.<br>Example: `{'tunflap': ['tun01']}` |

    ### Example anomaly run

    python generate_all_stats.py -t topology.csv -a anomaly -av "{'cpuspike': ['nylf01']}"


    ---
    ### MCP Endpoints

    - `"simulator_intent"` — Accepts structured or free-form commands to invoke the simulator.
    - `"simulator_stop_run"` — Kills a background simulation run.
    - `"simulator_status"` — Reports currently running background jobs.

    Structured JSON example:
    ```json
    {
        "mode": "anomaly",
        "topology": "topology.csv",
        "assurance": "assurance.csv",
        "bgp": "bgp.csv",
        "anomaly": {"cpuspike": ["nylf01"]}
    }
    ```

    The anomalies always will have to be converted to a string such as "{'cpuspike':['nylf01'], 'memspike':['nylf01']}"
    """
    # Support a raw command string for convenience
    if "command" in payload:
        # parse command string but enforce that it invokes our script
        cmd_string = payload["command"]
        # tokenise safely
        parts = shlex.split(cmd_string)
        # Basic validation: must start with python and script name
        if len(parts) < 2 or not parts[1].endswith(os.path.basename(SCRIPT)):
            raise ValueError("Provided command must call the local script: " + SCRIPT)
        cmd = parts
    else:
        # structured payload
        intent = {
            "mode": payload.get("mode"),
            "topology": payload.get("topology") or payload.get("topology_file") or payload.get("topology_config_file"),
            "assurance": payload.get("assurance") or payload.get("assurance_config") or payload.get("assurance_config_file"),
            "bgp": payload.get("bgp") or payload.get("bgp_config") or payload.get("bgp_config_file"),
            "tunnel": payload.get("tunnel") or payload.get("tunnel_config") or payload.get("tunnel_config_file"),
            "anomaly": payload.get("anomaly") or payload.get("anomaly_config") or payload.get("anomalies"),
        }
        cmd = build_cmd_from_intent(intent)

    # background or blocking
    background = bool(payload.get("background", False))
    if payload.get("mode") in ("steady", "anomaly"):
        background = True
    if background:
        spawn_info = spawn_command_nonblocking(cmd)
        return {"status": "spawned", **spawn_info}

    # blocking run
    timeout = payload.get("timeout")  # seconds or None
    result = run_command_blocking(cmd, timeout=timeout)
    return {"status": "done", "cmd": cmd, **result}

# Optional endpoint to stop a background run
@mcp.tool("simulator_stop_run")
def handle_stop(ctx, payload: dict):
    proc_id = payload.get("proc_id")
    if not proc_id:
        return {"error": "proc_id required"}
    try:
        res = stop_proc(proc_id)
        return {"status": "stopped", **res}
    except Exception as e:
        return {"error": str(e)}

# Provide a small "ping" handler and a listing of running procs
@mcp.tool("simulator_status")
def handle_status(ctx, payload: dict):
    """Return all tracked processes and their current states."""
    status_list = []
    for proc_id, info in RUNNING_PROCS.items():
        status_list.append({
            "proc_id": proc_id,
            "pid": info["pid"],
            "status": info.get("status"),
            "returncode": info.get("returncode"),
            "cmd": " ".join(info["cmd"]),
        })
    return {"ok": True, "running": status_list}

if __name__ == "__main__":
    # If you want to use a virtualenv python, set PYTHON_BIN env var (e.g. /path/to/venv/bin/python)
    print("Starting MCP server - generate_all_stats runner")
    print("SCRIPT:", SCRIPT, "PYTHON_BIN:", PYTHON_BIN)
    # Choose transport "http" or "ws" if you like; default shown below:
    mcp.run(transport="streamable-http")

