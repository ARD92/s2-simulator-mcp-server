# S2 Simulator MCP Server

## Overview

This project implements an MCP (Multi-Cloud Platform) server designed to interact with and control the S2 Observability Simulator. It allows users to generate network observability metrics in either a steady-state (baseline) mode or an anomaly-injection mode, simulating various network issues. Ensure you have all necessary files before you run this.

## Features

*   **Steady-State Simulation**: Generate baseline network observability metrics.
*   **Anomaly Injection**: Simulate various network issues like CPU spikes, memory spikes, link downs, BGP flaps, and more.
*   **Flexible Input**: Accept intent through structured JSON payloads or free-form command strings.
*   **Background Processing**: Run simulations as background processes, allowing for non-blocking operations.
*   **Session Management**: Stop and monitor running simulation sessions.

## Installation

1.  **Clone the repository** (if you haven't already). and https://github.com/ARD92/s2-observability-simulator.git which is the simulator tool. 
2.  **Install dependencies**: The server relies on `mcp` and `python-dotenv`.

    ```bash
    pip install -r requirements.txt
    ```
3.  **Ensure `generate_all_stats.py` is available**: This server expects the `generate_all_stats.py` script to be located in the directory specified by `SCRIPT_DIR` (default: `/root/s2-observability-simulator/`). You may need to adjust the `SCRIPT_DIR` and `PYTHON_BIN` environment variables if your setup differs. Clone https://github.com/ARD92/s2-observability-simulator.git to obtain the tool

## Usage

### MCP server config
```
{
  "mcpServers": {
    "simulator": {
        "command": "npx",
        "args": [
        "mcp-remote",
        "http://192.168.1.10:8050/mcp/",
        "--allow-http"
        ]
    }
  }
}
```

The MCP server exposes the following tools:

*   `simulator_intent`: To start a new simulation.
*   `simulator_stop_run`: To stop a running background simulation.
*   `simulator_status`: To list all tracked simulation processes and their statuses.

### Starting the MCP Server

To start the MCP server, run `main.py`:

```bash
python main.py
```

### Running Simulations

Simulations can be initiated using the `simulator_intent` tool. You can provide a structured JSON payload or freeform text and allow the llm to interpret.

#### Steady-State Mode

To generate steady-state metrics with a topology file and optional assurance/BGP files:

```json
{
    "mode": "steady",
    "topology": "topology.csv",
    "assurance": "assurance.csv",
    "bgp": "bgp.csv",
    "tunnel": "tunnel.csv"
}
```

#### Anomaly Mode

To inject anomalies, set the `mode` to "anomaly" and provide the `anomaly` payload:

```json
{
    "mode": "anomaly",
    "topology": "topology.csv",
    "assurance": "assurance.csv",
    "bgp": "bgp.csv",
    "anomaly": {"cpuspike": ["nylf01"], "memspike": ["nyag01"], "linkdown": ["nylf01_et-0/0/0"]}
}
```

```
use simulator tool with topology=mcp-topology.csv, bgp = mcp-bgp_config.csv, mode=anomaly, anamoly cpuspike for CASPJNP01, memspike for device CASPJNP02, linkdown on CALFJNP02 interface et-0/0/0

If you want to modify existing , use the following prompt

> kill the above session and reinitiate the same with interface et-0/0/4 instead of et-0/0/0

╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ✓  simulator_stop_run (simulator MCP Server) {"payload":{"proc_id":"5db1c996-3d88-48b8-a047-85b2e01c39cb"},"ctx":""}                              │
│                                                                                                                                                   │
│    {                                                                                                                                              │
│      "status": "stopped",                                                                                                                         │
│      "proc_id": "5db1c996-3d88-48b8-a047-85b2e01c39cb",                                                                                           │
│      "stopped": true,                                                                                                                             │
│      "signal": "SIGTERM"                                                                                                                          │
│    }                                                                                                                                              │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ✓  simulator_intent (simulator MCP Server) {"ctx":"","payload":{"topology":"mcp-topology.csv","mode":"anomaly","bgp":"mcp-bgp_config.csv","anoma… │
│                                                                                                                                                   │
│    {                                                                                                                                              │
│      "status": "spawned",                                                                                                                         │
│      "proc_id": "df5ee7b1-cf7a-4e2b-929d-09a3e66b84ed",                                                                                           │
│      "pid": 1389897                                                                                                                               │
│    }                                                                                                                                              │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✦ The previous simulator session has been stopped. I have re-initiated the simulator with the same anomalies, but with the linkdown on CALFJNP02
  interface et-0/0/4.
```

### Anomaly Types

The following anomaly types are supported in the `anomaly` payload:

| Key              | Description / Example Usage |
|------------------|-----------------------------|
| `trafficprofile` | Modify traffic on a given interface.<br>Example: `\'trafficprofile\': [\'nylf01_et-0/0/0_50-2-2\']` |
| `linkdown`       | Mark one or more links down.<br>Example: `\'linkdown\': [\'nylf01_et-0/0/0\']` |
| `nodedown`       | Mark one or more nodes down.<br>Example: `\'nodedown\': [\'nylf01\', \'nyag01\']` |
| `intflap`        | Enable interface flapping.<br>Example: `\'intflap\': [\'nylf01_et-0/0/0\']` |
| `intindisc`      | Introduce interface input discards or errors.<br>Example: `\'intindisc\': [\'nylf01_et-0/0/0\']` |
| `cpuspike`       | Simulate CPU utilization spike on given nodes.<br>Example: `\'cpuspike\': [\'nylf01\']` |
| `memspike`       | Simulate memory spike on given nodes.<br>Example: `\'memspike\': [\'nylf01\']` |
| `assurance`      | Inject anomalies into assurance metrics.<br>Example: `\'assurance\': [\'nylf01\']` |
| `bgpflap`        | Simulate BGP session flap events.<br>Example: `\'bgpflap\': [\'nylf01\']` |
| `tundown`        | Mark a tunnel as down.<br>Example: `\'tundown\': [\'tun01\']` |
| `tunflap`        | Simulate tunnel flapping.<br>Example: `\'tunflap\': [\'tun01\']` |
| `intoutdisc`     | Introduce interface output discards. <br>Example: `\'intoutdisc\': [\'nylf01_et-0/0/0\']` |
| `intinerr`       | Introduce interface input errors. <br>Example: `\'intinerr\': [\'nylf01_et-0/0/0\']` |
| `intouterr`      | Introduce interface output errors. <br>Example: `\'intouterr\': [\'nylf01_et-0/0/0\']` |

### Managing Sessions

#### Stopping a Session

To stop a running session, use `simulator_stop_run` with the `proc_id` obtained when spawning the command:

```json
{
    "proc_id": "YOUR_PROCESS_ID"
}
```
or 

```
>> > kill all sessions

╭───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ✓  simulator_stop_run (simulator MCP Server) {"payload":{"proc_id":"38018225-c96b-495a-8f90-cc1bc524c5b6"},"ctx":""}                              │
│                                                                                                                                                   │
│    {                                                                                                                                              │
│      "status": "stopped",                                                                                                                         │
│      "proc_id": "38018225-c96b-495a-8f90-cc1bc524c5b6",                                                                                           │
│      "stopped": true,                                                                                                                             │
│      "signal": "SIGTERM"                                                                                                                          │
│    }                                                                                                                                              │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✦ All active simulator sessions have been stopped.

```
#### Viewing Session Status

To see all active and finished simulator sessions:

```json
{}
```
(empty payload for `simulator_status`) or use 

```
>> show all sessions

 Here are all the simulator sessions:

   * Session ID: 5db1c996-3d88-48b8-a047-85b2e01c39cb (Finished)
       * Command: generate_all_stats.py -t mcp-topology.csv -a anomaly -b mcp-bgp_config.csv -av {"memspike": ["CASPJNP02"], "cpuspike": ["CASPJNP01"],
          "linkdown": ["CALFJNP02_et-0/0/0"]}
   * Session ID: df5ee7b1-cf7a-4e2b-929d-09a3e66b84ed (Finished)
       * Command: generate_all_stats.py -t mcp-topology.csv -a anomaly -b mcp-bgp_config.csv -av {"cpuspike": ["CASPJNP01"], "linkdown":
         ["CALFJNP02_et-0/0/4"], "memspike": ["CASPJNP02"]}
   * Session ID: 38018225-c96b-495a-8f90-cc1bc524c5b6 (Running)
       * Command: generate_all_stats.py -t mcp-topology.csv -a anomaly -b mcp-bgp_config.csv -av {"cpuspike": ["CASPJNP01"], "linkdown":
         ["CALFJNP02_et-0/0/1"], "memspike": ["CASPJNP02"]}
```
