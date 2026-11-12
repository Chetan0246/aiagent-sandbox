"""Boundary and security posture probes for AI agent sandboxes."""

import os
import sys
import socket
import subprocess
from pathlib import Path
from typing import Dict, Any, List

def check_cgroups() -> Dict[str, Any]:
    """Inspects cgroup v2 limits for the current user slice."""
    uid = os.getuid()
    slice_path = Path(f"/sys/fs/cgroup/user.slice/user-{uid}.slice")
    
    results = {
        "cgroup_v2_active": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
        "user_slice_path": str(slice_path),
        "limits": {}
    }
    
    if not slice_path.exists():
        results["error"] = f"Slice path {slice_path} not found"
        return results

    for controller in ["memory.max", "memory.swap.max", "pids.max", "pids.current", "memory.current"]:
        p = slice_path / controller
        if p.exists():
            val = p.read_text().strip()
            results["limits"][controller] = val
        else:
            results["limits"][controller] = "not_available"
            
    return results

def audit_sensitive_files() -> List[Dict[str, Any]]:
    """Checks DAC permissions against sensitive OS files."""
    targets = ["/etc/shadow", "/root", "/proc/1/environ", "/etc/sudoers"]
    findings = []
    
    for target in targets:
        accessible = False
        error_msg = ""
        try:
            p = Path(target)
            if p.is_dir():
                list(p.iterdir())
                accessible = True
            else:
                p.read_bytes()
                accessible = True
        except Exception as e:
            error_msg = str(e)
            
        findings.append({
            "target": target,
            "accessible": accessible,
            "status": "VULNERABILITY" if accessible else "BOUNDARY_HELD",
            "error": error_msg
        })
    return findings

def probe_network_gateway(gateway_ip: str = "192.168.122.1", ports: List[int] = None) -> List[Dict[str, Any]]:
    """Probes hypervisor gateway management ports."""
    if ports is None:
        ports = [22, 80, 5900, 8080]
        
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((gateway_ip, port))
            status = "OPEN"
            s.close()
        except socket.timeout:
            status = "FILTERED"
        except ConnectionRefusedError:
            status = "CLOSED"
        except Exception as e:
            status = f"ERROR: {e}"
            
        results.append({
            "target": f"{gateway_ip}:{port}",
            "status": status,
            "secure": status in ["CLOSED", "FILTERED"]
        })
    return results

def check_imds_reachability() -> Dict[str, Any]:
    """Checks whether AWS/GCP/cloud link-local metadata is reachable."""
    imds_ip = "169.254.169.254"
    reachable = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((imds_ip, 80))
            reachable = True
    except Exception:
        reachable = False
        
    return {
        "target": "169.254.169.254:80",
        "reachable": reachable,
        "status": "VULNERABLE" if reachable else "BOUNDARY_HELD"
    }

def check_mount_isolation() -> Dict[str, Any]:
    """Checks whether /tmp and /var/tmp are mounted on ephemeral tmpfs."""
    mounts = {}
    try:
        output = subprocess.check_output(["findmnt", "-no", "TARGET,FSTYPE"], text=True)
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) == 2:
                mounts[parts[0]] = parts[1]
    except Exception as e:
        mounts["error"] = str(e)
        
    return {
        "tmp_fstype": mounts.get("/tmp", "unknown"),
        "var_tmp_fstype": mounts.get("/var/tmp", "unknown"),
        "root_fstype": mounts.get("/", "unknown"),
        "tmp_isolated": mounts.get("/tmp") == "tmpfs",
        "var_tmp_isolated": mounts.get("/var/tmp") == "tmpfs",
    }
