"""Controlled stress and resource exhaustion probes for AI sandboxes."""

import os
import sys
import time
import math
import multiprocessing
from typing import Dict, Any

def run_fork_probe(max_procs: int = 100) -> Dict[str, Any]:
    """Tests fork limit without permanently exhausting system process table."""
    spawned = []
    failed = False
    error_msg = ""
    
    try:
        for i in range(max_procs):
            pid = os.fork()
            if pid == 0:
                # Child sleeps briefly then exits
                time.sleep(2)
                os._exit(0)
            else:
                spawned.append(pid)
    except BlockingIOError as e:
        failed = True
        error_msg = f"BlockingIOError: {e}"
    except OSError as e:
        failed = True
        error_msg = f"OSError [Errno {e.errno}]: {e.strerror}"
    finally:
        # Reap all children immediately
        for pid in spawned:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except Exception:
                pass
                
    return {
        "attempted": max_procs,
        "successfully_spawned": len(spawned),
        "hit_ceiling": failed,
        "error": error_msg
    }

def run_memory_probe(target_mb: int = 200, hold_seconds: float = 1.0) -> Dict[str, Any]:
    """Tests memory allocation within safe thresholds."""
    start_time = time.time()
    try:
        # Allocate contiguous bytearray
        buf = bytearray(target_mb * 1024 * 1024)
        # Touch pages to force physical commitment
        for i in range(0, len(buf), 4096):
            buf[i] = 1
        time.sleep(hold_seconds)
        del buf
        success = True
        error = ""
    except MemoryError as e:
        success = False
        error = f"MemoryError: {e}"
    except Exception as e:
        success = False
        error = str(e)
        
    duration = time.time() - start_time
    return {
        "target_mb": target_mb,
        "success": success,
        "duration_seconds": round(duration, 3),
        "error": error
    }

def _worker_cpu(duration: float):
    start = time.time()
    v = 0.0
    while time.time() - start < duration:
        v += math.sqrt(999999.0)
    return True

def run_concurrency_stress(workers: int = 3, duration: float = 2.0) -> Dict[str, Any]:
    """Simulates concurrent multi-worker load."""
    start_time = time.time()
    with multiprocessing.Pool(processes=workers) as pool:
        results = [pool.apply_async(_worker_cpu, (duration,)) for _ in range(workers)]
        success = all([r.get(timeout=duration + 5.0) for r in results])
        
    total_time = round(time.time() - start_time, 2)
    return {
        "workers": workers,
        "duration_per_worker": duration,
        "completed": success,
        "total_elapsed_seconds": total_time
    }
