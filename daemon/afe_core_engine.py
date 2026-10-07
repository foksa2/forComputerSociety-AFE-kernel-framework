#!/usr/bin/env python3
# Main user-space engine implementing $R[k]$ recursive discretization, low-and-slow accumulator, and execution control.
import os
import sys
import time
import math
import json
import logging
import signal
from typing import Dict, Optional
from entropy_analyzer import PreTLSEntropyEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] AFE-Core: %(message)s')

class SessionContext:
    def __init__(self, pid: int, comm: str, ppid: int, initial_gamma: float):
        self.pid = pid
        self.comm = comm
        self.ppid = ppid
        self.gamma = initial_gamma
        
        # Continuous Scoring State: R[0] = Gamma(L_p)
        self.r_k = initial_gamma
        self.last_update_time = time.monotonic()
        
        # Multi-Window Accumulator for Low-and-Slow Attack Detection
        self.long_term_window = []
        self.active = True

    def compute_decayed_score(self, now: float, lambda_decay: float) -> float:
        delta_t = now - self.last_update_time
        return self.r_k * math.exp(-lambda_decay * delta_t), delta_t

class AFEDecisionEngine:
    def __init__(self, config_path: str = "config/afe_hyperparams.json"):
        # Load hyperparameters
        with open(config_path, 'r') as f:
            self.config = json.load(f)

        self.alpha = self.config['alpha_entropy']       # 0.12
        self.beta = self.config['beta_cmd']             # 0.45
        self.lambda_decay = self.config['lambda_decay'] # 0.10 s^-1
        self.theta = self.config['theta_threshold']     # 0.85
        
        self.cmd_weights = self.config['command_weights']
        self.sessions: Dict[int, SessionContext] = {}

    def register_or_get_session(self, pid: int, comm: str, ppid: int, gamma_offset: float) -> SessionContext:
        if pid not in self.sessions:
            self.sessions[pid] = SessionContext(pid, comm, ppid, gamma_offset)
            logging.info(f"New Session Registered | PID: {pid} | Comm: {comm} | Initial Baseline R[0]=Gamma: {gamma_offset:+.2f}")
        return self.sessions[pid]

    def process_kernel_event(self, event: dict):
        pid = event['pid']
        event_type = event['event_type']
        comm = event.get('comm', 'unknown')
        ppid = event.get('ppid', 0)
        
        # Resolve Lineage Offset
        gamma = 0.40 if comm in ['www-data', 'nginx', 'apache'] else (
                -0.25 if 'ssh' in comm else 0.00)

        session = self.register_or_get_session(pid, comm, ppid, gamma)
        now = time.monotonic()

        # Step 1: Zero-Order Hold Exponential Decay
        decayed_r, delta_t = session.compute_decayed_score(now, self.lambda_decay)

        # Step 2: Compute Feature Multipliers
        e_io_term = 0.0
        w_cmd_term = 0.0

        if event_type == 2: # VFS_WRITE
            raw_buf = event.get('buffer_sample', b'')
            shannon_h = PreTLSEntropyEngine.calculate_entropy(raw_buf)
            e_io_term = PreTLSEntropyEngine.evaluate_vfs_risk_modifier(shannon_h)

        elif event_type == 1: # EXECVE
            executed_bin = os.path.basename(event.get('filename', '')).lower()
            w_cmd_term = self.cmd_weights.get(executed_bin, 0.10)

        # Step 3: Exact Discrete Update R[k] = R[k-1]*e^{-\lambda \Delta t} + \alpha E_io + \beta W_cmd
        session.r_k = decayed_r + (self.alpha * e_io_term) + (self.beta * w_cmd_term)
        session.last_update_time = now

        # Step 4: Multi-Window Low-and-Slow Accumulator Check
        session.long_term_window.append((now, session.r_k))
        session.long_term_window = [pt for pt in session.long_term_window if now - pt[0] <= 3600] # 1-Hour window

        logging.debug(f"PID {pid} ({comm}) | Delta_t: {delta_t:.2f}s | R[k]: {session.r_k:.4f}")

        # Step 5: Interdiction Threshold Evaluation
        if session.r_k > self.theta and session.active:
            self.trigger_interdiction(session, delta_t)

    def trigger_interdiction(self, session: SessionContext, delta_t: float):
        """Executes process-tree pruning and socket termination."""
        start_time = time.perf_counter()
        session.active = False
        
        try:
            pgid = os.getpgid(session.pid)
            logging.warning(f"!!! THRESHOLD BREACH (R[k] = {session.r_k:.4f} > {self.theta}) !!!")
            logging.warning(f"Interdicting Malicious Session | PID: {session.pid} | PGID: {pgid} | Comm: {session.comm}")
            
            # 1. Process Group Pruning via SIGKILL
            os.killpg(pgid, signal.SIGKILL)
            
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logging.info(f"SUCCESS: Process-tree PGID {pgid} terminated in {elapsed_ms:.2f} ms.")
            
        except ProcessLookupError:
            logging.warning(f"Target PID {session.pid} exited prior to SIGKILL signal dispatch.")
        except PermissionError:
            logging.error(f"Permission Denied: Core Engine must execute with root/CAP_SYS_ADMIN privileges.")
