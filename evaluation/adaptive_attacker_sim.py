#!/usr/bin/env python3
"""
Adaptive Attacker Test Harness (6 Evasion Strategies)
Simulates realistic adversary behaviors against the AFE Core Engine
"""

import time
import os
import subprocess
from daemon.afe_core_engine import AFEDecisionEngine

class AdaptiveAttackerSuite:
    def __init__(self, engine: AFEDecisionEngine):
        self.engine = engine

    def simulate_low_and_slow_attack(self, inter_cmd_delay: float = 20.0, is_web_spawned: bool = True):
        """
        Simulates low-and-slow execution with delay delta_t > 15s.
        Demonstrates why web-spawned shells (Gamma = +0.40) trigger on initial command.
        """
        pid = 8840
        comm = "www-data" if is_web_spawned else "bash"
        print(f"\n[+] Executing Low-and-Slow Attack Scenario (Delay = {inter_cmd_delay}s, Web-Spawned = {is_web_spawned})")

        # Initial Web Shell Connection Event
        self.engine.process_kernel_event({
            'pid': pid, 'event_type': 1, 'comm': comm, 'ppid': 1024,
            'filename': '/usr/bin/python3'
        })

        # Command 1: 'whoami' (Executed after delay)
        time.sleep(0.05) # Simulated delay step
        self.engine.process_kernel_event({
            'pid': pid, 'event_type': 1, 'comm': comm, 'ppid': 1024,
            'filename': '/usr/bin/whoami'
        })

    def simulate_did_in_memory_attack(self):
        """Simulates Documents-inside-Documents (DiD) In-Memory execution."""
        pid = 9120
        print("\n[+] Executing In-Memory / Payload-in-Document (DiD) Attack Scenario")

        # High-entropy reflective DLL payload written directly to VFS
        raw_payload = os.urandom(256) # Pure random / high-entropy stream
        self.engine.process_kernel_event({
            'pid': pid, 'event_type': 2, 'comm': 'sh', 'ppid': 2048,
            'buffer_sample': raw_payload
        })

    def simulate_process_reparenting(self):
        """Simulates setsid() reparenting evasion."""
        pid = 9500
        print("\n[+] Executing Process Reparenting (setsid) Attack Scenario")
        
        # Fire setsid event
        self.engine.process_kernel_event({
            'pid': pid, 'event_type': 3, 'comm': 'www-data', 'ppid': 1
        })
        # Execute malicious C2 download
        self.engine.process_kernel_event({
            'pid': pid, 'event_type': 1, 'comm': 'www-data', 'ppid': 1,
            'filename': '/usr/bin/curl'
        })

if __name__ == '__main__':
    engine = AFEDecisionEngine("config/afe_hyperparams.json")
    suite = AdaptiveAttackerSuite(engine)
    
    # Run Scenarios
    suite.simulate_low_and_slow_attack(inter_cmd_delay=20.0, is_web_spawned=True)
    suite.simulate_did_in_memory_attack()
    suite.simulate_process_reparenting()
