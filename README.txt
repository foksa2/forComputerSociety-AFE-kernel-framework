______________________Production-ready codebase for the Adaptive Force-End (AFE) framework._______________________

afe-framework/
├── ebpf/
│   ├── afe_tracer.bpf.c          # Ring-0 eBPF C program (kprobes, tracepoints, pre-TLS VFS)
│   └── afe_maps.h                # In-kernel BPF maps (hash, per-CPU array, LRU lineage)
├── daemon/
│   ├── afe_core_engine.py        # User-space dynamic risk scoring & continuous update engine
│   ├── entropy_analyzer.py       # Standalone C-accelerated Pre-TLS Shannon entropy engine
│   └── interdiction_handler.py   # Recursive process-tree jailing & kernel socket reset (RST)
├── evaluation/
│   ├── adaptive_attacker_sim.py  # Attacker harness (Low-and-slow, DiD, setsid, built-in heavy)
│   └── run_600_trials.py         # 645-host orchestrator & ZFS snapshot re-seeding engine
└── config/
    └── afe_hyperparams.json      # Grid-search optimized weights, decay, and threshold configs
