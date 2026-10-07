______________________Production-ready codebase for the Adaptive Force-End (AFE) framework._______________________
####### [Please NOTE: Malicious exploit payloads designed to target AV are excluded in compliance with ethical security research guidelines.

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

______________________Step-by-Step Compilation & Execution Guide_______________________
1) Kernel Requirements:
Requires Linux kernel $\ge 5.15$ with CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, and CONFIG_BPF_EVENTS=y.

2) Build eBPF C Bytecode:
Bashclang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c ebpf/afe_tracer.bpf.c -o ebpf/afe_tracer.bpf.o

3) Execute Core Engine (Root Privileges Required for Ring 0 Hooks):
Bashsudo python3 daemon/afe_core_engine.py

4) Run Attacker Simulation & 600-Trial Evaluation:
Bashpython3 evaluation/adaptive_attacker_sim.py
python3 evaluation/run_600_trials.py
