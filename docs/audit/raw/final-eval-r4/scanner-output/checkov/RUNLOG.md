# Checkov round-4 sweep

- Accuracy: 210/210 projects, 0 failures (4 shards, 1850-1856s wall each)
- Timing: 30 projects x 5 runs, 1629s wall, sequential
- Command: `checkov -d <project> -o json --quiet` (no --framework flag)
- Median of per-project medians (cold+warm): 10.12s

Note: this file previously contained round-3 lines carried over from the
R3 run-log template; they were replaced with the R4 record above.
