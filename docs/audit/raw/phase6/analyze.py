#!/usr/bin/env python3
"""Phase 6 analysis: summary stats, throughput, log-log scaling exponents.

Reads perf.csv (+ perf_huge.csv) and prints the tables/numbers that go
into 05_PERFORMANCE_AND_SCALE_REPORT.md. Stage medians are embedded from
the stagebreak harness runs (documented in the report).
"""
import csv
import math
import statistics

PERF = "/home/hatch/workspace/aegis-engine/docs/audit/raw/phase6/perf.csv"


def pct(sorted_vals, p):
    n = len(sorted_vals)
    k = (n - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, n - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def summarize(rows):
    walls = sorted(float(r["wall_ms"]) for r in rows)
    rss = [int(r["rss_kb"]) for r in rows]
    return {
        "n": len(walls),
        "min": walls[0],
        "median": statistics.median(walls),
        "p95": pct(walls, 95),
        "max": walls[-1],
        "rss_min": min(rss),
        "rss_max": max(rss),
        "findings": rows[0]["findings"],
        "resources": rows[0]["resources"],
        "discovered": rows[0]["files_discovered"],
    }


def fit_exponent(points):
    """Log-log least squares: time = a * files^b -> returns (b, r2)."""
    xs = [math.log(p[0]) for p in points]
    ys = [math.log(p[1]) for p in points]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    b = num / den
    ss_res = sum((y - (my + b * (x - mx))) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return b, 1 - ss_res / ss_tot


def main():
    rows = list(csv.DictReader(open(PERF)))
    sizes = ["small", "medium", "large"]
    print("== per-target summary (11 runs, text format) ==")
    medians = {}
    for s in sizes:
        r = [x for x in rows if x["repo_size"] == s]
        st = summarize(r)
        medians[s] = st["median"]
        cold = [x for x in r if x["cold_warm"] == "cold"][0]
        warm = [x for x in r if x["cold_warm"] == "warm"]
        warm_med = statistics.median(float(x["wall_ms"]) for x in warm)
        files = int(st["discovered"])
        print(f"{s:8s} files={files:5d} "
              f"min={st['min']:9.1f} median={st['median']:9.1f} "
              f"p95={st['p95']:9.1f} max={st['max']:9.1f} ms")
        print(f"         cold_run1={float(cold['wall_ms']):.1f} ms  "
              f"warm_median={warm_med:.1f} ms  "
              f"rss_max={st['rss_max']/1024:.1f} MiB")
        print(f"         findings={st['findings']} resources={st['resources']} "
              f"-> {files/(st['median']/1000):.1f} files/s, "
              f"{int(st['resources'])/(st['median']/1000):.1f} res/s")
        # completeness: constant across runs
        r0 = r[0]
        tot = int(r0["parsed"]) + int(r0["skipped"]) + int(r0["failed"])
        print(f"         completeness: discovered={r0['files_discovered']} "
              f"parsed={r0['parsed']} skipped={r0['skipped']} "
              f"failed={r0['failed']} (sum={tot})")
        fs = set(x["findings"] for x in r)
        print(f"         findings identical across runs: {len(fs)==1} {fs}")

    print()
    print("== end-to-end scaling exponent (CLI wall median vs files) ==")
    pts = [(10, medians["small"]), (200, medians["medium"]), (2000, medians["large"])]
    b, r2 = fit_exponent(pts)
    print(f"files 10/200/2000 -> exponent b={b:.3f} (R^2={r2:.4f})")

    print()
    print("== stage scaling exponents (stagebreak medians, ms) ==")
    stages = {
        "discovery": [(10,0.10),(100,0.47),(200,4.73),(250,7.36),(500,2.81),(1000,5.81),(2000,23.72)],
        "parse":     [(10,5.74),(100,176.01),(200,191.44),(250,479.66),(500,385.19),(1000,1175.99),(2000,4801.02)],
        "semantics": [(10,0.05),(100,2.60),(200,13.69),(250,8.03),(500,21.79),(1000,31.41),(2000,189.37)],
        "rules":     [(10,13.25),(100,52.80),(200,176.57),(250,158.00),(500,252.19),(1000,975.74),(2000,8269.25)],
        "report":    [(10,0.87),(100,15.28),(200,59.06),(250,131.46),(500,95.56),(1000,164.29),(2000,985.23)],
    }
    for name, pts in stages.items():
        b, r2 = fit_exponent(pts)
        print(f"  {name:10s} exponent b={b:.3f} (R^2={r2:.4f})")

    print()
    print("== isolated rule-engine scaling (warm registry, rulebreak) ==")
    eng = [(250,25.15),(500,25.19),(1000,58.23),(2000,136.53),(4000,411.68),(7373,1297.62)]
    b, r2 = fit_exponent(eng)
    print(f"  registry.Run exponent b={b:.3f} (R^2={r2:.4f})")
    # pairwise segment exponents to show acceleration
    for (n0,t0),(n1,t1) in zip(eng, eng[1:]):
        seg = math.log(t1/t0)/math.log(n1/n0)
        print(f"    {n0}->{n1} resources: segment exponent {seg:.2f}")


if __name__ == "__main__":
    main()
