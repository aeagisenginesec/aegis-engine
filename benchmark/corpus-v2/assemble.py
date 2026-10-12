#!/usr/bin/env python3
"""Assemble corpus-v2: 200 projects from partA/B/C with a secret-seeded held-out split.

Layout:
  benchmark/corpus-v2/
    gen/            partA.py, partB.py, partC.py (builder sources)
    projects/       150 dev-set projects (v2-xxx/main.tf, ...)
    manifest.json   150 dev entries
    heldout/
      projects/     50 held-out projects
      manifest.json 50 held-out entries (chmod 600)
      .seed         secret seed (chmod 600, gitignored)
    SPLIT.md        split documentation + integrity hashes
    assemble.py     this script (reproducible; held-out needs .seed)

Split: stratified by secret seed — 35 vuln + 15 secure held out.
known_gap projects are forced into dev (authors should see/fix them).
"""
import hashlib
import json
import os
import random
import secrets
import shutil
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "gen"))
import partA, partB, partC  # noqa: E402

DEV_SEED_PUBLIC = "corpus-v2-dev"  # not actually used for randomness below; numbering is fixed

def load_all():
    all_projects = []
    for part, prefix in ((partA.PROJECTS, "A"), (partB.PROJECTS, "B"), (partC.PROJECTS, "C")):
        for p in part:
            all_projects.append(dict(p, part=prefix))
    return all_projects

def main():
    projs = load_all()
    assert len(projs) == 200, f"expected 200 projects, got {len(projs)}"
    vuln = [p for p in projs if p["vulnerable"]]
    sec = [p for p in projs if not p["vulnerable"]]
    assert len(vuln) == 140 and len(sec) == 60, f"vuln={len(vuln)} secure={len(sec)}"

    # global numbering: A -> v2-000..059, B -> v2-060..129, C -> v2-130..199
    order = ([p for p in projs if p["part"] == "A"] +
             [p for p in projs if p["part"] == "B"] +
             [p for p in projs if p["part"] == "C"])
    for i, p in enumerate(order):
        p["gid"] = f"v2-{i:03d}"

    # secret seed for held-out selection
    seed_path = os.path.join(HERE, "heldout", ".seed")
    if os.path.exists(seed_path):
        seed = open(seed_path).read().strip()
        print(f"reusing existing held-out seed from {seed_path}")
    else:
        seed = secrets.token_hex(16)
        with open(seed_path, "w") as f:
            f.write(seed + "\n")
        os.chmod(seed_path, stat.S_IRUSR | stat.S_IWUSR)
        print(f"generated new held-out seed -> {seed_path} (chmod 600)")

    rng = random.Random("corpus-v2-heldout:" + seed)
    gaps = [p for p in vuln if p.get("known_gap")]
    vuln_pool = [p for p in vuln if not p.get("known_gap")]
    rng.shuffle(vuln_pool)
    rng.shuffle(sec)
    heldout = vuln_pool[:35] + sec[:15]
    heldout_ids = {p["gid"] for p in heldout}
    dev = [p for p in order if p["gid"] not in heldout_ids]
    assert len(dev) == 150 and len(heldout) == 50
    assert all(p.get("known_gap") for p in gaps) and all(g not in heldout for g in gaps), "gaps must stay in dev"

    # write projects + manifests
    for d in ("projects", "heldout/projects"):
        pth = os.path.join(HERE, d)
        shutil.rmtree(pth, ignore_errors=True)
        os.makedirs(pth)

    def entry(p):
        e = {"project": p["gid"], "vulnerable": p["vulnerable"],
             "category": p.get("category", ""), "expected": p["expected"]}
        if p.get("known_gap"):
            e["known_gap"] = True
        return e

    for p, dest in [(p, "projects") for p in dev] + [(p, "heldout/projects") for p in heldout]:
        d = os.path.join(HERE, dest, p["gid"])
        os.makedirs(d)
        for fname, content in p["files"].items():
            fpath = os.path.join(d, fname)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "w") as f:
                f.write(content)

    dev_manifest = [entry(p) for p in dev]
    ho_manifest = [entry(p) for p in heldout]
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(dev_manifest, f, indent=2)
    ho_path = os.path.join(HERE, "heldout", "manifest.json")
    with open(ho_path, "w") as f:
        json.dump(ho_manifest, f, indent=2)
    os.chmod(ho_path, stat.S_IRUSR | stat.S_IWUSR)

    ho_hash = hashlib.sha256(open(ho_path, "rb").read()).hexdigest()
    seed_hash = hashlib.sha256(seed.encode()).hexdigest()

    split_md = f"""# Corpus-v2 split

- **Dev set**: 150 projects (`projects/`, `manifest.json`) — visible to rule authors.
- **Held-out set**: 50 projects (`heldout/projects/`, `heldout/manifest.json`) — RESTRICTED.
- **Selection**: stratified secret-seed shuffle — 35 vulnerable + 15 secure held out.
  known_gap projects (documented scanner limitations) are forced into dev.
- **Held-out manifest sha256**: `{ho_hash}`
- **Seed sha256**: `{seed_hash}` (seed itself in `heldout/.seed`, chmod 600, gitignored)

## Policy

Do NOT tune rules against held-out projects or inspect `heldout/manifest.json`
during development. The held-out set measures generalization. In CI, inject the
seed as a secret and verify `heldout/manifest.json` against the sha256 above
before scoring; any mismatch means the labels were tampered with.

In this local environment true access control is not enforceable — this file,
the chmod-600 permissions, and the integrity hash are the mechanism, plus
reviewer discipline. Treat any held-out tuning as a benchmark integrity violation.
"""
    with open(os.path.join(HERE, "SPLIT.md"), "w") as f:
        f.write(split_md)

    # .gitignore for the seed
    gi = os.path.join(HERE, ".gitignore")
    if not os.path.exists(gi) or ".seed" not in open(gi).read():
        with open(gi, "a") as f:
            f.write("heldout/.seed\n")

    n_vuln_dev = sum(1 for p in dev if p["vulnerable"])
    n_sec_dev = 150 - n_vuln_dev
    print(f"dev: {len(dev)} ({n_vuln_dev} vuln, {n_sec_dev} secure) | heldout: 50 (35 vuln, 15 secure)")
    print(f"known_gap in dev: {len(gaps)}")
    print(f"heldout manifest sha256: {ho_hash}")

if __name__ == "__main__":
    main()
