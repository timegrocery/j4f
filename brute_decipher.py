#!/usr/bin/env python3
"""
brute_decipher.py — module-driven CTF decipher toolkit.

Usage:
  python3 brute_decipher.py -c config.json "cipher text"
"""

import argparse, importlib, json, sys, time, traceback
from pathlib import Path
from typing import List, Dict
from modules.common import snake_from_camel, smart_hint

# ---------- load config ----------
def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

# ---------- pretty print ----------
def print_candidates(cands, top_k: int, show_hint_mode: str = "auto"):
    if not cands:
        print("No candidates produced."); return
    #print("\n=== Top candidates ===")
    for i, c in enumerate(cands[:top_k], 1):
        print(f"[{i}] score={c.score:.3f}  algo={c.algo:<10} {c.params}")
        print(f"     raw:   {c.text}")
        if show_hint_mode != "never":
            if show_hint_mode == "always":
                # legacy behavior (not recommended): always show snake
                print(f"     snake: {snake_from_camel(c.text)}")
            else:
                hint = smart_hint(c.text)  # ('snake', val) or ('lower', val) or None
                if hint:
                    label, val = hint
                    print(f"     {label}: {val}")
        print()

# ---------- ranking helpers ----------
def unique_by_text(items):
    seen = set()
    out = []
    for x in items:
        key = x.text  # dedupe by plaintext text
        if key in seen:
            continue
        seen.add(key)
        out.append(x)
    return out

def cap_per_algo(ranked_all, per_algo_cap: int) -> List:
    """From a ranked list (desc score), keep up to N per algorithm, preserving order."""
    kept_per: Dict[str, int] = {}
    out = []
    for c in ranked_all:
        k = kept_per.get(c.algo, 0)
        if k < per_algo_cap:
            out.append(c)
            kept_per[c.algo] = k + 1
    return out

def ensure_each_algo_top1_present(buckets: Dict[str, List], current: List, top_k: int) -> List:
    """
    Make sure at least the top-1 item from each algo appears early in the list.
    We place all per-algo #1 seeds at the front (sorted by score desc), then the rest.
    """
    seeds = [items[0] for items in buckets.values() if items]
    # remove any already present duplicates from seeds list based on identity
    seed_ids = set(id(x) for x in seeds)
    rest = [c for c in current if id(c) not in seed_ids]
    # Sort seeds by score desc so the most convincing ones show first
    seeds_sorted = sorted(seeds, key=lambda x: x.score, reverse=True)
    return unique_by_text(seeds_sorted + rest)

def main():
    ap = argparse.ArgumentParser(description="CTF brute decipher toolkit")
    ap.add_argument("ciphertext", help="Cipher text (quote it in your shell)")
    ap.add_argument("-c", "--config", default="config.json", help="Path to JSON config")
    ap.add_argument("--top", type=int, default=None, help="Override top_k printing")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    active = cfg.get("active_modules", [])
    mod_cfgs = cfg.get("modules", {})
    glob = cfg.get("global", {})

    show_hint_mode = (glob.get("show_hint", "auto")).lower()
    top_k = args.top if args.top is not None else int(glob.get("top_k", 10))
    total_budget_s = float(glob.get("total_budget_s", 600.0))
    # NEW knobs
    per_algo_cap = int(glob.get("per_algo_cap", 5))  # cap how many per algorithm feed into the final list
    ensure_each_algo_top1 = bool(glob.get("ensure_each_algo_top1", True))

    # import after config to avoid import cost if config fails
    from modules.common import Candidate, dedupe_and_rank

    ciphertext = args.ciphertext
    results: List[Candidate] = []

    started_all = time.monotonic()
    for name in active:
        # dynamic import: modules.<name>
        try:
            module = importlib.import_module(f"modules.{name}")
        except Exception as e:
            print(f"[!] Could not import module '{name}': {e}", file=sys.stderr)
            continue

        # prepare per-module config
        mc = dict(mod_cfgs.get(name, {}))
        # optional placeholder expansion
        if "text_to_decipher" in mc and mc["text_to_decipher"] == "%c":
            mc["text_to_decipher"] = ciphertext  # give module freedom to read it

        try:
            # Each module must expose: run(ciphertext: str, config: dict) -> List[Candidate]
            out = module.run(ciphertext, mc)
            #print(f"[diag] module '{name}' returned {len(out)} candidates")
            results.extend(out)
        except Exception as e:
            print(f"[!] Module '{name}' raised an error: {e}", file=sys.stderr)
            traceback.print_exc()

        # respect global time budget
        if time.monotonic() - started_all > total_budget_s:
            print("[!] Global time budget exceeded; returning best-so-far.", file=sys.stderr)
            break

    # First, dedupe by text and rank globally (your existing logic)
    ranked_all = dedupe_and_rank(results)  # desc by score

    # Bucket by algorithm for targeted post-processing
    buckets: Dict[str, List[Candidate]] = {}
    for c in ranked_all:
        buckets.setdefault(c.algo, []).append(c)

    # Apply per-algorithm cap to avoid flooding (e.g., super_rot spam)
    if per_algo_cap > 0:
        capped = cap_per_algo(ranked_all, per_algo_cap)
    else:
        capped = ranked_all

    # Optionally ensure each algorithm's top-1 shows up early (keep that order!)
    if ensure_each_algo_top1 and capped:
        ranked_final = ensure_each_algo_top1_present(buckets, capped, top_k)
    else:
        # otherwise keep the global score order (already sorted upstream)
        ranked_final = capped

    print_candidates(ranked_final, top_k, show_hint_mode)

if __name__ == "__main__":
    main()
