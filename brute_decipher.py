#!/usr/bin/env python3
"""
brute_decipher.py — module-driven CTF decipher toolkit.

Usage:
  python3 brute_decipher.py -c config.json "cipher text"
"""

import argparse, importlib, json, sys, time, traceback
from pathlib import Path
from typing import List
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
        # optional placeholder expansion:
        if "text_to_decipher" in mc and mc["text_to_decipher"] == "%c":
            mc["text_to_decipher"] = ciphertext  # give module freedom to read it
        # all modules will still receive 'ciphertext' explicitly
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

    ranked = dedupe_and_rank(results)
    print_candidates(ranked, top_k, show_hint_mode)

if __name__ == "__main__":
    main()
