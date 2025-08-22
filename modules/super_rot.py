# modules/super_rot.py
from typing import List
from .common import Candidate, fitness, shift_char
import re, time

_B64ISH_STD  = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
_B64ISH_URL  = re.compile(r'^[A-Za-z0-9\-_]+={0,2}$')

def _progressive_transform(s: str, start=0, step=1, mode='decode', order='LTR') -> str:
    n=len(s); sign = -1 if mode=='decode' else 1
    out=[]
    for i,ch in enumerate(s):
        j = i if order=='LTR' else (n-1-i)
        k = (start + j*step) % 26
        out.append(shift_char(ch, sign*k))
    return "".join(out)

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config keys:
      - max_abs_step: int (default 5)  # tries steps in [-N..-1, +1..+N]
      - modes: ["decode","encode"]
      - orders: ["LTR","RTL"]
      - start_keys: optional list of ints (0..25). If absent => all 0..25
      - budget_s: float (soft budget; returns early if exceeded)
      - text_to_decipher: optional; if present, overrides ciphertext (supports '%c')
    """
    import time

    # Read config with safe defaults
    start_keys = config.get("start_keys", list(range(26)))
    if not isinstance(start_keys, (list, tuple)):
        # allow e.g. "all" or a single int
        start_keys = list(range(26)) if str(start_keys).lower() == "all" else [int(start_keys) % 26]

    max_abs_step = int(config.get("max_abs_step", 5)) or 5
    modes  = config.get("modes", ["decode", "encode"]) or ["decode", "encode"]
    orders = config.get("orders", ["LTR", "RTL"]) or ["LTR", "RTL"]
    budget_s = float(config.get("budget_s", 60.0))

    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    results: List[Candidate] = []
    started = time.monotonic()

    steps = list(range(-max_abs_step, 0)) + list(range(1, max_abs_step + 1))
    for start_key in start_keys:
        for step in steps:
            for order in orders:
                for mode in modes:
                    if time.monotonic() - started > budget_s:
                        # stop cleanly but keep anything we already found
                        return results
                    t = _progressive_transform(ciphertext, start=start_key, step=step, mode=mode, order=order)
                    sc = fitness(t)
                    # Prefer real base decoders over super-rot outputs that look like base64(-url)
                    if _B64ISH_STD.match(t) or _B64ISH_URL.match(t):
                        sc -= 2.0
                        if t.endswith("=="):
                            sc -= 1.0
                    # -------------- MISSING LINE (now added) --------------
                    results.append(
                        Candidate(
                            "super_rot",
                            f"start={start_key} step={step:+d} {order}/{mode}",
                            t,
                            sc,
                        )
                    )

    # Fallback: if nothing produced (e.g., budget 0 or config too restrictive), try the classic lane
    if not results:
        t = _progressive_transform(ciphertext, start=9, step=+1, mode="decode", order="LTR")
        results.append(Candidate("super_rot", "fallback start=9 step=+1 LTR/decode", t, fitness(t)))

    return results
