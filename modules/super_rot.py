# modules/super_rot.py
from typing import List
from .common import Candidate, fitness, shift_char
import re, time

_RE_B64ISH  = re.compile(r'^[A-Za-z0-9+/]{12,}(?:==|=)?$')
_RE_B64URL  = re.compile(r'^[A-Za-z0-9_-]{12,}(?:==|=)?$')
_RE_B58ISH  = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{12,}$')
_RE_B45ISH = re.compile(r'^[0-9A-Z $%*+\-./:]{12,}$')
_B91_ALPH = r'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@\[\]^_`{|}~"'
_RE_B91ISH = re.compile(rf'^[{_B91_ALPH}]{{12,}}$')

def _encoding_shape_penalty(s: str) -> float:
    pen = 0.0
    if _RE_B64ISH.fullmatch(s) or _RE_B64URL.fullmatch(s):
        pen += 6.0
        if s.endswith('=') or s.endswith('=='): pen += 2.0
    if _RE_B58ISH.fullmatch(s):
        pen += 3.0
    # NEW:
    if _RE_B45ISH.fullmatch(s):
        pen += 2.5
    if _RE_B91ISH.fullmatch(s):
        pen += 2.5
    if len(s) >= 16 and ' ' not in s:
        digits = sum(c.isdigit() for c in s)
        if digits / len(s) >= 0.25:
            pen += 1.0
    return pen

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
                    sc -= _encoding_shape_penalty(t)
                    sc -= float(config.get("general_malus", 1.2))  # small across-the-board malus

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
