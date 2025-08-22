# modules/rot13.py
from typing import List
from .common import Candidate, fitness, shift_char

def _rotN(s: str, k: int) -> str:
    return "".join(shift_char(ch, -k) for ch in s)

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - n: int or "all"  (default 13; "all" tries 0..25)
      - budget_s: float (default 1.0)
      - text_to_decipher: optional override with '%c' support
    """
    import time
    n = config.get("n", 13)
    budget_s = float(config.get("budget_s", 1.0))
    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    results: List[Candidate] = []
    started = time.monotonic()

    if n == "all":
        for k in range(26):
            if time.monotonic()-started > budget_s: break
            t = _rotN(ciphertext, k)
            results.append(Candidate("rotN", f"k={k}", t, fitness(t)))
    else:
        k = int(n) % 26
        t = _rotN(ciphertext, k)
        results.append(Candidate("rotN", f"k={k}", t, fitness(t)))

    return results
