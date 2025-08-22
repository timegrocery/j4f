# modules/base45.py
from typing import List, Tuple
from .common import Candidate, fitness, is_mostly_printable
import re, unicodedata, time

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
A2I = {c:i for i,c in enumerate(ALPHABET)}
ALLOWED = set(ALPHABET)
ALLOWED_PRINT = " _-.,:;!?/|()[]{}'\"\\"

# scanner (min 6 to keep it sane; 6 chars -> 4 bytes)
RE_B45 = re.compile(rf'(?<![{re.escape("".join(sorted(set(map(chr, range(32,127))) - ALLOWED)))}])[{re.escape(ALPHABET)}]{{6,}}')

def _normalize(s: str) -> str:
    t = unicodedata.normalize("NFKC", s)
    return t.replace("\u200b","").replace("\u200c","").replace("\u200d","").strip()

def _strip_to_allowed(s: str) -> str:
    return ''.join(ch for ch in s if ch in ALPHABET)

def _to_text(b: bytes, min_len: int = 6) -> str | None:
    try:
        t = b.decode("utf-8", errors="ignore")
        if t and len(t.strip()) >= min_len and is_mostly_printable(t):
            return t
    except Exception:
        pass
    return None

def _module_bonus(t: str) -> float:
    n = len(t)
    if n == 0: return 0.0
    letters = sum(ch.isalpha() for ch in t)
    others  = sum(not (ch.isalnum() or ch in ALLOWED_PRINT) for ch in t)
    lp = letters / n
    op = others  / n
    if lp >= 0.75 and op <= 0.05: return 1.3
    if lp >= 0.60 and op <= 0.10: return 0.7
    return 0.2

def _path_penalty(path: str) -> float:
    if path.startswith("raw->"): return 0.0
    pen = 0.0
    if "keep_only" in path: pen += 0.3
    if "scan" in path:      pen += 0.2
    if "rm_periodic" in path or "rm[" in path: pen += 1.0
    return pen

def _add(results: List[Candidate], path: str, t: str, drop_ratio: float = 0.0):
    sc = fitness(t) + _module_bonus(t) - min(2.0, drop_ratio * 3.0) - _path_penalty(path)
    results.append(Candidate("base45", f"path={path}", t, sc))

# --- RFC 9285 decode ---
def b45decode(s: str) -> bytes:
    """
    Decode Base45 per RFC 9285. Raises on invalid chars/length.
    """
    vals = [A2I[c] for c in s]  # KeyError -> invalid char
    out = bytearray()
    i = 0
    L = len(vals)
    while i < L:
        if i+2 < L:
            v = vals[i] + 45*vals[i+1] + 45*45*vals[i+2]
            if v > 0xFFFF: raise ValueError("base45: value out of range")
            out.append(v // 256)
            out.append(v % 256)
            i += 3
        elif i+1 < L:
            v = vals[i] + 45*vals[i+1]
            if v > 0xFF: raise ValueError("base45: value out of range")
            out.append(v)
            i += 2
        else:
            raise ValueError("base45: dangling char")
    return bytes(out)

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - budget_s: float (default 5.0)
      - scan_substrings: bool (default true)
      - min_token_len: int (default 6)
      - periodic_max_k: int (default 6)
      - min_plain_len: int (default 6)
      - text_to_decipher: optional; overrides with '%c'
    """
    budget_s = float(config.get("budget_s", 5.0))
    scan_sub = bool(config.get("scan_substrings", True))
    min_len  = int(config.get("min_token_len", 6))
    periodic_max_k = int(config.get("periodic_max_k", 6))
    min_plain_len = int(config.get("min_plain_len", 6))

    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    started = time.monotonic()
    def time_up() -> bool: return (time.monotonic() - started) > budget_s

    src = _normalize(ciphertext)
    results: List[Candidate] = []
    tried = set()

    def try_decode(s: str, tag: str, drop_ratio: float = 0.0):
        if s in tried: return
        tried.add(s)
        try:
            out = b45decode(s)
        except Exception:
            return
        plain = _to_text(out, min_plain_len)
        if plain:
            _add(results, tag, plain, drop_ratio)

    # Whole string
    if not time_up():
        try_decode(src, "raw->b45")
        keep = _strip_to_allowed(src)
        if len(keep) >= min_len and not time_up():
            drop = 1.0 - (len(keep)/max(1,len(src)))
            try_decode(keep, f"keep_only(drop={drop:.2f})->b45", drop)

    # Light periodic junk removal (covers “insert a junk every k chars”)
    if not time_up():
        n = len(src)
        for k in range(2, max(3, periodic_max_k+1)):
            if time_up(): break
            for ph in range(k):
                cleaned = ''.join(ch for i,ch in enumerate(src) if i % k != ph)
                keep2 = _strip_to_allowed(cleaned)
                if len(keep2) >= min_len:
                    drop = 1.0 - (len(keep2)/max(1,len(src)))
                    try_decode(keep2, f"rm_periodic(k={k},ph={ph},drop={drop:.2f})->b45", drop)

    # Substring scan
    if scan_sub and not time_up():
        for m in RE_B45.finditer(src):
            tok = m.group(0)
            try_decode(tok, f"scan[{m.start()}:{m.end()}]->b45")

    return results
