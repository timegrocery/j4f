# modules/base91.py
from typing import List
from .common import Candidate, fitness, is_mostly_printable
import re, unicodedata, time

# basE91 alphabet (canonical)
ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
# Build decode table
D = {c:i for i,c in enumerate(ALPHABET)}
ALLOWED = set(ALPHABET)
ALLOWED_PRINT = " _-.,:;!?/|()[]{}'\"\\"

# Rough token scan: need a bit longer—8+ is a good start
RE_B91 = re.compile(rf'[{re.escape(ALPHABET)}]{{8,}}')

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
    if lp >= 0.70 and op <= 0.08: return 1.1
    if lp >= 0.55 and op <= 0.12: return 0.6
    return 0.2

def _path_penalty(path: str) -> float:
    if path.startswith("raw->"): return 0.0
    pen = 0.0
    if "keep_only" in path: pen += 0.3
    if "scan" in path:      pen += 0.2
    if "rm_periodic" in path or "rm[" in path: pen += 1.0
    return pen

def _add(results: list, path: str, t: str, drop_ratio: float = 0.0):
    sc = fitness(t) + _module_bonus(t) - min(2.0, drop_ratio*3.0) - _path_penalty(path)
    results.append(Candidate("base91", f"path={path}", t, sc))

# basE91 decoder (public-domain style implementation)
def b91decode(s: str) -> bytes:
    v = -1
    b = 0
    n = 0
    out = bytearray()
    for ch in s:
        if ch not in D:
            raise ValueError("invalid base91 char")
        c = D[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v != -1:
        out.append((b | v << n) & 255)
    return bytes(out)

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - budget_s: float (default 5.0)
      - scan_substrings: bool (default true)
      - min_token_len: int (default 8)
      - periodic_max_k: int (default 6)
      - min_plain_len: int (default 6)
      - text_to_decipher: optional; overrides with '%c'
    """
    budget_s = float(config.get("budget_s", 5.0))
    scan_sub = bool(config.get("scan_substrings", True))
    min_len  = int(config.get("min_token_len", 8))
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
            out = b91decode(s)
        except Exception:
            return
        plain = _to_text(out, min_plain_len)
        if plain:
            _add(results, tag, plain, drop_ratio)

    # Whole string
    if not time_up():
        try_decode(src, "raw->b91")
        keep = _strip_to_allowed(src)
        if len(keep) >= min_len and not time_up():
            drop = 1.0 - (len(keep)/max(1,len(src)))
            try_decode(keep, f"keep_only(drop={drop:.2f})->b91", drop)

    # Light periodic junk removal
    if not time_up():
        n = len(src)
        for k in range(2, max(3, periodic_max_k+1)):
            if time_up(): break
            for ph in range(k):
                cleaned = ''.join(ch for i,ch in enumerate(src) if i % k != ph)
                keep2 = _strip_to_allowed(cleaned)
                if len(keep2) >= min_len:
                    drop = 1.0 - (len(keep2)/max(1,len(src)))
                    try_decode(keep2, f"rm_periodic(k={k},ph={ph},drop={drop:.2f})->b91", drop)

    # Substring scan
    if scan_sub and not time_up():
        for m in RE_B91.finditer(src):
            tok = m.group(0)
            if len(tok) >= min_len:
                try_decode(tok, f"scan[{m.start()}:{m.end()}]->b91")

    return results
