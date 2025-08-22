from typing import List, Tuple
from .common import Candidate, fitness, is_mostly_printable, snake_from_camel
import base64, string, re

# --- NEW: token scanners ---
_B64_CHARS      = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_B64_URL_CHARS  = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

RE_B64     = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])')
RE_B64_URL = re.compile(r'(?<![A-Za-z0-9\-_])[A-Za-z0-9\-_]{16,}={0,2}(?![A-Za-z0-9\-_])')

def _autopad(s: str) -> str:
    # pad to a multiple of 4
    m = len(s) % 4
    return s if m == 0 else s + "=" * (4 - m)

def _decode_once(s: str) -> List[Tuple[str, bytes]]:
    outs=[]
    # hex (only if sane)
    try:
        if all(c in string.hexdigits for c in s) and len(s)%2==0:
            outs.append(("hex", bytes.fromhex(s)))
    except Exception:
        pass
    # b64/b32/a85/b85
    for name, fn in [
        ("base64", base64.b64decode),
        ("urlsafe_b64", base64.urlsafe_b64decode),
        ("base32", base64.b32decode),
        ("a85", base64.a85decode),
        ("b85", base64.b85decode),
    ]:
        try:
            outs.append((name, fn(_autopad(s))))
        except Exception:
            continue
    return outs

def _to_text(b: bytes) -> str | None:
    try:
        t = b.decode("utf-8", errors="ignore")
        if t and is_mostly_printable(t): return t
    except Exception:
        pass
    return None

def _scan_tokens(s: str, min_len: int = 16, allow_urlsafe: bool = True) -> List[Tuple[str, int, int, str]]:
    """
    Returns list of (kind, start, end, token)
      kind ∈ {"b64","b64url"}
    """
    tokens = []
    for m in RE_B64.finditer(s):
        if (m.end()-m.start()) >= min_len:
            tokens.append(("b64", m.start(), m.end(), m.group(0)))
    if allow_urlsafe:
        for m in RE_B64_URL.finditer(s):
            if (m.end()-m.start()) >= min_len:
                tokens.append(("b64url", m.start(), m.end(), m.group(0)))
    return tokens

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - nested_passes: int (default 1)
      - budget_s: float (default 5.0)
      - scan_substrings: bool (default true)
      - min_token_len: int (default 16)
      - allow_urlsafe: bool (default true)
      - text_to_decipher: optional override with '%c'
    """
    import time
    nested = max(0, int(config.get("nested_passes", 1)))
    budget_s = float(config.get("budget_s", 5.0))
    scan_sub = bool(config.get("scan_substrings", True))
    min_len  = int(config.get("min_token_len", 16))
    allow_u  = bool(config.get("allow_urlsafe", True))

    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    results: List[Candidate] = []
    started = time.monotonic()

    def add_candidate(path: str, t: str):
        score = fitness(t)
        # If mostly letters and minimal weird symbols, add confidence bonus
        letters = sum(ch.isalpha() for ch in t); n = max(1, len(t))
        others = sum(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:;!?/|()[]{}'\"\\"
                     for ch in t)
        if letters/n >= 0.70 and others/n <= 0.08:
            score += 1.5
        results.append(Candidate("base", f"path={path}", t, score))

    # 1) Try whole-string decodes (what you already had)
    for name, b in _decode_once(ciphertext.strip()):
        if time.monotonic()-started > budget_s: return results
        t = _to_text(b)
        if t: 
            add_candidate(f"raw->{name}", t)

    # 2) NEW: scan for embedded tokens and decode them
    if scan_sub:
        seen_spans = set()
        for kind, a, b, tok in _scan_tokens(ciphertext, min_len=min_len, allow_urlsafe=allow_u):
            if (a,b) in seen_spans: continue
            seen_spans.add((a,b))

            # Try both std and urlsafe decoders depending on kind
            try_variants = []
            if kind == "b64":
                try_variants = [("base64", base64.b64decode)]
            else:
                try_variants = [("urlsafe_b64", base64.urlsafe_b64decode), ("base64", base64.b64decode)]

            for name, fn in try_variants:
                if time.monotonic()-started > budget_s: return results
                try:
                    out = fn(_autopad(tok))
                    t = _to_text(out)
                    if t:
                        add_candidate(f"scan[{kind}@{a}:{b}]->{name}", t)
                        # nested: try decoding again
                        queue = [(t, f"scan[{kind}@{a}:{b}]->{name}")]
                        for _ in range(nested):
                            next_q=[]
                            for s2, path in queue:
                                if time.monotonic()-started > budget_s: return results
                                for name2, b2 in _decode_once(s2.strip()):
                                    t2 = _to_text(b2)
                                    if t2:
                                        add_candidate(f"{path}->{name2}", t2)
                                        next_q.append((t2, f"{path}->{name2}"))
                            queue = next_q
                except Exception:
                    continue

    return results