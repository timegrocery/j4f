# modules/base64.py
from typing import List, Tuple
from .common import Candidate, fitness, is_mostly_printable
import base64, string, re, unicodedata, time
from collections import Counter
from itertools import combinations

# Regex for embedded tokens (shorter to catch small chunks)
RE_B64     = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])')
RE_B64_URL = re.compile(r'(?<![A-Za-z0-9\-_])[A-Za-z0-9\-_]{8,}={0,2}(?![A-Za-z0-9\-_])')

B64_ALLOWED_STD  = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
B64_ALLOWED_URL  = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
ALLOWED_PRINT    = " _-.,:;!?/|()[]{}'\"\\"
MIN_PLAIN_LEN = 6

def _path_penalty(path: str) -> float:
    # Favor raw/simple paths; penalize heavy salvage/nesting
    if path.startswith("raw->"): 
        return 0.0
    pen = 0.0
    if "keep_" in path:         pen += 0.40
    if "rm_" in path:           pen += 1.20   # any removal is suspect
    if "->base64->" in path:    pen += 0.60   # nested decodes
    if "->a85" in path or "->b85" in path:
                                 pen += 0.60
    return pen

def _autopad(s: str) -> str:
    m = len(s) % 4
    return s if m == 0 else s + "=" * (4 - m)

def _decode_once(s: str) -> List[Tuple[str, bytes]]:
    outs=[]
    # Hex
    try:
        if all(c in string.hexdigits for c in s) and len(s)%2==0:
            outs.append(("hex", bytes.fromhex(s)))
    except Exception:
        pass
    # Base families (be permissive with padding)
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

def _to_text(b: bytes, *, min_len: int = MIN_PLAIN_LEN) -> str | None:
    try:
        t = b.decode("utf-8", errors="ignore")
        # reject too-short outputs (common false positives)
        if not t or len(t.strip()) < min_len:
            return None
        # keep printable only
        from .common import is_mostly_printable
        if is_mostly_printable(t):
            return t
    except Exception:
        pass
    return None

def _module_bonus(t: str) -> float:
    # Occam bonus for clean plaintext
    n = len(t)
    if n == 0: return 0.0
    letters = sum(ch.isalpha() for ch in t)
    others  = sum(not (ch.isalnum() or ch in ALLOWED_PRINT) for ch in t)
    lp = letters / n
    op = others  / n
    if lp >= 0.75 and op <= 0.05: return 1.6
    if lp >= 0.60 and op <= 0.10: return 0.9
    return 0.3

# Repairs for obfuscated tokens (leet/punctuation/unicode)
_REPAIRS = {'|':'I','!':'I','$':'S','@':'A','€':'E','£':'L','—':'-','–':'-','·':'.'}

def _normalize(s: str) -> str:
    t = unicodedata.normalize("NFKC", s)
    return t.replace("\u200b","").replace("\u200c","").replace("\u200d","").strip()

def _repair_variants(tok: str) -> List[str]:
    t = _normalize(tok)
    variants = {t}
    t2 = ''.join(_REPAIRS.get(ch, ch) for ch in t)
    variants.add(t2)
    variants.add(t2.replace('-', '+').replace('_', '/'))  # to std
    variants.add(t2.replace('+', '-').replace('/', '_'))  # to url
    return list(variants)

def _strip_to_allowed(s: str, allowed: set) -> str:
    return ''.join(ch for ch in s if ch in allowed)

def _scan_tokens(s: str, min_len: int = 12, allow_urlsafe: bool = True):
    tokens = []
    for m in RE_B64.finditer(s):
        if (m.end()-m.start()) >= min_len:
            tokens.append(("b64", m.start(), m.end(), m.group(0)))
    if allow_urlsafe:
        for m in RE_B64_URL.finditer(s):
            if (m.end()-m.start()) >= min_len:
                tokens.append(("b64url", m.start(), m.end(), m.group(0)))
    return tokens

def _add_candidate(results, path: str, t: str, drop_ratio: float = 0.0):
    sc = fitness(t) + _module_bonus(t) - min(2.0, drop_ratio * 3.0) - _path_penalty(path)
    results.append(Candidate("base", f"path={path}", t, sc))

# ---- NEW: aggressive salvage helpers ----
def _top_digits(s: str, k: int = 3) -> List[str]:
    cnt = Counter(ch for ch in s if ch.isdigit())
    return [d for d,_ in cnt.most_common(k)]

def _top_alnum_ngrams_with_digit(s: str, n: int, topk: int = 6) -> List[str]:
    # collect n-grams that are [A-Za-z0-9]{n} and contain at least 1 digit and 1 letter
    cand = Counter()
    for i in range(len(s)-n+1):
        g = s[i:i+n]
        if all(c.isalnum() for c in g) and any(c.isdigit() for c in g) and any(c.isalpha() for c in g):
            cand[g] += 1
    return [g for g,_ in cand.most_common(topk)]

def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - nested_passes: int (default 1)
      - budget_s: float (default 5.0)
      - scan_substrings: bool (default true)
      - min_token_len: int (default 12)
      - allow_urlsafe: bool (default true)
      - aggressive_salvage: bool (default true)
      - periodic_max_k: int (default 6)
      - digit_combo_k: int (default 2)      # NEW: remove top-k digits at once
      - kgram_lengths: [2,3]                # NEW: alnum n-gram removal lengths
      - kgram_topk: int (default 6)         # NEW: how many frequent n-grams to try
      - text_to_decipher: optional override with '%c'
    """
    nested = max(0, int(config.get("nested_passes", 1)))
    budget_s = float(config.get("budget_s", 5.0))
    scan_sub = bool(config.get("scan_substrings", True))
    min_len  = int(config.get("min_token_len", 12))
    allow_u  = bool(config.get("allow_urlsafe", True))
    aggressive = bool(config.get("aggressive_salvage", True))
    periodic_max_k = int(config.get("periodic_max_k", 6))
    digit_combo_k = int(config.get("digit_combo_k", 2))
    kgram_lengths = list(map(int, config.get("kgram_lengths", [2,3])))
    kgram_topk = int(config.get("kgram_topk", 6))

    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    results: List[Candidate] = []
    started = time.monotonic()
    src = _normalize(ciphertext)

    def time_up() -> bool:
        return (time.monotonic() - started) > budget_s

    def try_decode_string(s: str, path: str, drop_ratio: float = 0.0):
        for name, b in _decode_once(s):
            if time_up(): return
            plain = _to_text(b, min_len=int(config.get("min_plain_len", MIN_PLAIN_LEN)))
            if plain:
                _add_candidate(results, path, plain, drop_ratio)
                # nested passes
                queue = [(plain, f"{path}->{name}")]
                for _ in range(nested):
                    if time_up(): return
                    next_q=[]
                    for s2, p2 in queue:
                        for name2, b2 in _decode_once(s2.strip()):
                            t2 = _to_text(b2)
                            if t2:
                                _add_candidate(results, f"{p2}->{name2}", t2, drop_ratio)
                                next_q.append((t2, f"{p2}->{name2}"))
                    queue = next_q

    # ---------- 1) Whole-string attempts ----------
    tried = set()

    # (a) normalized + repaired variants
    for tok in _repair_variants(src):
        if time_up(): return results
        if tok in tried: continue
        tried.add(tok)
        try_decode_string(tok, "raw")

    # (b) strip to allowed (std/url)
    for allowed, tag in [(B64_ALLOWED_STD, "keep_std"), (B64_ALLOWED_URL, "keep_url")]:
        stripped = _strip_to_allowed(src, allowed)
        if len(stripped) >= min_len and stripped not in tried:
            tried.add(stripped)
            drop_ratio = 1.0 - (len(stripped)/max(1,len(src)))
            try_decode_string(stripped, tag, drop_ratio)

    # (c) digit deletions and periodic deletions (existing aggressive salvage)
    if aggressive and not time_up():
        # Single-digit deletions (as before, threshold >=3)
        cnt = Counter(ch for ch in src if ch.isdigit())
        for digit, dc in cnt.most_common(10):
            if time_up(): break
            if dc < 3: break
            cleaned = src.replace(digit, "")
            for allowed, tag in [(B64_ALLOWED_STD, "rm_digit_std"), (B64_ALLOWED_URL, "rm_digit_url")]:
                stripped = _strip_to_allowed(cleaned, allowed)
                if len(stripped) >= min_len and stripped not in tried:
                    tried.add(stripped)
                    drop_ratio = 1.0 - (len(stripped)/max(1,len(src)))
                    try_decode_string(stripped, f"{tag}[{digit!r}]", drop_ratio)

        # NEW: top-K digit COMBOS (remove both, e.g., '2' and '9')
        if not time_up():
            digs = _top_digits(src, k=3)
            for r in range(2, min(digit_combo_k, len(digs)) + 1):
                for combo in combinations(digs, r):
                    if time_up(): break
                    cleaned = src
                    for d in combo:
                        cleaned = cleaned.replace(d, "")
                    for allowed, tag in [(B64_ALLOWED_STD, "rm_dcombo_std"), (B64_ALLOWED_URL, "rm_dcombo_url")]:
                        stripped = _strip_to_allowed(cleaned, allowed)
                        if len(stripped) >= min_len and stripped not in tried:
                            tried.add(stripped)
                            drop_ratio = 1.0 - (len(stripped)/max(1,len(src)))
                            try_decode_string(stripped, f"{tag}[{''.join(combo)}]", drop_ratio)

        # Periodic deletions
        if not time_up():
            n = len(src)
            for k in range(2, max(3, periodic_max_k+1)):
                if time_up(): break
                for phase in range(k):
                    cleaned = ''.join(ch for i,ch in enumerate(src) if i % k != phase)
                    for allowed, tag in [(B64_ALLOWED_STD, "rm_periodic_std"), (B64_ALLOWED_URL, "rm_periodic_url")]:
                        stripped = _strip_to_allowed(cleaned, allowed)
                        if len(stripped) >= min_len and stripped not in tried:
                            tried.add(stripped)
                            drop_ratio = 1.0 - (len(stripped)/max(1,len(src)))
                            try_decode_string(stripped, f"{tag}[k={k},ph={phase}]", drop_ratio)

        # NEW: mixed alnum n-gram removal (lengths = 2 and/or 3) that include digits
        if not time_up():
            for nlen in kgram_lengths:
                grams = _top_alnum_ngrams_with_digit(src, n=nlen, topk=kgram_topk)
                for g in grams:
                    if time_up(): break
                    cleaned = src.replace(g, "")
                    for allowed, tag in [(B64_ALLOWED_STD, "rm_kgram_std"), (B64_ALLOWED_URL, "rm_kgram_url")]:
                        stripped = _strip_to_allowed(cleaned, allowed)
                        if len(stripped) >= min_len and stripped not in tried:
                            tried.add(stripped)
                            drop_ratio = 1.0 - (len(stripped)/max(1,len(src)))
                            try_decode_string(stripped, f"{tag}[{g!r}]", drop_ratio)

    # ---------- 2) Substring scan (regex) with repair variants ----------
    if scan_sub and not time_up():
        seen_spans = set()
        for kind, a, b, tok in _scan_tokens(src, min_len=min_len, allow_urlsafe=allow_u):
            if (a,b) in seen_spans: continue
            seen_spans.add((a,b))
            decoder_sets = [("base64", base64.b64decode), ("urlsafe_b64", base64.urlsafe_b64decode)]
            prefer = decoder_sets if kind == "b64url" else decoder_sets[::-1]
            for repaired in _repair_variants(tok):
                for name, fn in prefer:
                    if time_up(): return results
                    try:
                        out = fn(_autopad(repaired))
                        t = _to_text(out)
                        if t:
                            _add_candidate(results, f"scan[{kind}@{a}:{b}]->{name}", t)
                            # nested passes
                            queue = [(t, f"scan[{kind}@{a}:{b}]->{name}")]
                            for _ in range(nested):
                                if time_up(): return results
                                next_q=[]
                                for s2, path in queue:
                                    for name2, b2 in _decode_once(s2.strip()):
                                        t2 = _to_text(b2)
                                        if t2:
                                            _add_candidate(results, f"{path}->{name2}", t2)
                                            next_q.append((t2, f"{path}->{name2}"))
                                queue = next_q
                    except Exception:
                        continue

    return results
