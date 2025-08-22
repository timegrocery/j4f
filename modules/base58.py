# modules/base58.py
from typing import List, Tuple
from .common import Candidate, fitness, is_mostly_printable
import string, re, unicodedata, time, hashlib, base64
from collections import Counter
from itertools import combinations

ALPHABETS = {
    "bitcoin": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "ripple":  "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
    "flickr":  "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
}

B58_STD = ALPHABETS["bitcoin"]
allowed = re.escape(B58_STD)

# Detect base58-looking substrings (shorter min to catch small chunks)
RE_B58 = re.compile(rf'(?<![{allowed}])[{allowed}]{{8,}}(?![{allowed}])')

ALLOWED_PRINT = " _-.,:;!?/|()[]{}'\"\\"

def _normalize(s: str) -> str:
    t = unicodedata.normalize("NFKC", s)
    return t.replace("\u200b","").replace("\u200c","").replace("\u200d","").strip()

def _strip_to_allowed(s: str, allowed: set) -> str:
    return ''.join(ch for ch in s if ch in allowed)

# ---------- base58 decode helpers ----------
def b58_decode_to_bytes(s: str, alphabet: str) -> bytes:
    """
    Pure-Python Base58 decode (no padding). Handles leading-zeros via '1' prefix in bitcoin alphabet.
    """
    if not s:
        return b""
    # map char -> value
    try:
        base = len(alphabet)
        charmap = {c: i for i, c in enumerate(alphabet)}
        num = 0
        for ch in s:
            num = num * base + charmap[ch]  # KeyError if invalid char
        # convert to big-endian bytes
        full = []
        while num > 0:
            num, rem = divmod(num, 256)
            full.append(rem)
        full = bytes(reversed(full))
        # handle leading zeros (represented by leading '1' in bitcoin alphabet)
        zeros = 0
        for ch in s:
            if ch == alphabet[0]:
                zeros += 1
            else:
                break
        return b'\x00' * zeros + full
    except Exception:
        # treat any invalid character as failure
        raise

def b58check_strip_and_verify(raw: bytes) -> Tuple[bool, bytes]:
    """
    Base58Check: [payload][4-byte checksum] where checksum = first 4 of double SHA-256(payload)
    Returns (is_valid, payload_without_checksum)
    """
    if len(raw) < 5:
        return (False, raw)
    payload, checksum = raw[:-4], raw[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return (checksum == calc, payload)

# ---------- tiny base64 nested (optional) ----------
def _maybe_nested_base64(s: str) -> List[str]:
    """
    If s looks base64-ish, try base64 and urlsafe_b64 decode once and return printable texts.
    """
    outs = []
    s_stripped = s.strip()
    if not s_stripped:
        return outs
    # quick shape check
    if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', s_stripped) or re.fullmatch(r'[A-Za-z0-9\-_]{8,}={0,2}', s_stripped):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                pad = (-len(s_stripped)) % 4
                t = fn(s_stripped + ("=" * pad)).decode("utf-8", errors="ignore")
                if t and is_mostly_printable(t):
                    outs.append(t)
            except Exception:
                continue
    return outs

# ---------- scoring tweaks ----------
def _module_bonus(t: str) -> float:
    # small Occam bonus for clean plaintext
    n = len(t)
    if n == 0: return 0.0
    letters = sum(ch.isalpha() for ch in t)
    others  = sum(not (ch.isalnum() or ch in ALLOWED_PRINT) for ch in t)
    lp = letters / n
    op = others  / n
    if lp >= 0.75 and op <= 0.05: return 1.4
    if lp >= 0.60 and op <= 0.10: return 0.7
    return 0.2

def _path_penalty(path: str) -> float:
    # Favor raw/simple; penalize heavy salvage or deep nesting
    if path.startswith("raw->"): return 0.0
    pen = 0.0
    if "keep_" in path: pen += 0.30
    if "rm_" in path:   pen += 1.10
    if "nested_b64" in path: pen += 0.50
    return pen

def _add_candidate(results: List[Candidate], path: str, t: str, drop_ratio: float = 0.0):
    sc = fitness(t) + _module_bonus(t) - min(2.0, drop_ratio * 3.0) - _path_penalty(path)
    results.append(Candidate("base58", f"path={path}", t, sc))

# ---------- main run ----------
def run(ciphertext: str, config: dict) -> List[Candidate]:
    """
    config:
      - alphabets: ["bitcoin","ripple","flickr"] (default ["bitcoin"])
      - check_modes: ["none","b58check"] (default ["none","b58check"])
      - nested_passes: int (default 1)   # try base64 on decoded text if it looks b64-ish
      - budget_s: float (default 5.0)
      - scan_substrings: bool (default true)
      - min_token_len: int (default 10)  # min length for regex token capture
      - aggressive_salvage: bool (default true)
      - periodic_max_k: int (default 6)
      - min_plain_len: int (default 6)   # don't keep ultra-short plaintexts
      - text_to_decipher: optional; if present, overrides ciphertext (supports '%c')
    """
    nested = max(0, int(config.get("nested_passes", 1)))
    budget_s = float(config.get("budget_s", 5.0))
    scan_sub = bool(config.get("scan_substrings", True))
    min_len  = int(config.get("min_token_len", 10))
    aggressive = bool(config.get("aggressive_salvage", True))
    periodic_max_k = int(config.get("periodic_max_k", 6))
    min_plain_len = int(config.get("min_plain_len", 6))
    alphs = config.get("alphabets", ["bitcoin"]) or ["bitcoin"]
    check_modes = config.get("check_modes", ["none","b58check"])

    text_override = config.get("text_to_decipher")
    if isinstance(text_override, str):
        ciphertext = text_override.replace("%c", ciphertext)

    started = time.monotonic()
    def time_up() -> bool: return (time.monotonic() - started) > budget_s

    src = _normalize(ciphertext)
    results: List[Candidate] = []
    tried_strings = set()

    def to_text_or_none(b: bytes) -> str | None:
        try:
            t = b.decode("utf-8", errors="ignore")
            if t and len(t.strip()) >= min_plain_len and is_mostly_printable(t):
                return t
        except Exception:
            pass
        return None

    def try_decode_b58_token(tok: str, tag: str):
        # Try all alphabets and check modes
        for aname in alphs:
            alphabet = ALPHABETS.get(aname, B58_STD)
            try:
                raw = b58_decode_to_bytes(tok, alphabet)
            except Exception:
                continue

            # plain bytes -> printable?
            plain = to_text_or_none(raw)
            if plain:
                _add_candidate(results, f"{tag}|{aname}", plain, 0.0)
                # nested base64 if looks b64ish
                nest = _maybe_nested_base64(plain)
                for ntxt in nest[:nested]:
                    _add_candidate(results, f"{tag}|{aname}|nested_b64", ntxt, 0.0)

            # Base58Check: verify and strip checksum
            if "b58check" in check_modes:
                ok, payload = b58check_strip_and_verify(raw)
                if ok:
                    plain2 = to_text_or_none(payload)
                    if plain2:
                        _add_candidate(results, f"{tag}|{aname}|b58check", plain2, 0.0)
                        nest2 = _maybe_nested_base64(plain2)
                        for ntxt in nest2[:nested]:
                            _add_candidate(results, f"{tag}|{aname}|b58check|nested_b64", ntxt, 0.0)

    # 1) Whole string (raw/repair/keep-only)
    if not time_up():
        s = src
        if s not in tried_strings:
            tried_strings.add(s)
            try_decode_b58_token(s, "raw")

        # keep-only allowed (std alphabet)
        keep = _strip_to_allowed(s, allowed)
        if len(keep) >= min_len and keep not in tried_strings:
            tried_strings.add(keep)
            drop_ratio = 1.0 - (len(keep)/max(1,len(s)))
            try_decode_b58_token(keep, f"keep_std(drop={drop_ratio:.2f})")

    # 2) Aggressive salvage (periodic deletions + top non-base char removals)
    if aggressive and not time_up():
        # remove most common non-base chars (up to 2)
        nonbase = [c for c in src if c not in allowed and not c.isspace()]
        for ch, _cnt in Counter(nonbase).most_common(2):
            cleaned = src.replace(ch, "")
            keep2 = _strip_to_allowed(cleaned, allowed)
            if len(keep2) >= min_len and keep2 not in tried_strings:
                tried_strings.add(keep2)
                drop_ratio = 1.0 - (len(keep2)/max(1,len(src)))
                try_decode_b58_token(keep2, f"rm[{repr(ch)}](drop={drop_ratio:.2f})")

        # periodic deletions (k=2..periodic_max_k), all phases
        n = len(src)
        for k in range(2, max(3, periodic_max_k + 1)):
            if time_up(): break
            for phase in range(k):
                cleaned = ''.join(ch for i, ch in enumerate(src) if i % k != phase)
                keep3 = _strip_to_allowed(cleaned, allowed)
                if len(keep3) >= min_len and keep3 not in tried_strings:
                    tried_strings.add(keep3)
                    drop_ratio = 1.0 - (len(keep3)/max(1,len(src)))
                    try_decode_b58_token(keep3, f"rm_periodic(k={k},ph={phase},drop={drop_ratio:.2f})")

    # 3) Substring scan
    if scan_sub and not time_up():
        seen = set()
        for m in RE_B58.finditer(src):
            a, b = m.start(), m.end()
            if (a, b) in seen: continue
            seen.add((a, b))
            tok = m.group(0)
            try_decode_b58_token(tok, f"scan[{a}:{b}]")

    return results
