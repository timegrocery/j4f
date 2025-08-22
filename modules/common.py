# modules/common.py
import string, time, re
from dataclasses import dataclass
from typing import List

LOW, UPP = string.ascii_lowercase, string.ascii_uppercase

def _char_stats(t: str):
    n = len(t)
    letters = sum(ch.isalpha() for ch in t)
    digits  = sum(ch.isdigit() for ch in t)
    spaces  = t.count(' ')
    unders  = t.count('_')
    hyphens = t.count('-')
    others  = n - (letters + digits + spaces + unders + hyphens)
    return n, letters, digits, spaces, unders, hyphens, others

def _charclass_score(t: str) -> float:
    n, letters, digits, spaces, unders, hyphens, others = _char_stats(t)
    if n == 0: return 0.0
    letter_prop = letters / n
    digit_prop  = digits  / n
    other_prop  = others  / n
    score = 0.0
    # Prefer plaintext-like: mostly letters + a bit of separators
    score += letter_prop * 2.2
    score -= digit_prop  * 0.9
    score -= other_prop  * 2.2
    # base64 padding is suspicious outside of base decoders
    if "==" in t: score -= 1.5
    return score

def _control_penalty(t: str) -> float:
    ctrls = sum(((ord(c) < 32) and c not in '\n\t\r') or (ord(c) == 127) for c in t)
    return -min(3.0, ctrls * 0.9)

def _wordness_score(t: str) -> float:
    """
    Tokenize by common flag separators, reward multiple alphabetic words and natural vowels.
    No heavy dictionaries; just structure + vowel share.
    """
    s = t.replace('_',' ').replace('+',' ').replace('-',' ').replace('/',' ')
    toks = re.findall(r"[A-Za-z]{3,}", s)  # words >=3 letters
    if not toks: return 0.0
    vowels = set("aeiouAEIOU")
    # token count matters, and vowels-per-token ~ natural language
    tok_score = len(toks) * 0.8
    vowel_score = 0.0
    for w in toks:
        v = sum(ch in vowels for ch in w) / max(1, len(w))
        # reward vowel ratio around 35–55%
        vowel_score += max(0.0, 1.0 - abs(v - 0.45) / 0.45)
    vowel_score *= 0.5
    return tok_score + vowel_score

def _tail_noise_penalty(t: str) -> float:
    toks = re.findall(r"[A-Za-z0-9\+\-_]+", t)
    if not toks: 
        return 0.0
    last = toks[-1]
    # penalize short, all-caps tails (e.g., 'VV', 'VVV')
    if re.fullmatch(r"[A-Z]{2,5}", last):
        return -1.0
    return 0.0

def _case_boundaries(s: str) -> int:
    # count lower->Upper boundaries, the ones we would split on for camelCase
    return sum(1 for i in range(1, len(s)) if s[i-1].islower() and s[i].isupper())

def _wordness_quick(t: str) -> float:
    # lightweight "does this look like words?" score (no dict)
    # count alpha words (>=3 chars) + vowel reasonableness
    tokens = re.findall(r"[A-Za-z]{3,}", t)
    if not tokens: return 0.0
    vset = set("aeiouAEIOU")
    vowel_part = 0.0
    for w in tokens:
        vr = sum(c in vset for c in w) / max(1, len(w))
        vowel_part += max(0.0, 1.0 - abs(vr - 0.45)/0.45)
    return len(tokens)*0.5 + vowel_part*0.3

def smart_hint(text: str):
    """
    Returns (label, hint) or None.
    label ∈ {'snake','lower'}
    """
    raw = text
    lower = raw.lower()
    snake = snake_from_camel(raw)

    # how "alternating" is it, measured by camel boundaries density?
    boundaries = _case_boundaries(raw)
    density = boundaries / max(1, len(raw))

    # quick readability estimates
    raw_score   = _wordness_quick(lower) + ngram_hits(lower)
    snake_score = _wordness_quick(snake) + ngram_hits(snake)

    # if very alternating (lots of flips), prefer lower; snake would be noisy
    if density > 0.40:  # ~ every other char flips case
        # only show if clearly helps vs raw
        if raw_score >= 0.6:
            return ("lower", lower)
        else:
            return None

    # otherwise it might be true CamelCase; consider snake if it helps
    # also avoid super underscore-y outputs
    if snake.count('_') <= len(snake)//3 and snake_score >= raw_score + 0.2:
        return ("snake", snake)

    # fall back: if lower obviously better than raw
    if raw_score >= 0.6:
        return ("lower", lower)

    return None
    
# ---- Candidate ----
@dataclass
class Candidate:
    algo: str
    params: str
    text: str
    score: float

# ---- English-ish scoring (generic) ----
ENG_FREQ = {
    'A':8.12,'B':1.49,'C':2.71,'D':4.32,'E':12.02,'F':2.30,'G':2.03,'H':5.92,'I':7.31,'J':0.10,'K':0.69,'L':3.98,
    'M':2.61,'N':6.95,'O':7.68,'P':1.82,'Q':0.11,'R':6.02,'S':6.28,'T':9.10,'U':2.88,'V':1.11,'W':2.09,'X':0.17,'Y':2.11,'Z':0.07
}
BIGRAMS = set("th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro".split())
TRIGRAMS = set("the and ing her hat his tha ere for ent ion ter you thi not are all wit ver".split())
TETRA = set("TION ATIO NTHE THED THAT THER HERE ETHE".split())

def is_mostly_printable(s: str, thresh: float=0.9) -> bool:
    printable = set(string.printable)
    good = sum(1 for ch in s if ch in printable)
    return (good / max(1, len(s))) >= thresh

def chi_square_english(t: str) -> float:
    tU = [ch for ch in t.upper() if 'A' <= ch <= 'Z']
    total = len(tU)
    if total == 0: return 0.0
    counts = {c:0 for c in string.ascii_uppercase}
    for ch in tU: counts[ch]+=1
    chi=0.0
    for c, exp_pct in ENG_FREQ.items():
        exp = total * (exp_pct/100.0)
        obs = counts[c]
        if exp>0: chi += (obs-exp)**2/exp
    return 1.0/(1.0+chi)

def index_of_coincidence(t: str) -> float:
    tU = [ch for ch in t.upper() if 'A'<=ch<='Z']
    n=len(tU)
    if n<2: return 0.0
    counts={c:0 for c in string.ascii_uppercase}
    for ch in tU: counts[ch]+=1
    num=sum(c*(c-1) for c in counts.values())
    den=n*(n-1)
    ic=num/den
    target=0.066
    return max(0.0, 1.0-abs(ic-target)/0.066)

def ngram_hits(t: str) -> float:
    tl=t.lower(); n=len(tl)
    b=sum(1 for i in range(n-1) if tl[i:i+2] in BIGRAMS)
    tr=sum(1 for i in range(n-2) if tl[i:i+3] in TRIGRAMS)
    tt=sum(1 for i in range(n-3) if tl[i:i+4] in TETRA)
    return b*0.6 + tr*1.0 + tt*1.5

def snake_from_camel(s: str) -> str:
    out=[]
    for i,ch in enumerate(s):
        if i>0 and s[i-1].islower() and ch.isupper(): out.append('_')
        out.append(ch)
    return "".join(out).lower()

def fitness(t: str) -> float:
    # Base language signals
    chi  = chi_square_english(t)
    ic   = index_of_coincidence(t)
    ngr  = ngram_hits(t)
    cls  = _charclass_score(t)
    wrd  = _wordness_score(t)
    ctlp = _control_penalty(t)

    n = len(t)
    # Length factor: short strings shouldn't dominate. Saturate at 16 chars.
    len_fac = min(1.0, n / 16.0)

    base = 0.0
    # Scale most metrics by length factor
    base += (chi * 3.0 + ic * 2.5 + ngr * 1.2 + cls * 1.3) * len_fac
    base += wrd * 0.6 * len_fac

    # Small bonus for explicit word separators
    base += (t.count(' ') + t.count('_') + t.count('+')) * 0.15

    # Very short outputs are rarely the answer
    if n < 4:  base -= (4 - n) * 2.0
    if n <= 2: base -= 4.0

    # Control characters are a strong negative signal
    base += ctlp

    # Downweight non-printables overall
    if not is_mostly_printable(t):
        base *= 0.6

    # CamelCase helper stays as a side-signal (split to snake and re-score n-grams lightly)
    snake = snake_from_camel(t)
    if snake != t.lower():
        base += ngram_hits(snake) * 0.6 * len_fac

    base += _tail_noise_penalty(t)
    return base

def dedupe_and_rank(cands: List[Candidate]) -> List[Candidate]:
    best = {}
    for c in cands:
        key = c.text
        if key not in best or c.score > best[key].score:
            best[key] = c
    ranked = sorted(best.values(), key=lambda x: x.score, reverse=True)
    return ranked

# ---- tiny char ops used by multiple modules ----
def shift_char(ch: str, k: int) -> str:
    if ch.islower(): return LOW[(LOW.index(ch)+k)%26]
    if ch.isupper(): return UPP[(UPP.index(ch)+k)%26]
    return ch

def atbash_char(ch: str) -> str:
    if ch.islower(): return LOW[25-LOW.index(ch)]
    if ch.isupper(): return UPP[25-UPP.index(ch)]
    return ch

def fitness(t: str) -> float:
    base = 0.0
    base += chi_square_english(t) * 3.0
    base += index_of_coincidence(t) * 2.5
    base += ngram_hits(t) * 1.2
    base += _charclass_score(t) * 1.3   # <--- add this
    snake = snake_from_camel(t)
    if snake != t.lower(): base += ngram_hits(snake) * 0.8
    base += (t.count(' ')+t.count('_')) * 0.1
    if not is_mostly_printable(t): base *= 0.5
    return base