# modules/common.py
import string, time
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
    # Prefer plaintext-like: mostly letters and a bit of space/underscore/hyphen
    score += letter_prop * 2.2
    score -= digit_prop  * 0.9
    score -= other_prop  * 2.2
    # Base64 padding in non-base contexts is a red flag
    if "==" in t: score -= 0.8
    return score

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
    base = 0.0
    base += chi_square_english(t) * 3.0
    base += index_of_coincidence(t) * 2.5
    base += ngram_hits(t) * 1.2
    snake = snake_from_camel(t)
    if snake != t.lower(): base += ngram_hits(snake) * 0.8
    base += (t.count(' ')+t.count('_')) * 0.1
    if not is_mostly_printable(t): base *= 0.5
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
    base += _charclass_score(t) * 1.3   # <-- NEW: character-class weighting
    snake = snake_from_camel(t)
    if snake != t.lower(): base += ngram_hits(snake) * 0.8
    base += (t.count(' ')+t.count('_')) * 0.1
    if not is_mostly_printable(t): base *= 0.5
    return base