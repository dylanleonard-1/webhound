# WebHound — scanner/webhound/threat_intel/brand_impersonation.py
# Phase-13 Task 5: detect domains impersonating known brands —
# typosquatting (edit-distance), homoglyph/IDN confusables, and
# payment/auth-provider impersonation. Pure, offline.
#
# This sharpens the existing domain_classifier brand-lookalike signal
# into an explainable verdict: which brand, what technique, how close.

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import tldextract

# Brands worth protecting, grouped so we can say WHY impersonation of a
# payment vs auth vs general brand matters more.
_PAYMENT_BRANDS = {
    "paypal", "stripe", "braintree", "klarna", "afterpay", "adyen",
    "squareup", "venmo", "wise", "revolut",
}
_AUTH_BRANDS = {
    "okta", "auth0", "onelogin", "duo", "microsoftonline", "google",
    "apple", "clerk", "login",
}
_BANK_BRANDS = {
    "chase", "wellsfargo", "bankofamerica", "citibank", "barclays",
    "hsbc", "coinbase", "binance", "kraken", "metamask",
}
_GENERAL_BRANDS = {
    "amazon", "microsoft", "facebook", "instagram", "netflix", "twitter",
    "linkedin", "ebay", "walmart", "dropbox", "shopify", "icloud", "gmail",
}
_ALL_BRANDS = (_PAYMENT_BRANDS | _AUTH_BRANDS | _BANK_BRANDS | _GENERAL_BRANDS)

# Legitimate registrable domains for the brands — an exact match here is
# NOT impersonation (paypal.com is paypal).
_LEGITIMATE = {
    "paypal.com", "stripe.com", "braintreegateway.com", "klarna.com",
    "afterpay.com", "adyen.com", "squareup.com", "venmo.com", "wise.com",
    "revolut.com", "okta.com", "auth0.com", "onelogin.com", "duo.com",
    "microsoftonline.com", "google.com", "apple.com", "clerk.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "barclays.com", "hsbc.com", "coinbase.com", "binance.com", "kraken.com",
    "metamask.io", "amazon.com", "microsoft.com", "facebook.com",
    "instagram.com", "netflix.com", "twitter.com", "linkedin.com",
    "ebay.com", "walmart.com", "dropbox.com", "icloud.com", "gmail.com",
    "shopify.com", "myshopify.com",
}

# Homoglyph map: visually-confusable characters → their ASCII look-alike.
_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "$": "s", "@": "a", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",  # Cyrillic
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ⅼ": "l",
    "rn": "m",  # classic rn→m
}


class ImpersonationTechnique(str, Enum):
    NONE = "none"
    EXACT_BRAND_OTHER_TLD = "brand_on_other_tld"
    TYPOSQUAT = "typosquat"
    HOMOGLYPH = "homoglyph"
    COMBOSQUAT = "combosquat"          # brand + extra words (paypal-secure-login)


class BrandClass(str, Enum):
    PAYMENT = "payment"
    AUTH = "auth"
    BANK = "bank"
    GENERAL = "general"


@dataclass(frozen=True)
class ImpersonationVerdict:
    is_impersonation: bool
    brand: str | None = None
    brand_class: BrandClass | None = None
    technique: ImpersonationTechnique = ImpersonationTechnique.NONE
    confidence: float = 0.0
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "is_impersonation": self.is_impersonation,
            "brand": self.brand,
            "brand_class": self.brand_class.value if self.brand_class else None,
            "technique": self.technique.value,
            "confidence": round(self.confidence, 3),
            "detail": self.detail,
        }


def _brand_class(brand: str) -> BrandClass:
    if brand in _PAYMENT_BRANDS:
        return BrandClass.PAYMENT
    if brand in _AUTH_BRANDS:
        return BrandClass.AUTH
    if brand in _BANK_BRANDS:
        return BrandClass.BANK
    return BrandClass.GENERAL


def _host(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    if "://" in v:
        return (urlparse(v).hostname or "").lower()
    return v.split("/", 1)[0]


def _deskew(label: str) -> str:
    """Map confusable characters to ASCII so homoglyphs collapse onto the
    brand they imitate. Also NFKD-normalizes unicode."""
    norm = unicodedata.normalize("NFKD", label)
    out = norm
    # Multi-char first (rn→m), then single chars.
    out = out.replace("rn", "m")
    out = "".join(_HOMOGLYPHS.get(ch, ch) for ch in out)
    return out


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def assess_domain(host_or_url: str) -> ImpersonationVerdict:
    """Classify whether *host_or_url* impersonates a known brand."""
    host = _host(host_or_url)
    if not host:
        return ImpersonationVerdict(False)
    ext = tldextract.extract(host)
    registrable = (f"{ext.domain}.{ext.suffix}"
                   if ext.domain and ext.suffix else host)
    label = (ext.domain or "").lower()
    if not label:
        return ImpersonationVerdict(False)

    # Legit brand domain → not impersonation.
    if registrable in _LEGITIMATE:
        return ImpersonationVerdict(False, detail="legitimate brand domain")

    deskewed = _deskew(label)
    flat = re.sub(r"[^a-z0-9]", "", deskewed)

    best: ImpersonationVerdict = ImpersonationVerdict(False)
    for brand in _ALL_BRANDS:
        bclass = _brand_class(brand)
        # 1. Exact brand as the *raw* label on a non-legit registrable
        #    domain (e.g. okta.tk) — no confusables involved.
        if label == brand:
            return ImpersonationVerdict(
                True, brand=brand, brand_class=bclass,
                technique=ImpersonationTechnique.EXACT_BRAND_OTHER_TLD,
                confidence=0.85,
                detail=f"'{brand}' used as domain label on {registrable}")
        # 2. Homoglyph / lookalike: the de-skewed label collapses onto the
        #    brand but the raw label differs (confusables: pаypal, paypa1).
        if (deskewed == brand or flat == brand) and label != brand:
            return ImpersonationVerdict(
                True, brand=brand, brand_class=bclass,
                technique=ImpersonationTechnique.HOMOGLYPH,
                confidence=0.9,
                detail=f"homoglyph/lookalike of '{brand}' ({label})")
        # 3. Combosquat: brand appears as a whole token among others.
        tokens = re.split(r"[^a-z0-9]+", deskewed)
        if brand in tokens and len(tokens) > 1:
            cand = ImpersonationVerdict(
                True, brand=brand, brand_class=bclass,
                technique=ImpersonationTechnique.COMBOSQUAT,
                confidence=0.7,
                detail=f"'{brand}' combined with other words in {label}")
            if cand.confidence > best.confidence:
                best = cand
        # 4. Typosquat: small edit distance to the brand (length-aware).
        if len(brand) >= 5:
            dist = _levenshtein(flat, brand)
            if 0 < dist <= (2 if len(brand) >= 8 else 1):
                cand = ImpersonationVerdict(
                    True, brand=brand, brand_class=bclass,
                    technique=ImpersonationTechnique.TYPOSQUAT,
                    confidence=0.75 if dist == 1 else 0.6,
                    detail=f"typosquat of '{brand}' (edit distance {dist})")
                if cand.confidence > best.confidence:
                    best = cand
    return best
