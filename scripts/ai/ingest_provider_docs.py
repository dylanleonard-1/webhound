#!/usr/bin/env python3
"""Phase 6D — Official provider/platform documentation ingestion.

Creates SUMMARIZED detection-relevant notes from official provider docs.
NOT a verbatim mirror — extracts security/WAF/DNS/rate-limiting/deployment facts
only. Each provider's ToS and copyright is respected: link + extracted facts.

Providers (priority order):
  Priority 1 (WebHound stack): Cloudflare, Vercel, Railway
  Priority 2 (hosting):        Netlify, Render, Fly.io
  Priority 3 (enterprise WAF): AWS CloudFront/WAF, Azure Front Door, GCP Armor,
                                Fastly, Akamai, Imperva, Sucuri
  Priority 4 (integrations):   Stripe, Resend, GitHub, Google OAuth

Usage:
  GITHUB_TOKEN=$(gh auth token) python scripts/ai/ingest_provider_docs.py run
  python scripts/ai/ingest_provider_docs.py run --dry-run
  python scripts/ai/ingest_provider_docs.py query "cloudflare WAF challenge"
  python scripts/ai/ingest_provider_docs.py selftest
"""
from __future__ import annotations
import argparse, hashlib, json, math, os, re, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
INGEST_STAMP = "2026-06-13"
MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
PROV_NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "provider-docs")
NOTES_DIR     = os.path.join(ROOT, "knowledge", "provider-docs")
CHUNKS_PATH   = os.path.join(PROV_NORM_DIR, "provider_chunks.jsonl")
USER_AGENT = "WebHound-KnowledgeIngest/6D (+https://webhoundsecurity.com)"
HTTP_TIMEOUT = 25
MAX_PAGE_BYTES = 250_000   # skip pages larger than this
MAX_EXTRACT_CHARS = 6_000  # max extracted chars to keep per page (not a mirror)
CHUNK_TARGET = 1400
CHUNK_MIN = 180
STOP = set((
    "a an the is are was were of to and or in on for with not no this that it "
    "as by be at from we you your our can will may should if then so "
    "what which who whom where when how why help helps document documents "
    "explain explains teach teaches relevant most more used use using work does do "
    "about into via per best useful section page click see also"
).split())
TAG_BONUS = 8.0

# ---------------------------------------------------------------------------
# Provider configs
# ---------------------------------------------------------------------------
PROVIDERS = [
  # ── Priority 1: WebHound stack ──────────────────────────────────────────
  { "slug": "cloudflare",
    "name": "Cloudflare", "tier": "A",
    "terms": "https://www.cloudflare.com/website-terms/",
    "terms_note": "Developer docs are publicly available; ingesting factual summary only.",
    "tags": ["cloudflare","waf","cdn","dns","rate-limiting","challenge-page",
             "bot-protection","ip-allowlisting","provider-context"],
    "pages": [
      ("https://developers.cloudflare.com/llms.txt",
       "Cloudflare Developers — LLM index"),
      ("https://developers.cloudflare.com/waf/",
       "Cloudflare WAF overview"),
      ("https://developers.cloudflare.com/waf/custom-rules/",
       "Cloudflare WAF custom rules"),
      ("https://developers.cloudflare.com/waf/rate-limiting-rules/",
       "Cloudflare WAF rate limiting rules"),
      ("https://developers.cloudflare.com/bots/",
       "Cloudflare bot management"),
      ("https://developers.cloudflare.com/turnstile/",
       "Cloudflare Turnstile CAPTCHA"),
      ("https://developers.cloudflare.com/cache/",
       "Cloudflare cache overview"),
      ("https://developers.cloudflare.com/dns/",
       "Cloudflare DNS overview"),
      ("https://developers.cloudflare.com/ssl/",
       "Cloudflare SSL/TLS overview"),
    ],
  },
  { "slug": "vercel",
    "name": "Vercel", "tier": "A",
    "terms": "https://vercel.com/legal/privacy-policy",
    "terms_note": "Docs are publicly available; ingesting factual summary only.",
    "tags": ["vercel","deployment-protection","preview-deployments","firewall",
             "headers","edge-network","provider-context"],
    "pages": [
      ("https://vercel.com/docs/security",
       "Vercel security overview"),
      ("https://vercel.com/docs/security/vercel-firewall",
       "Vercel firewall"),
      ("https://vercel.com/docs/deployment-protection",
       "Vercel deployment protection"),
      ("https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation",
       "Vercel protection bypass automation"),
      ("https://vercel.com/docs/deployments/preview-deployments",
       "Vercel preview deployments"),
      ("https://vercel.com/docs/headers",
       "Vercel response headers"),
      ("https://vercel.com/docs/edge-network",
       "Vercel edge network / caching"),
    ],
  },
  { "slug": "railway",
    "name": "Railway", "tier": "A",
    "terms": "https://railway.com/legal/terms",
    "terms_note": "Docs are publicly available; ingesting factual summary only.",
    "tags": ["railway","public-networking","custom-domains","healthchecks",
             "variables","deployments","provider-context"],
    "pages": [
      ("https://docs.railway.com/",
       "Railway docs overview"),
      ("https://docs.railway.com/guides/public-networking",
       "Railway public networking + custom domains"),
      ("https://docs.railway.com/guides/healthchecks",
       "Railway health checks"),
      ("https://docs.railway.com/guides/variables",
       "Railway environment variables"),
      ("https://docs.railway.com/guides/deployments",
       "Railway deployments"),
    ],
  },
  # ── Priority 2: Common hosting ───────────────────────────────────────────
  { "slug": "netlify",
    "name": "Netlify", "tier": "A",
    "terms": "https://www.netlify.com/legal/terms-of-use/",
    "terms_note": "Docs are publicly available; ingesting factual summary only.",
    "tags": ["netlify","custom-domains","https-ssl","headers","redirects",
             "deploy-previews","provider-context"],
    "pages": [
      ("https://docs.netlify.com/",
       "Netlify docs overview"),
      ("https://docs.netlify.com/domains-https/custom-domains/",
       "Netlify custom domains"),
      ("https://docs.netlify.com/routing/headers/",
       "Netlify response headers"),
      ("https://docs.netlify.com/routing/redirects/",
       "Netlify redirects"),
      ("https://docs.netlify.com/site-deploys/deploy-previews/",
       "Netlify deploy previews"),
    ],
  },
  { "slug": "render",
    "name": "Render", "tier": "A",
    "terms": "https://render.com/terms",
    "terms_note": "Docs are publicly available; ingesting factual summary only.",
    "tags": ["render","web-services","custom-domains","healthchecks","deploys",
             "private-services","provider-context"],
    "pages": [
      ("https://docs.render.com/",
       "Render docs overview"),
      ("https://docs.render.com/web-services",
       "Render web services"),
      ("https://docs.render.com/custom-domains",
       "Render custom domains"),
      ("https://docs.render.com/deploys",
       "Render deploys and health checks"),
    ],
  },
  { "slug": "flyio",
    "name": "Fly.io", "tier": "A",
    "terms": "https://fly.io/legal/terms-of-service/",
    "terms_note": "Docs are publicly available; ingesting factual summary only.",
    "tags": ["flyio","networking","custom-domain","secrets","machines",
             "health-checks","provider-context"],
    "pages": [
      ("https://fly.io/docs/",
       "Fly.io docs overview"),
      ("https://fly.io/docs/networking/",
       "Fly.io networking overview"),
      ("https://fly.io/docs/networking/custom-domain/",
       "Fly.io custom domains"),
      ("https://fly.io/docs/reference/configuration/",
       "Fly.io app configuration (health checks, services)"),
    ],
  },
  # ── Priority 3: Enterprise WAF/CDN ───────────────────────────────────────
  { "slug": "aws-cloudfront",
    "name": "AWS CloudFront", "tier": "A",
    "terms": "https://aws.amazon.com/legal/",
    "terms_note": "AWS docs are publicly available; ingesting factual summary only.",
    "tags": ["aws","cloudfront","cdn","caching","headers","custom-error-pages",
             "provider-context"],
    "pages": [
      ("https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html",
       "AWS CloudFront introduction"),
      ("https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/add-origin-custom-headers.html",
       "AWS CloudFront custom headers"),
      ("https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html",
       "AWS CloudFront caching behavior"),
    ],
  },
  { "slug": "aws-waf",
    "name": "AWS WAF", "tier": "A",
    "terms": "https://aws.amazon.com/legal/",
    "terms_note": "AWS docs are publicly available; ingesting factual summary only.",
    "tags": ["aws","waf","managed-rules","rate-based","web-acl","provider-context"],
    "pages": [
      ("https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html",
       "AWS WAF overview"),
      ("https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html",
       "AWS WAF managed rule groups"),
      ("https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html",
       "AWS WAF rate-based rules"),
    ],
  },
  { "slug": "azure-front-door",
    "name": "Azure Front Door + WAF", "tier": "A",
    "terms": "https://azure.microsoft.com/en-us/support/legal/",
    "terms_note": "Azure docs are publicly available; ingesting factual summary only.",
    "tags": ["azure","front-door","waf","cdn","caching","provider-context"],
    "pages": [
      ("https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview",
       "Azure Front Door overview"),
      ("https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview",
       "Azure WAF on Front Door overview"),
    ],
  },
  { "slug": "google-cloud-armor",
    "name": "Google Cloud Armor", "tier": "A",
    "terms": "https://cloud.google.com/terms/",
    "terms_note": "GCP docs are publicly available; ingesting factual summary only.",
    "tags": ["gcp","cloud-armor","waf","ddos","load-balancing","provider-context"],
    "pages": [
      ("https://cloud.google.com/armor/docs/cloud-armor-overview",
       "Google Cloud Armor overview"),
      ("https://cloud.google.com/cdn/docs/overview",
       "Google Cloud CDN overview"),
    ],
  },
  { "slug": "fastly",
    "name": "Fastly", "tier": "A",
    "terms": "https://www.fastly.com/terms",
    "terms_note": "Fastly docs are publicly available; ingesting factual summary only.",
    "tags": ["fastly","cdn","waf","caching","headers","bot-management",
             "provider-context"],
    "pages": [
      ("https://docs.fastly.com/en/guides/about-fastlys-cdn-service",
       "Fastly CDN basics"),
      ("https://docs.fastly.com/en/ngwaf/",
       "Fastly Next-Gen WAF overview"),
    ],
  },
  { "slug": "akamai",
    "name": "Akamai", "tier": "A",
    "terms": "https://www.akamai.com/legal",
    "terms_note": "Akamai docs are publicly available; ingesting factual summary only.",
    "tags": ["akamai","cdn","waf","bot-manager","edge-dns","provider-context"],
    "pages": [
      ("https://techdocs.akamai.com/app-api-protector/docs/welcome-app-api-protector",
       "Akamai App & API Protector (WAF) overview"),
    ],
  },
  { "slug": "imperva",
    "name": "Imperva", "tier": "A",
    "terms": "https://www.imperva.com/legal/",
    "terms_note": "Imperva docs are publicly available; ingesting factual summary only.",
    "tags": ["imperva","cloud-waf","bot-protection","ddos","cdn","provider-context"],
    "pages": [
      ("https://docs.imperva.com/bundle/cloud-application-security/page/introducing-incapsula.htm",
       "Imperva cloud WAF (Incapsula) overview"),
    ],
  },
  { "slug": "sucuri",
    "name": "Sucuri", "tier": "A",
    "terms": "https://sucuri.net/terms-of-service/",
    "terms_note": "Sucuri docs are publicly available; ingesting factual summary only.",
    "tags": ["sucuri","waf","cdn","ddos","ip-allowlisting","challenge-page",
             "provider-context"],
    "pages": [
      ("https://docs.sucuri.net/website-firewall/",
       "Sucuri firewall overview"),
      ("https://docs.sucuri.net/website-firewall/firewall-settings/ip-whitelisting/",
       "Sucuri IP allowlisting"),
    ],
  },
  # ── Priority 4: Integration providers ────────────────────────────────────
  { "slug": "stripe",
    "name": "Stripe", "tier": "A",
    "terms": "https://stripe.com/privacy",
    "terms_note": "Stripe docs are publicly available; ingesting factual summary only.",
    "tags": ["stripe","webhooks","webhook-signature","checkout","oauth",
             "provider-context"],
    "pages": [
      ("https://docs.stripe.com/webhooks",
       "Stripe webhooks overview"),
      ("https://docs.stripe.com/webhooks/signatures",
       "Stripe webhook signature validation"),
      ("https://docs.stripe.com/security",
       "Stripe security overview"),
    ],
  },
  { "slug": "resend",
    "name": "Resend", "tier": "A",
    "terms": "https://resend.com/legal/terms-of-service",
    "terms_note": "Resend docs are publicly available; ingesting factual summary only.",
    "tags": ["resend","email","spf","dkim","dmarc","dns","provider-context"],
    "pages": [
      ("https://resend.com/docs/introduction",
       "Resend introduction"),
      ("https://resend.com/docs/dashboard/domains/introduction",
       "Resend domain setup"),
    ],
  },
  { "slug": "github",
    "name": "GitHub", "tier": "A",
    "terms": "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
    "terms_note": "GitHub docs are publicly available; ingesting factual summary only.",
    "tags": ["github","oauth-apps","oauth","webhooks","secret-scanning",
             "code-scanning","provider-context"],
    "pages": [
      ("https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app",
       "GitHub — creating an OAuth app"),
      ("https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
       "GitHub — OAuth app authorization flow"),
      ("https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning",
       "GitHub secret scanning overview"),
    ],
  },
  { "slug": "google-oauth",
    "name": "Google OAuth / Identity", "tier": "A",
    "terms": "https://developers.google.com/terms/",
    "terms_note": "Google developer docs are publicly available; ingesting factual summary only.",
    "tags": ["google","oauth2","openid-connect","scopes","redirect-uri",
             "provider-context"],
    "pages": [
      ("https://developers.google.com/identity/protocols/oauth2",
       "Google OAuth 2.0 overview"),
      ("https://developers.google.com/identity/protocols/oauth2/web-server",
       "Google OAuth 2.0 web server flow"),
      ("https://developers.google.com/identity/protocols/oauth2/scopes",
       "Google OAuth 2.0 scopes"),
    ],
  },
]

# ---------------------------------------------------------------------------
# Retrieval test cases (24 topics)
# ---------------------------------------------------------------------------
SELFTEST = [
  ("Cloudflare WAF false positives and rule actions", {"cloudflare"}),
  ("Cloudflare challenge pages blocking scanners", {"cloudflare"}),
  ("Cloudflare scanner IP allowlisting", {"cloudflare"}),
  ("Cloudflare rate limiting rules and headers", {"cloudflare"}),
  ("Cloudflare cache masking header changes", {"cloudflare"}),
  ("Vercel deployment protection mechanisms", {"vercel"}),
  ("Vercel preview deployment access and behavior", {"vercel"}),
  ("Vercel firewall WAF behavior", {"vercel"}),
  ("Railway public networking custom domains", {"railway"}),
  ("Railway health checks runtime behavior", {"railway"}),
  ("Netlify redirects headers configuration", {"netlify"}),
  ("Render Fly deployment health check behavior", {"render","flyio"}),
  ("Fastly Akamai cache WAF behavior", {"fastly","akamai"}),
  ("Imperva Sucuri challenge block pages", {"imperva","sucuri"}),
  ("AWS CloudFront WAF behavior", {"aws-cloudfront","aws-waf"}),
  ("Azure Front Door WAF", {"azure-front-door"}),
  ("Google Cloud Armor WAF DDoS protection", {"google-cloud-armor"}),
  ("Stripe webhook signature validation", {"stripe"}),
  ("Resend DNS SPF DKIM DMARC email", {"resend"}),
  ("GitHub OAuth redirect rules authorization", {"github"}),
  ("Google OAuth redirect scope", {"google-oauth"}),
  ("provider context reasoning for WADE scanner", {"cloudflare","vercel","railway"}),
  ("provider false positive patterns WAF challenge", {"cloudflare","imperva","sucuri","aws-waf"}),
  ("scanner allowlisting recommendations IP whitelist", {"cloudflare","sucuri","vercel"}),
]

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _http(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
        "Accept": "text/html,text/plain,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            # Read up to MAX_PAGE_BYTES regardless of total size
            return r.read(MAX_PAGE_BYTES)
    except urllib.error.HTTPError as e:
        print(f"      [http-{e.code}] {url}")
        return b""
    except Exception as e:
        print(f"      [err] {url}: {type(e).__name__}")
        return b""

# ---------------------------------------------------------------------------
# HTML → text extraction
# ---------------------------------------------------------------------------
_TAG = re.compile(r"<[^>]+>", re.DOTALL)
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_WS = re.compile(r"\n{3,}")
_ENTITIES = [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&quot;",'"'),
             ("&apos;","'"),("&#39;","'"),("&nbsp;"," ")]

def _strip_html(raw: str) -> str:
    text = _SCRIPT.sub(" ", raw)
    text = _TAG.sub(" ", text)
    for ent, rep in _ENTITIES:
        text = text.replace(ent, rep)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return _WS.sub("\n\n", "\n".join(lines))

# Detection-relevant keywords for section extraction
DETECT_KW = re.compile(
    r"\b(waf|firewall|challenge|captcha|turnstile|block(?:ed|ing)?|allow(?:list|ing)?|"
    r"whitelist|rate.lim|throttl|bot|crawler|spider|scanner|scraper|"
    r"cache|cdn|header|xff|x-forwarded|cf-ray|cf-cache|via\b|age\b|etag|"
    r"deploy(?:ment)?|preview|protect(?:ion)?|bypass|token|secret|webhook|"
    r"signature|hmac|spf|dkim|dmarc|dns|mx\b|txt\b|ssl|tls|certif|"
    r"oauth|scope|redirect|authori[sz]|health.?check|heartbeat|"
    r"ip.address|cidr|subnet|origin|proxy|443|80\b|timeout|retry|backoff|"
    r"error.?page|403|404|429|503|200 ok)",
    re.IGNORECASE,
)

def extract_relevant(text: str, max_chars: int = MAX_EXTRACT_CHARS) -> str:
    """Extract detection-relevant paragraphs from stripped text."""
    paras = [p.strip() for p in re.split(r"\n{2,}", text) if p.strip()]
    scored = []
    for p in paras:
        hits = len(DETECT_KW.findall(p))
        if hits > 0 or len(p) < 120:
            scored.append((hits, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    out, used = [], 0
    for _, p in scored:
        if used + len(p) > max_chars:
            break
        out.append(p)
        used += len(p)
    # keep order (not score order) for readability
    ordered = [p for _, p in scored if p in out]
    return "\n\n".join(ordered[:40]) if ordered else text[:max_chars]

# ---------------------------------------------------------------------------
# Normalize / chunk
# ---------------------------------------------------------------------------
def normalize(raw: str, is_html: bool) -> str:
    if is_html:
        text = _strip_html(raw)
        text = extract_relevant(text)
    else:
        text = raw.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        if len(text) > MAX_EXTRACT_CHARS:
            text = text[:MAX_EXTRACT_CHARS]
    return text + "\n"

def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def chunk_text(doc_id: str, source_key: str, text: str) -> list[dict]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if buf and len(buf) + len(p) + 2 > CHUNK_TARGET:
            chunks.append(buf)
            buf = p
        else:
            buf = f"{buf}\n\n{p}" if buf else p
    if buf:
        chunks.append(buf)
    out, seen = [], set()
    for c in chunks:
        c = c.strip()
        key = re.sub(r"\s+", " ", c.lower())
        if len(c) < CHUNK_MIN or key in seen:
            continue
        seen.add(key)
        out.append({"chunk_id": f"{doc_id}::{len(out):03d}", "doc_id": doc_id,
                    "source_key": source_key, "ordinal": len(out),
                    "char_len": len(c), "text": c})
    return out

# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------
def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")

def existing_doc_ids() -> set[str]:
    ids: set[str] = set()
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    ids.add(json.loads(line)["doc_id"])
    return ids

def _ensure_trailing_newline(path: str) -> None:
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                with open(path, "a", encoding="utf-8") as g:
                    g.write("\n")

def append_manifest(records: list[dict]) -> None:
    if not records:
        return
    _ensure_trailing_newline(MANIFEST_PATH)
    with open(MANIFEST_PATH, "a", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def provider_record(prov: dict, doc_id: str, url: str, title: str,
                    norm_rel: str, chash: str) -> dict:
    return {
        "doc_id": doc_id, "title": title, "source_name": prov["name"],
        "source_url": url, "source_type": "official_provider_doc",
        "doc_role": "engine_note", "authority_tier": prov["tier"],
        "language": "en", "product_or_provider": prov["slug"],
        "topic_tags": prov["tags"], "version": INGEST_STAMP,
        "last_updated": INGEST_STAMP, "first_ingested": INGEST_STAMP,
        "content_hash": chash, "confidence_score": 0.9,
        "verification_status": "verified", "license_terms": prov["terms_note"],
        "citability": "citable_external", "pii_risk_class": "none",
        "retention_class": "long", "entities": [prov["name"], prov["slug"]],
        "related_docs": [], "trust_label": "trusted_external",
        "normalized_path": norm_rel,
    }

# ---------------------------------------------------------------------------
# Retrieval (same pattern as 6C)
# ---------------------------------------------------------------------------
def _stem(w: str) -> str:
    if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w

def _terms(s: str) -> list[str]:
    return [_stem(w) for w in re.findall(r"[a-z0-9]+", s.lower())
            if w not in STOP and len(w) > 1]

def load_chunks() -> list[dict]:
    if not os.path.exists(CHUNKS_PATH):
        return []
    rows = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def _build_idf(chunks: list[dict]) -> dict[str, float]:
    df: dict[str, int] = {}
    for c in chunks:
        for w in set(_terms(c["text"])):
            df[w] = df.get(w, 0) + 1
    n = max(1, len(chunks))
    return {w: math.log(1 + n / d) for w, d in df.items()}

def _chunk_score(c: dict, qterms: set[str], idf: dict[str, float]) -> float:
    ct = _terms(c["text"]) + 3 * _terms(c["source_key"].replace("-", " "))
    if not ct:
        return 0.0
    tf: dict[str, int] = {}
    for w in ct:
        tf[w] = tf.get(w, 0) + 1
    denom = 1 + (len(ct) / 500.0)
    return sum(tf.get(w, 0) * idf.get(w, math.log(2)) for w in qterms) / denom

SOURCE_TAGS = {p["slug"]: set(p["tags"]) for p in PROVIDERS}

def retrieve_sources(chunks: list[dict], query: str, k: int = 3) -> list[str]:
    idf = _build_idf(chunks)
    qt = set(_terms(query))
    best: dict[str, float] = {}
    for c in chunks:
        s = _chunk_score(c, qt, idf)
        if s <= 0:
            continue
        r = c["source_key"]
        if s > best.get(r, 0.0):
            best[r] = s
    for key, tags in SOURCE_TAGS.items():
        overlap = len(qt & set(_terms(" ".join(tags))))
        if overlap:
            best[key] = best.get(key, 0.0) + overlap * TAG_BONUS
    return sorted(best, key=lambda r: best[r], reverse=True)[:k]

def retrieve(chunks: list[dict], query: str, k: int = 5) -> list[dict]:
    idf = _build_idf(chunks)
    qt = set(_terms(query))
    scored = [(_chunk_score(c, qt, idf), c) for c in chunks]
    scored = [(s, c) for s, c in scored if s > 0]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:k]]

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_run(args) -> int:
    have = existing_doc_ids()
    os.makedirs(PROV_NORM_DIR, exist_ok=True)
    new_records, all_chunks, summaries = [], [], []
    skipped, failed = [], []
    seen_ids: set[str] = set(have)

    for prov in PROVIDERS:
        slug = prov["slug"]
        prov_dir = os.path.join(PROV_NORM_DIR, slug)
        os.makedirs(prov_dir, exist_ok=True)
        pnew = 0
        for url, title in prov["pages"]:
            is_html = not (url.endswith(".txt") or url.endswith(".md"))
            raw_bytes = b"" if args.dry_run else _http(url)
            if not raw_bytes:
                failed.append((slug, url, title))
                continue
            raw_str = raw_bytes.decode("utf-8", "replace")
            norm = normalize(raw_str, is_html)
            if len(norm.strip()) < 100:
                skipped.append((slug, url, "empty/JS-shell"))
                continue
            # doc_id from slug + url path
            path_part = re.sub(r"https?://[^/]+", "", url).strip("/")
            path_part = re.sub(r"[^a-z0-9]+", "-", path_part.lower()).strip("-")[:60]
            doc_id = f"pd-{slug}--{path_part}" if path_part else f"pd-{slug}--root"
            # dedup
            n = 1
            base = doc_id
            while doc_id in seen_ids:
                n += 1
                doc_id = f"{base}-{n}"
            seen_ids.add(doc_id)

            ch = chunk_text(doc_id, slug, norm)
            if not ch:
                skipped.append((slug, url, "no chunks"))
                continue
            all_chunks.extend(ch)

            # write normalized artifact
            norm_path = os.path.join(prov_dir, f"{doc_id}.md")
            with open(norm_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"# {title}\n\nSource: {url}\n"
                        f"Provider: {prov['name']} | Authority: Tier {prov['tier']}\n"
                        f"Ingested: {INGEST_STAMP} | Terms: {prov['terms_note']}\n"
                        f"Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.\n\n")
                f.write(norm)

            if doc_id not in have:
                rec = provider_record(prov, doc_id, url, title,
                                      _rel(norm_path),
                                      _sha256(norm.encode()))
                new_records.append(rec)
                pnew += 1
            summaries.append({"provider": slug, "url": url, "doc_id": doc_id,
                               "chunks": len(ch), "chars": len(norm)})
            if not args.dry_run:
                time.sleep(0.3)  # gentle rate limit
        print(f"  [{slug:20s}] new={pnew:2d}")

    print(f"\n[summary] providers={len(PROVIDERS)} pages_ok={len(summaries)}"
          f" failed={len(failed)} skipped={len(skipped)}"
          f" new_records={len(new_records)} chunks={len(all_chunks)}")
    if failed:
        print(f"[failed] {len(failed)} pages:")
        for s, u, t in failed:
            print(f"  [{s}] {u}")
    if skipped:
        print(f"[skipped] {len(skipped)} pages:")
        for s, u, r in skipped:
            print(f"  [{s}] {u} ({r})")

    if args.dry_run:
        print("[dry-run] nothing written.")
        return 0

    with open(CHUNKS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    with open(os.path.join(PROV_NORM_DIR, "ingest_summary.json"),
              "w", encoding="utf-8", newline="\n") as f:
        json.dump({"stamp": INGEST_STAMP, "providers": summaries,
                   "failed": failed, "skipped": skipped,
                   "new_records": len(new_records),
                   "chunks": len(all_chunks)},
                  f, ensure_ascii=False, indent=2)
        f.write("\n")
    append_manifest(new_records)
    print(f"[ok] chunks={len(all_chunks)} new_records={len(new_records)}")
    return 0

def cmd_query(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no chunks; run first.")
        return 1
    print(f"query: {args.query!r}  -> sources: {retrieve_sources(chunks, args.query)}")
    for i, c in enumerate(retrieve(chunks, args.query, k=args.k), 1):
        print(f"  {i}. [{c['source_key']}/{c['doc_id']}] "
              f"{re.sub(chr(92)+'s+', ' ', c['text'])[:130]}...")
    return 0

def cmd_selftest(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no chunks; run first.")
        return 1
    top1 = top3 = 0
    for q, want in SELFTEST:
        got = retrieve_sources(chunks, q, k=3)
        ok3 = any(g in want for g in got)
        ok1 = bool(got[:1] and got[0] in want)
        if ok1:
            top1 += 1
        if ok3:
            top3 += 1
        print(f"  [{'OK ' if ok3 else 'MISS'}] {'/'.join(sorted(want))[:30]:30s} got={got}")
    n = len(SELFTEST)
    print(f"\n[selftest] top1={top1}/{n} top3={top3}/{n}")
    return 0 if top3 >= n * 0.8 else 1  # 80% threshold

# ---------------------------------------------------------------------------
# Supplement: authored knowledge/provider-docs/ notes → internal_doc records
# ---------------------------------------------------------------------------
KNOWN_SLUGS = {p["slug"] for p in PROVIDERS}

def supplement_record(doc_id: str, slug: str, title: str, norm_rel: str, chash: str) -> dict:
    prov_tags = next((p["tags"] for p in PROVIDERS if p["slug"] == slug), ["provider-context"])
    return {
        "doc_id": doc_id, "title": title, "source_name": f"WebHound authored — {slug}",
        "source_url": f"knowledge/provider-docs/{slug}/", "source_type": "internal_doc",
        "doc_role": "engine_note", "authority_tier": "B",
        "language": "en", "product_or_provider": slug,
        "topic_tags": prov_tags, "version": INGEST_STAMP,
        "last_updated": INGEST_STAMP, "first_ingested": INGEST_STAMP,
        "content_hash": chash, "confidence_score": 0.85,
        "verification_status": "reviewed", "license_terms": "internal authored note",
        "citability": "internal_only", "pii_risk_class": "none",
        "retention_class": "long", "entities": [slug],
        "related_docs": [], "trust_label": "internal_trusted",
        "normalized_path": norm_rel,
    }

def cmd_supplement(args) -> int:
    have = existing_doc_ids()
    new_records, all_chunks = [], []
    seen_ids: set[str] = set(have)
    existing_chunks = load_chunks()

    for slug in sorted(os.listdir(NOTES_DIR)):
        slug_dir = os.path.join(NOTES_DIR, slug)
        if not os.path.isdir(slug_dir):
            continue
        if slug not in KNOWN_SLUGS:
            continue
        for fname in sorted(os.listdir(slug_dir)):
            if not fname.endswith(".md") or fname.lower() == "readme.md":
                continue
            fpath = os.path.join(slug_dir, fname)
            text = open(fpath, encoding="utf-8").read()
            # first heading becomes title
            m = re.search(r"^#+ (.+)", text, re.MULTILINE)
            title = m.group(1).strip() if m else fname[:-3].replace("-", " ").title()
            norm = text.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
            doc_id_base = f"pn-{slug}--{fname[:-3]}"
            doc_id = doc_id_base
            n = 1
            while doc_id in seen_ids:
                n += 1
                doc_id = f"{doc_id_base}-{n}"
            seen_ids.add(doc_id)
            ch = chunk_text(doc_id, slug, norm)
            if not ch:
                continue
            all_chunks.extend(ch)
            if doc_id not in have:
                chash = _sha256(norm.encode())
                rec = supplement_record(doc_id, slug, title, _rel(fpath), chash)
                new_records.append(rec)
        print(f"  [supplement {slug:20s}] new={sum(1 for r in new_records if r['product_or_provider']==slug)}")

    combined = existing_chunks + all_chunks
    print(f"[supplement] authored_notes={len(new_records)} new_chunks={len(all_chunks)}"
          f" total_chunks={len(combined)}")
    if args.dry_run:
        print("[dry-run] nothing written.")
        return 0
    with open(CHUNKS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for c in combined:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    append_manifest(new_records)
    print(f"[ok] supplement complete. new_records={len(new_records)}")
    return 0

def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 6D provider docs ingestion")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--dry-run", action="store_true")
    r.set_defaults(func=cmd_run)
    su = sub.add_parser("supplement"); su.add_argument("--dry-run", action="store_true")
    su.set_defaults(func=cmd_supplement)
    q = sub.add_parser("query"); q.add_argument("query")
    q.add_argument("-k", type=int, default=5); q.set_defaults(func=cmd_query)
    s = sub.add_parser("selftest"); s.set_defaults(func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
