"""Phase 8A: Obsidian vault note generators for export_brain_vault.py.

Each gen_*() returns {relative_path: note_content}.
All generators read d["now"] and d["marker"] from the analysis dict.
"""
from __future__ import annotations


def _fm(t: str, now: str, mk: str, tags: list[str] | None = None) -> str:
    return (f"---\ntitle: {t}\nstatus: active\nsource: webhound-ai-brain\n"
            f"created: {now}\nphase: 8A\nscope: internal\n---\n{mk}\n\n")


def _n(t: str, desc: str, now: str, mk: str,
       links: list[str] | None = None,
       tags: list[str] | None = None, extra: str = "") -> str:
    parts = [_fm(t, now, mk, tags), f"# {t}\n\n{desc}\n"]
    if extra:
        parts.append(extra)
    if links:
        parts.append("## See Also\n\n" + "\n".join(f"- [[{l}]]" for l in links))
    parts.append("\n" + " ".join(f"#{x}" for x in (tags or ["webhound"])) + "\n")
    return "\n".join(parts)


def gen_maps(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    n, c = d["total_docs"], d["total_chunks"]
    def moc(title, desc, links):
        return _n(title, desc, now, mk, links, ["map-of-content", "webhound"])
    return {
        "00-Maps/WebHound Master Map.md": moc(
            "WebHound Master Map",
            f"Root navigation for WebHound AI Brain. **{n} docs · {c} chunks** across knowledge phases.",
            ["AI Brain Map", "Knowledge Corpus Map", "WADE Intelligence Map",
             "Scanner Engine Map", "Provider Intelligence Map",
             "Threat Intelligence Map", "Vulnerability Taxonomy Map", "External Tool Map"],
        ),
        "00-Maps/AI Brain Map.md": moc(
            "AI Brain Map",
            "Architecture and retrieval components of the WebHound AI Knowledge System (Phase 8A).",
            ["WebHound Architecture Overview", "Phase History", "WADE Overview",
             "Corpus Overview", "Retrieval Modes", "WADE Brain Interface"],
        ),
        "00-Maps/WADE Intelligence Map.md": moc(
            "WADE Intelligence Map",
            "WADE decision architecture, confidence model, FP rules, and retrieval interface.",
            ["WADE Overview", "WADE Confidence Model", "WADE FP Rules",
             "WADE Retrieval Interface", "WADE Brain Interface"],
        ),
        "00-Maps/Knowledge Corpus Map.md": moc(
            "Knowledge Corpus Map",
            f"Corpus: {n} docs · {c} semantic chunks across phases 6A–8A.",
            ["Corpus Overview", "Manifest Schema", "Chunk Index", "Retrieval Modes", "Phase History"],
        ),
        "00-Maps/Scanner Engine Map.md": moc(
            "Scanner Engine Map",
            "Passive and active scanner engines that generate findings for WADE analysis.",
            ["Scanner Engines Overview", "Nuclei Engine", "ZAP Engine", "DalFox Engine"],
        ),
        "00-Maps/External Tool Map.md": moc(
            "External Tool Map",
            "Planned graph and memory integrations for the WebHound AI Brain layer.",
            ["External Tools Overview", "LightRAG Plan", "Graphiti Plan",
             "Neo4j Graph Schema Plan", "Graphify Status"],
        ),
        "00-Maps/Provider Intelligence Map.md": moc(
            "Provider Intelligence Map",
            f"CDN, WAF, and cloud provider intelligence. {len(d['providers'])} providers tracked.",
            ["Provider Intelligence Overview", "CDN Providers", "WAF Providers", "Cloud Providers"],
        ),
        "00-Maps/Threat Intelligence Map.md": moc(
            "Threat Intelligence Map",
            "External TI sources integrated into WADE decision-making (Phases 6E–6F).",
            ["Threat Intelligence Overview", "TI Sources", "VirusTotal Integration"],
        ),
        "00-Maps/Vulnerability Taxonomy Map.md": moc(
            "Vulnerability Taxonomy Map",
            "CWE, OWASP, and CVSS frameworks for finding classification.",
            ["Taxonomy Overview", "CWE Mapping", "OWASP Categories", "Severity Framework"],
        ),
    }


def gen_architecture(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "01-Architecture/WebHound Architecture Overview.md": _n(
            "WebHound Architecture Overview",
            "WebHound is an automated security intelligence platform. "
            "Phase 8A adds retrieval-augmented knowledge to the scanner + WADE pipeline.",
            now, mk,
            ["AI Brain Map", "WADE Overview", "Scanner Engines Overview", "Corpus Overview"],
            ["architecture", "webhound"],
            "## Components\n\n- Scanner Engines: Nuclei, ZAP, DalFox\n"
            "- WADE: confidence scoring + FP suppression\n"
            "- Knowledge Corpus: 487 docs, 1161 chunks\n"
            "- Hybrid Retrieval: 35% lexical + 65% dense\n"
            "- AI Brain: graph/memory layer (Phase 8A+)\n",
        ),
        "01-Architecture/Phase History.md": _n(
            "Phase History",
            "WebHound AI Knowledge Layer phases.",
            now, mk,
            ["Corpus Overview", "WebHound Architecture Overview"],
            ["architecture", "phase-history"],
            "6A Security docs · 6B Detection engine · 6C CDN/WAF (Cloudflare, Vercel, Fastly) · "
            "6D More providers (Akamai, AWS, Azure, Imperva) · 6E Threat intel · 6F VirusTotal · "
            "6G Retrieval baseline (12%/38%/52%) · 6H Chunk index rebuild (1161 chunks) · "
            "7A Dense hybrid (76%/88%/90%) · 8A AI Brain Foundation\n",
        ),
        "01-Architecture/Component Inventory.md": _n(
            "Component Inventory",
            "Key scripts and corpus paths.",
            now, mk,
            ["WebHound Architecture Overview", "Corpus Overview"],
            ["architecture", "inventory"],
            "Scripts: `build_unified_chunk_index.py`, `build_dense_index.py`, "
            "`hybrid_retrieval.py`, `export_brain_vault.py`, "
            "`lightrag_prepare_corpus.py`, `graphiti_seed_memory.py`\n\n"
            "Corpus: `manifest.jsonl` (487), `unified_chunks.jsonl` (1161), "
            "`corpus/indexes/dense/` (384-dim), `corpus/exports/lightrag/`\n",
        ),
    }


def gen_scanners(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "02-Scanner Engines/Scanner Engines Overview.md": _n(
            "Scanner Engines Overview",
            "Multi-engine scanning: passive engines observe; active engines probe.",
            now, mk, ["Nuclei Engine", "ZAP Engine", "DalFox Engine", "WADE Overview"],
            ["scanner", "webhound"],
            "- **Nuclei** — template CVE/misconfig (active+passive)\n"
            "- **ZAP** — OWASP web scanner (active+passive)\n"
            "- **DalFox** — XSS fuzzer (active confirmation)\n",
        ),
        "02-Scanner Engines/Nuclei Engine.md": _n(
            "Nuclei Engine",
            "Template-driven CVE/misconfiguration/exposure detection with matchers and extractors.",
            now, mk, ["Scanner Engines Overview", "WADE Overview", "Vulnerability Taxonomy Overview"],
            ["scanner", "nuclei"],
        ),
        "02-Scanner Engines/ZAP Engine.md": _n(
            "ZAP Engine",
            "OWASP ZAP passive + active scanning. FP rates vary by rule — see WADE FP Rules.",
            now, mk, ["Scanner Engines Overview", "WADE FP Rules"], ["scanner", "zap", "owasp"],
        ),
        "02-Scanner Engines/DalFox Engine.md": _n(
            "DalFox Engine",
            "Fast XSS fuzzer (reflected/stored/DOM). Active confirmation raises WADE confidence +0.4.",
            now, mk, ["Scanner Engines Overview", "WADE Confidence Model", "CWE Mapping"],
            ["scanner", "dalfox", "xss"],
        ),
    }


def gen_wade(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "03-WADE/WADE Overview.md": _n(
            "WADE Overview",
            "WADE scores findings, suppresses FPs, and retrieves knowledge for explanation. "
            "Phase 7A readiness: 8.9/10.",
            now, mk,
            ["WADE Confidence Model", "WADE FP Rules", "WADE Retrieval Interface",
             "WADE Brain Interface", "Scanner Engines Overview"],
            ["wade", "webhound"],
            "Capabilities: finding classification · confidence scoring · FP detection · "
            "provider context · TI enrichment · CWE mapping · evidence chain · "
            "knowledge retrieval · decision explanation\n",
        ),
        "03-WADE/WADE Confidence Model.md": _n(
            "WADE Confidence Model",
            "Confidence (0–1): active confirmation +0.4, passive +0.2, "
            "knowledge match +0.2, multi-scanner +0.1, TI +0.1.",
            now, mk, ["WADE Overview", "WADE FP Rules", "Severity Framework"],
            ["wade", "confidence"],
        ),
        "03-WADE/WADE FP Rules.md": _n(
            "WADE FP Rules",
            "FP suppression: CDN-injected headers, WAF challenge pages (Cloudflare 1020), "
            "bot protection tokens, shared CDN IPs.",
            now, mk, ["WADE Overview", "Provider Intelligence Overview", "Threat Intelligence Overview"],
            ["wade", "false-positive"],
        ),
        "03-WADE/WADE Retrieval Interface.md": _n(
            "WADE Retrieval Interface",
            "WADE queries hybrid retrieval for decision support. "
            "Full spec: WADE Brain Interface.",
            now, mk, ["WADE Overview", "WADE Brain Interface", "Retrieval Modes", "Corpus Overview"],
            ["wade", "retrieval"],
        ),
    }


def gen_corpus(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    tier_rows = "\n".join(f"| {t} | {c} |" for t, c in sorted(d["tiers"].items()))
    return {
        "04-Knowledge Corpus/Corpus Overview.md": _n(
            "Corpus Overview",
            f"**{d['total_docs']} docs · {d['total_chunks']} chunks** across phases 6A–8A.",
            now, mk, ["Manifest Schema", "Chunk Index", "Retrieval Modes", "Phase History"],
            ["corpus", "knowledge"],
            "| Tier | Docs |\n|------|------|\n" + tier_rows + "\n\n"
            + "\n".join(f"- **{k}**: {v}" for k, v in sorted(d["src_types"].items()) if k) + "\n",
        ),
        "04-Knowledge Corpus/Manifest Schema.md": _n(
            "Manifest Schema",
            "14 fields per record: doc_id, title, source_name, source_url, source_type, doc_role, "
            "authority_tier, language, product_or_provider, topic_tags, content_hash, "
            "confidence_score, verification_status, first_ingested.",
            now, mk, ["Corpus Overview", "Chunk Index"], ["corpus", "schema"],
        ),
        "04-Knowledge Corpus/Chunk Index.md": _n(
            "Chunk Index",
            f"Semantic chunking at ##/### boundaries, 300–1200 chars. "
            f"{d['total_chunks']} chunks from {d['total_docs']} docs.",
            now, mk, ["Corpus Overview", "Retrieval Modes", "Manifest Schema"],
            ["corpus", "chunking"],
        ),
        "04-Knowledge Corpus/Retrieval Modes.md": _n(
            "Retrieval Modes",
            "lexical_only (TF-IDF) · dense_only (cosine) · hybrid (0.35/0.65). "
            "Phase 7A: hybrid 76%/88%/90% top-1/3/5.",
            now, mk, ["Chunk Index", "WADE Retrieval Interface", "WADE Brain Interface"],
            ["retrieval", "embeddings"],
            "| Mode | Top-1 | Top-3 | Top-5 |\n|------|-------|-------|-------|\n"
            "| lexical_only | 12% | 38% | 52% |\n"
            "| dense_only | 71% | 84% | 92% |\n"
            "| hybrid | 76% | 88% | 90% |\n",
        ),
    }


def gen_providers(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    ps = d["providers"]
    cdn = [p for p in ps if any(x in p.lower() for x in ["cloudflare","fastly","akamai","cloudfront","netlify"])]
    waf = [p for p in ps if any(x in p.lower() for x in ["aws-waf","azure","imperva","sucuri","google-cloud"])]
    cloud = [p for p in ps if any(x in p.lower() for x in ["vercel","railway","fly","render","stripe","resend","github"])]
    def plist(items): return "\n".join(f"- {p}" for p in items) or "- (none matched)"
    return {
        "05-Provider Intelligence/Provider Intelligence Overview.md": _n(
            "Provider Intelligence Overview",
            f"{len(ps)} providers tracked across CDN, WAF, and cloud categories.",
            now, mk, ["CDN Providers", "WAF Providers", "Cloud Providers", "WADE FP Rules"],
            ["provider", "intelligence"],
        ),
        "05-Provider Intelligence/CDN Providers.md": _n(
            "CDN Providers",
            "CDN providers inject headers, alter responses, and return challenge pages.",
            now, mk, ["Provider Intelligence Overview", "WADE FP Rules"], ["cdn", "provider"],
            plist(cdn) + "\n",
        ),
        "05-Provider Intelligence/WAF Providers.md": _n(
            "WAF Providers",
            "WAF block/challenge signatures distinguish WAF blocks from real vulnerabilities.",
            now, mk, ["Provider Intelligence Overview", "WADE FP Rules"], ["waf", "provider"],
            plist(waf) + "\n",
        ),
        "05-Provider Intelligence/Cloud Providers.md": _n(
            "Cloud Providers",
            "Cloud/SaaS providers with deployment-specific security behaviors (Phases 6C–6D).",
            now, mk, ["Provider Intelligence Overview", "WADE Overview"], ["cloud", "provider"],
            plist(cloud) + "\n",
        ),
    }


def gen_ti(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "06-Threat Intelligence/Threat Intelligence Overview.md": _n(
            "Threat Intelligence Overview",
            "External TI feeds enrich findings with IP reputation and known-bad indicators (6E–6F).",
            now, mk, ["TI Sources", "VirusTotal Integration", "WADE Overview"],
            ["threat-intel", "webhound"],
        ),
        "06-Threat Intelligence/TI Sources.md": _n(
            "TI Sources",
            "VirusTotal (hash/URL reputation) · GreyNoise (CDN/scanner IP) · AbuseIPDB (known-bad IP).",
            now, mk, ["Threat Intelligence Overview", "VirusTotal Integration"],
            ["threat-intel", "sources"],
        ),
        "06-Threat Intelligence/VirusTotal Integration.md": _n(
            "VirusTotal Integration",
            "VT lookups enrich findings where third-party scripts or URLs can be hash-checked (6F).",
            now, mk, ["TI Sources", "WADE Confidence Model"], ["threat-intel", "virustotal"],
        ),
    }


def gen_taxonomy(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "07-Vulnerability Taxonomy/Taxonomy Overview.md": _n(
            "Taxonomy Overview",
            "WebHound maps findings to CWE, OWASP Top 10, and CVSS for consistent classification.",
            now, mk, ["CWE Mapping", "OWASP Categories", "Severity Framework", "WADE Overview"],
            ["taxonomy", "cwe", "owasp"],
        ),
        "07-Vulnerability Taxonomy/CWE Mapping.md": _n(
            "CWE Mapping",
            "Key CWEs used in WADE: CWE-79 (XSS) · CWE-89 (SQLi) · CWE-22 (Path Traversal) · "
            "CWE-601 (Open Redirect) · CWE-352 (CSRF) · CWE-200 (Info Exposure) · "
            "CWE-693 (Missing Header).",
            now, mk, ["Taxonomy Overview", "OWASP Categories"], ["taxonomy", "cwe"],
        ),
        "07-Vulnerability Taxonomy/OWASP Categories.md": _n(
            "OWASP Categories",
            "OWASP Top 10 (2021): A01 Access Control · A02 Crypto · A03 Injection · "
            "A04 Design · A05 Misconfig · A06 Components · A07 Auth · "
            "A08 Integrity · A09 Logging · A10 SSRF.",
            now, mk, ["Taxonomy Overview", "CWE Mapping", "Severity Framework"],
            ["taxonomy", "owasp"],
        ),
        "07-Vulnerability Taxonomy/Severity Framework.md": _n(
            "Severity Framework",
            "CVSS v3.1 base: Critical (9.0+) · High (7–8.9) · Medium (4–6.9) · "
            "Low (0.1–3.9) · Info (0).",
            now, mk, ["Taxonomy Overview", "WADE Confidence Model"], ["taxonomy", "severity", "cvss"],
        ),
    }


def gen_external(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "08-External Tools/External Tools Overview.md": _n(
            "External Tools Overview",
            "Planned integrations for Phase 8A. Docs/plans only — not installed.",
            now, mk, ["LightRAG Plan", "Graphiti Plan", "Neo4j Graph Schema Plan", "Graphify Status"],
            ["external-tools", "phase-8a"],
        ),
        "08-External Tools/LightRAG Plan.md": _n(
            "LightRAG Plan",
            "Graph-enhanced retrieval. See `docs/ai/LIGHTRAG_INTEGRATION_PLAN.md`. "
            "Export: `corpus/exports/lightrag/lightrag_documents.jsonl` (1161 docs).",
            now, mk, ["External Tools Overview", "Corpus Overview", "Retrieval Modes"],
            ["lightrag", "graph-rag"],
        ),
        "08-External Tools/Graphiti Plan.md": _n(
            "Graphiti Plan",
            "Episodic memory for WebHound sessions. "
            "See `docs/ai/GRAPHITI_MEMORY_PLAN.md`. 10 memory types, 10 seeds ready.",
            now, mk, ["External Tools Overview", "WADE Overview"], ["graphiti", "memory"],
        ),
        "08-External Tools/Neo4j Graph Schema Plan.md": _n(
            "Neo4j Graph Schema Plan",
            "17-node, 14-relationship schema. See `docs/ai/NEO4J_GRAPH_SCHEMA_PLAN.md`.",
            now, mk, ["External Tools Overview", "Corpus Overview", "Provider Intelligence Overview"],
            ["neo4j", "graph"],
        ),
        "08-External Tools/Graphify Status.md": _n(
            "Graphify Status",
            "Not installed. See `docs/ai/GRAPHIFY_SETUP.md`.",
            now, mk, ["External Tools Overview"], ["graphify", "status"],
        ),
    }


def gen_reports(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "09-Reports/Phase Results Overview.md": _n(
            "Phase Results Overview",
            "Phase result docs: `PHASE6H_RESULTS.md` (chunk index) · "
            "`PHASE7A_RESULTS.md` (dense retrieval) · `PHASE8A_RESULTS.md` (AI Brain).",
            now, mk, ["AI Brain Map", "Phase History"], ["reports", "phase-results"],
        ),
    }


def gen_decisions(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "10-Decisions/Architecture Decisions.md": _n(
            "Architecture Decisions",
            "1. Local-only embeddings (privacy + cost)\n"
            "2. Hybrid weights 0.35/0.65 (dense outperforms)\n"
            "3. Numpy over FAISS (1161 chunks fits in RAM)\n"
            "4. Append-only manifest (immutable ingestion record)\n"
            "5. No cloud APIs (all retrieval runs locally)",
            now, mk, ["WebHound Architecture Overview", "Retrieval Modes"],
            ["decisions", "architecture"],
        ),
        "10-Decisions/Local Only Embedding Decision.md": _n(
            "Local Only Embedding Decision",
            "all-MiniLM-L6-v2 local over cloud APIs. Protects sensitive content; no API costs.",
            now, mk, ["Architecture Decisions", "Retrieval Modes"], ["decisions", "embeddings"],
        ),
        "10-Decisions/Hybrid Retrieval Weights.md": _n(
            "Hybrid Retrieval Weights",
            "0.35 lex + 0.65 dense. Confirmed by Phase 7A: hybrid 76% vs lexical 12% top-1.",
            now, mk, ["Architecture Decisions", "Retrieval Modes"], ["decisions", "retrieval"],
        ),
    }


def gen_graphify(d: dict) -> dict[str, str]:
    now, mk = d["now"], d["marker"]
    return {
        "99-Graphify/Graphify Status.md": _n(
            "Graphify Status",
            "Not installed. Folder reserved for graph.html + graph.json output. "
            "See `docs/ai/GRAPHIFY_SETUP.md`.",
            now, mk, ["External Tools Overview"], ["graphify"],
        ),
    }
