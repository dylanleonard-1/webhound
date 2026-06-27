# Phase 1 — Master Enterprise Knowledge Graph

**WebHound Enterprise Security Academy** · the blueprint of *what* the Academy must eventually teach.

> **Governed by** `docs/academy/PHASE_0_ACADEMY_CONSTITUTION.md`. This is the concrete *population* of Phase 0’s structures (ID convention, L1–L5 bands, Bloom verbs, typed edges, taxonomy, metadata, file-org). It **extends, never contradicts** Phase 0.
> **This phase maps only** — no lessons/quizzes/labs/chapters/content; no academy redesign.
> **Machine-readable companion:** `apps/web/src/lib/academy/_graph/` (`domains.json`, `nodes.json`, `edges.json`, `README.md`) — validated parseable + acyclic.

## Honest scope statement (read first)

A literal leaf-enumeration of every concept across 62 domains would be tens of thousands of nodes and would collapse into shallow filler — which *lowers* quality (Phase 0 §0.6). Phase 1 therefore delivers a **structurally complete, extensible backbone**:

- **(a) Complete domain set** — all 62 domains (§2), incl. 20 added beyond the brief.
- **(b) Domain→Module→Chapter decomposition for ALL domains** (§2 tree), with **leaf depth for the exemplar verticals**.
- **(c) Three exemplar verticals fully enumerated to leaf** with complete metadata, in `nodes.json`: the **Kerberos chain** (Identity→AuthN→Kerberos→KDC→TGT→Service Ticket→PAC→attacks), the **SOX/ITGC/audit vertical**, and the **Networking→DNS→AD vertical**.
- **(d) A machine-enforceable pattern** (`_graph/README.md`) so remaining leaves generate later with no structural redesign.

**Explicitly enumerated to leaf:** 30 concept nodes across the 3 verticals (status `enumerated`). **Scaffolded for expansion:** all other domains (domain nodes present; sub-trees described here, leaves generated later).

---

## Section 1 — Master Knowledge Graph

The Academy’s knowledge is a **directed acyclic competence graph** (Phase 0 §24), not a linear bookshelf. Nodes are competencies/concepts; edges are typed relationships (`requires`, `recommends`, `reinforces`, `relatedTo`). Human-facing **Domains → Modules → Chapters → Lessons** are *views*; **role tracks** are curated traversals.

**Current population (validated):** 62 domains · 41 graph nodes (11 domain nodes + 30 leaf concept nodes) · 42 edges (35 `requires`, 7 `relatedTo`/`reinforces`) · 345 attached vocabulary terms · **0 dangling endpoints · 0 cycles**. The graph is the source of truth; the trees and tracks below are computed views over it.

The graph’s jobs (all enabled by this data shape): compute prerequisite closure, recommend the learner’s "ready next" frontier, detect gaps (a competency with no lesson), and run impact analysis (what depends on X if X changes).

## Section 2 — Domain Tree

### 2.1 The complete domain set (62) — grouped, with additions flagged

The brief’s list was challenged and extended. **★ = added by Phase 1** beyond the brief/Phase 0 enum (governed enum extension, Phase 0 §25).

**Foundations:** Enterprise Business · Enterprise IT · Computing Fundamentals · Operating Systems · Windows · Linux
**Infrastructure:** Networking · Enterprise Networking · ★Network Security · Cloud · ★Cloud Security · Enterprise Architecture · Databases · Storage · Virtualization · ★Containers & Kubernetes
**Identity & Access:** Identity · Authentication · Authorization · Active Directory · Microsoft Entra · IAM · ★Cryptography & PKI · ★Secrets Management · ★Zero Trust
**GRC & Audit:** Governance · Risk · Compliance · SOX · COSO · COBIT · ITGC · Internal Audit · External Audit · Audit Evidence · ★Legal & Regulatory · ★Data Protection & Privacy (GDPR/CCPA)
**Security Operations:** Vulnerability Management · Security Operations (SOC) · Threat Hunting · Incident Response · Digital Forensics · ★Logging/SIEM/Detection Engineering · ★Threat Intelligence · ★Endpoint & EDR · ★Email & Collaboration Security · ★Monitoring & Observability
**Security Engineering:** AppSec · DevSecOps · Security Engineering · ★Change & Configuration Mgmt · ★Asset Management & CMDB · ★AI/ML Security · ★OT/ICS-SCADA Security
**Resilience & Third-Party:** Vendor/Third-Party Risk · ★Supply Chain Security · Disaster Recovery · Business Continuity · Physical Security · ★Security Awareness & Human Factors
**Leadership & Business:** Enterprise Security Leadership · ★Security Finance & Budgeting

**Why these additions belong (not bloat):** *Cryptography/PKI* is a hidden prerequisite of Kerberos, TLS, and signing — teaching identity without it leaves a gap. *Detection Engineering/SIEM* and *Threat Intel* are now distinct disciplines from generic SecOps. *OT/ICS* is mandatory given PCA’s manufacturing context (plant floors, Purdue model, safety-first). *Data Protection/Privacy* and *Legal/Regulatory* are separated from Compliance because privacy law (GDPR/CCPA) is its own body of knowledge. *Zero Trust*, *Containers/K8s*, *AI/ML security*, *Supply Chain* are the current/emerging architecture every enterprise now faces. *Security Finance* and *Security Awareness* are the business/human realities a leader must master.

### 2.2 Decomposition pattern (all domains) + leaf depth (exemplars)

Every domain decomposes **Domain → Module → Chapter → Lesson → Concept → Vocabulary**. Below: leaf depth for the three exemplar verticals (these map 1:1 to `nodes.json`); module/chapter scaffold for representative other domains (leaves generated later via the pattern).

**Exemplar A — Identity → Authentication → Kerberos (LEAF-ENUMERATED):**
```
Identity
  └ Module: Identity Foundations
     └ Chapter: Identity Basics
        ├ what-is-identity (L1)
        └ authn-vs-authz (L1)
Cryptography & PKI
  └ Module: Crypto Foundations › Chapter: Symmetric
        └ symmetric-encryption (L2)
Authentication
  └ Module: Foundations › Chapter: Factors
        └ authentication-factors / MFA (L1)
  └ Module: Protocols › Chapter: Kerberos
        ├ kerberos-overview (L2)
        ├ kdc-as-tgs (L3)            (AS + TGS)
        ├ tgt (L3)                   (Ticket-Granting Ticket)
        ├ service-ticket (L3)        (TGS-issued)
        ├ pac (L4)                   (Privilege Attribute Certificate)
        └ kerberos-attacks (L4)      (Kerberoasting, Golden/Silver, AS-REP)
```

**Exemplar B — SOX / ITGC / Audit (LEAF-ENUMERATED):**
```
SOX › Foundations › Overview:  what-is-sox (L1) → icfr (L1)
COSO › Framework › Components:  coso-five-components (L2)
ITGC › Foundations › Overview:  itgc-overview (L2)
ITGC › Access:                  logical-access (L2)
IAM  › Lifecycle:               provisioning-deprovisioning (L2)
ITGC › Access:                  access-reviews (L2)
Audit Evidence › Testing:       tod-toe (L3) → populations-samples (L3) → exceptions-remediation (L3)
SOX  › Testing:                 itgc-sox-testing (L3, synthesis)
```

**Exemplar C — Networking → DNS → Active Directory (LEAF-ENUMERATED):**
```
Networking › Foundations:  tcp-ip-model (L1) → ip-addressing (L1)
Networking › Services › DNS:  dns-overview (L2) → dns-resolution (L2) → dns-srv-records (L2)
Active Directory › Foundations:  ad-basics (L2) → domains-ous-forests (L2) → security-groups (L2)
Active Directory › Services:  dc-locator (L3)  (uses DNS SRV to find DCs)
```

**Scaffold examples (module/chapter level; leaves generated later):**
- *Incident Response* → Modules: IR Lifecycle · Detection & Triage · Containment/Eradication/Recovery · Forensics Handoff · Tabletop & Comms. (e.g. IR Lifecycle › Chapter "Preparation" → leaves: IR plan, roles, runbooks…)
- *Cloud Security* → Modules: Shared Responsibility · Cloud IAM · CSPM · Workload Protection · Cloud Detection.
- *OT/ICS Security* → Modules: ICS Fundamentals · Purdue Model · OT Protocols · Safety vs Security · OT Monitoring.
- *Leadership* → Modules: Program Strategy · Board Communication · Team & Talent · Metrics & Budgeting.

(Every scaffolded domain follows the identical Domain→Module→Chapter→Lesson→Concept→Vocabulary shape; the `_graph/README.md` invariants make leaf generation mechanical and safe.)

## Section 3 — Dependency Graph

**Rule (Phase 0):** the Academy must never teach a concept before its `requires` prerequisites. `requires` edges form a DAG (verified — 0 cycles).

**The flagship worked cross-domain chain** (the brief’s spine) — every arrow is a real `requires` edge in `edges.json`:

```
tcp-ip-model → ip-addressing → dns-overview → ad-basics
   → kerberos-overview ──┐
authn-vs-authz ──────────┤
   (and) authn-vs-authz → logical-access ┐
security-groups → provisioning-deprovisioning ┘
   → access-reviews → (with) audit-evidence: tod-toe → populations-samples → exceptions-remediation
   → itgc-sox-testing  ✅ (synthesis capstone target)
itgc-overview ← icfr ← what-is-sox ;  itgc-overview ← coso-five-components ;  logical-access ← itgc-overview
```

Read it as: you cannot teach **ITGC logical-access testing** until the learner knows **AuthN vs AuthZ** and **ITGC overview**; you cannot teach **access reviews** until **provisioning/deprovisioning** (which needs **AD security groups**, which needs **AD basics**, which needs **DNS**, which needs **IP addressing**, which needs **TCP/IP**); and **end-to-end SOX testing** sits atop both the access chain and the **audit-evidence** chain. This is exactly why the Academy is a graph: the SOX synthesis node legitimately depends on *networking* fundamentals.

**The Kerberos sub-chain** (deep, single-domain): `authentication-factors → kerberos-overview → kdc-as-tgs → tgt → service-ticket → pac → kerberos-attacks`, with `kerberos-overview` also requiring `symmetric-encryption` (crypto) and `ad-basics` (AD) — a clean illustration of cross-domain prerequisites converging.

`recommends` (soft), `reinforces` (spiral re-teach), and `relatedTo` (lateral) edges enrich navigation but are **excluded from the cycle check** by design.

## Section 4 — Vocabulary Graph

Per Phase 0 §9, every concept attaches a controlled vocabulary set. Phase 1 records a `vocabCount` per node (345 total) and defines the **per-concept vocabulary schema** (the leaf content fills the actual terms later, sourced to the canonical glossary):

```
Concept → {
  core:        terms you must know to grasp the concept (e.g. Kerberos: KDC, ticket, realm)
  supporting:  adjacent terms (e.g. SPN, salt, nonce)
  enterprise:  how it shows up at scale (e.g. forest trust, RODC)
  business:    business-facing framing (e.g. "single sign-on reduces password risk")
  audit:       audit/control framing (e.g. "Kerberos logs as access evidence")
  risk:        risk framing (e.g. "ticket theft → lateral movement")
  compliance:  obligation framing (where relevant)
  acronyms:    expanded on first use (TGT, TGS, PAC, KDC)
  misunderstandings: the classic confusions (e.g. "SOC = System and Organization Controls, NOT Security Operations Center"; "TGT is not a service ticket")
  relatedConcepts: graph relatedTo links
}
```

**Worked example (Kerberos PAC):** *core* {PAC, ticket, SID, group membership}; *supporting* {KDC signature, authorization data}; *misunderstanding* "the PAC authenticates you" → no, it carries **authorization** data (groups/SIDs) inside an already-authenticated ticket; *related* {service-ticket, authorization, kerberos-attacks}. **Worked example (SOX):** *misunderstanding* "SOC report = Security Operations Center" → it is **System and Organization Controls** (the exact confusion the existing pca-risk content already corrects).

## Section 5 — Career Mapping

Each concept carries a `careers` map (role → ★1–5). Roles tracked: Help Desk, SysAdmin, IAM Analyst, SOC Analyst, Security Engineer, GRC Analyst, IT Auditor, Cloud Engineer, Threat Hunter, Incident Responder (extensible). Examples from the enumerated set:

| Concept | Help Desk | SysAdmin | IAM | SOC | Sec Eng | GRC | IT Auditor | Cloud |
|--------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| DNS overview | ★★★★ | ★★★★★ | ★★★★ | ★★★★★ | ★★★★★ | – | ★★ | ★★★★★ |
| Kerberos overview | – | ★★★★ | ★★★★ | ★★★★★ | ★★★★★ | – | ★★ | – |
| Kerberos attacks | – | – | – | ★★★★★ | ★★★★★ | – | – | – |
| AuthN vs AuthZ | ★★★★ | – | ★★★★★ | ★★★★★ | ★★★★★ | – | ★★★★★ | – |
| ITGC overview | – | ★★★ | ★★★★ | – | ★★★ | ★★★★★ | ★★★★★ | – |
| Access reviews | – | – | ★★★★★ | – | – | ★★★★★ | ★★★★★ | – |
| ToD vs ToE | – | – | – | – | – | ★★★★★ | ★★★★★ | – |

This powers role **tracks** (Phase 0 §5): e.g. the *IT Auditor* track traverses the SOX/ITGC/audit-evidence chain; the *SOC Analyst* track traverses networking→DNS→AD→Kerberos→Kerberos-attacks→detection.

## Section 6 — Enterprise-Department Mapping

Each concept carries a `departments` list — which parts of the enterprise it touches and how. This is what makes the Academy *enterprise* education rather than abstract security.

| Concept | Departments & interaction |
|--------|---------------------------|
| Provisioning/Deprovisioning | **HR** triggers Joiner/Leaver; **IT** executes; **Compliance** audits timeliness. |
| Access reviews | **IT** runs them; **business managers** recertify; **Audit/Compliance** rely on the evidence. |
| SOX / ICFR | **Finance** owns the financials; **Executive** signs (302/404); **IT** provides ITGC assurance; **Compliance/Audit** test. |
| Kerberos attacks | **Security** detects/responds; **IT** remediates AD; **Executive** briefed if material. |
| OT/ICS controls | **Manufacturing/Operations** own the plant; **Security** advises; **Safety** has veto. |
| DR/BCP | **Operations** + **every BU** define impact; **IT** recovers; **Executive** owns continuity. |

## Section 7 — Interview-Probability Mapping

Each concept carries `interviewProb` (★1–5). This later powers interview-focused study paths (like the existing `/academy/pca-risk` interview prep, now generalized). High-probability examples:

- ★★★★★: AuthN vs AuthZ · DNS · Active Directory basics · Kerberos overview · SOX/ICFR · ITGC overview · access reviews · provisioning/deprovisioning · ToD vs ToE · populations & samples.
- ★★★★: TCP/IP · MFA · KDC/TGT/service-ticket · Kerberos attacks · COSO · exceptions/remediation · SOC 1 vs SOC 2 (vendor vertical).
- ★★★: DC Locator · SRV records · PAC · symmetric encryption.

## Section 8 — Metadata Standard

Phase 1 uses a **superset of the Phase 0 `LessonMeta`** (§26), specialized for graph nodes. Fields (see `nodes.json.fieldSemantics`): `id` · `type` (domain/module/chapter/concept) · `title` · `difficulty` (L1–L5) · `bloom` · `estMinutes` · `prereq[]` · `importance{ent,bus,sec,aud,int}` (1–5) · `careers{role:★}` · `departments[]` · `interviewProb` (★1–5) · `lab` (bool) · `diagram` (bool) · `vocabCount` · `related[]` · `capstone[]` · `status` (enumerated/scaffolded) · `volatility`.

**Authoring rule (Bloom-aligned learning objectives, Phase 0 §22):** every concept’s objective uses a Bloom verb and is measurable — **never** "understand X." Examples (for enumerated concepts):
- *AuthN vs AuthZ (L1/understand):* "**Differentiate** authentication from authorization and **explain** three enterprise authentication mechanisms."
- *Kerberos KDC (L3/analyze):* "**Trace** a Kerberos exchange through the AS and TGS and **identify** where the TGT and service ticket are issued."
- *Kerberos attacks (L4/analyze):* "**Diagnose** a Kerberoasting attempt from event telemetry and **recommend** a detection."
- *Access reviews (L2/apply):* "**Perform** a user access recertification and **assemble** the evidence an auditor requires."
- *ToD vs ToE (L3/analyze):* "**Differentiate** test of design from test of operating effectiveness and **select** an appropriate sample for a quarterly control."

This standard is **populated** for the 30 enumerated concepts and **defined** for all (the `_graph/README.md` invariants make it enforceable by tooling).

## Section 9 — Gap Analysis (challenging our own work)

We critically reviewed the graph; findings and resolutions:

1. **Cycle check — PASS.** Programmatic Kahn topological sort over the 35 `requires` edges: **0 cycles, DAG valid.** All 42 edge endpoints resolve to known nodes/domains (0 dangling). *(Validation script below.)*
2. **Missing domains — addressed.** The brief omitted crypto/PKI, detection-engineering/SIEM, threat-intel, zero-trust, containers/K8s, OT/ICS, AI/ML security, data-protection/privacy, legal/regulatory, supply-chain, security-awareness, security-finance, asset/CMDB, change/config-mgmt, endpoint/EDR, email-security, monitoring/observability — **20 added** (§2.1). Remaining candidate (deferred): *human-factors social-engineering depth* and *insurance/cyber-risk-transfer* — flagged for Phase 2.
3. **Sequencing risk — fixed.** Initial instinct placed Kerberos before crypto; corrected so `kerberos-overview requires symmetric-encryption`. ITGC was almost placed before identity; corrected so `logical-access requires authn-vs-authz`.
4. **Weak prerequisite — noted.** `kerberos-overview requires ad-basics` is true for the Windows realm but Kerberos exists outside AD (MIT Kerberos). Resolution: keep AD as a `requires` for the *enterprise* framing, add a future `recommends` variant for protocol-pure study. Logged for Phase 2.
5. **Duplicate-concept risk.** "Logical access" (ITGC) vs "authorization" (identity) overlap. Resolved by scoping: `authorization` = the *mechanism*; `itgc.logical-access` = the *control/evidence* over it; linked via `relatedTo`, not merged.
6. **Volatility hot-spots.** `kerberos-attacks` marked `volatile` (tradecraft + detections evolve); cloud/Entra/AI domains will skew volatile — they need short `reviewBy` cycles (Phase 0 §17). Evergreen anchors (TCP/IP, COSO, ToD/ToE) are safe long-life.
7. **Orphan risk.** All 30 leaf nodes are reachable from a vertical/track; scaffolded domain nodes are intentionally "pending leaves," not orphans.
8. **Over-scope honesty.** We deliberately did NOT fake leaf enumeration for 62 domains; doing so would have produced shallow filler (Phase 0 §0.6). The backbone + pattern is the correct, shippable scope.

**Validation script (re-runnable):**
```python
import json, collections, pathlib
g=pathlib.Path('apps/web/src/lib/academy/_graph')
N=json.load(open(g/'nodes.json'))['nodes']; E=json.load(open(g/'edges.json'))['edges']
ids={n['id'] for n in N}|{d['id'] for d in json.load(open(g/'domains.json'))['domains']}
assert not [e for e in E if e['from'] not in ids or e['to'] not in ids], 'dangling edge'
req=[e for e in E if e['type']=='requires']; adj=collections.defaultdict(list); ind=collections.defaultdict(int); V=set()
for e in req: adj[e['to']].append(e['from']); ind[e['from']]+=1; V|={e['from'],e['to']}
q=[v for v in V if ind[v]==0]; seen=0
while q:
    x=q.pop(); seen+=1
    for y in adj[x]:
        ind[y]-=1
        if ind[y]==0: q.append(y)
print('DAG OK' if seen==len(V) else 'CYCLE!')
```

## Section 10 — Recommendations for Phase 2

1. **Build the `_schema/` TypeScript types** (Phase 0 Appendix A) and a **validator script** that enforces the `_graph/README.md` invariants in CI — turn Phase 1’s manual checks into an automated gate before authoring leaves.
2. **Depth-first, not breadth-first** (Phase 0 §30): take ONE enumerated vertical (recommend the **SOX/ITGC track**, since `/academy/pca-risk` already seeds it) and author it to *full Phase 0 lesson standard* (hook→exposition→diagram→worked example→retrieval→lab→assessment). Prove the whole pipeline end-to-end on one track before broadening.
3. **Generate the next leaf tier by pattern**, validator-gated, for the two other exemplar verticals; review for the weak-prereq and duplicate findings above.
4. **Migrate `/academy/pca-risk` content into the graph** as conformant legacy (map its glossary/modules/labs to node ids) — backward-compatible per Phase 0 §29.
5. **Stand up role tracks** (IT Auditor, SOC Analyst, Cloud Engineer) as graph traversals; verify each is fully covered by enumerated leaves before publishing.
6. **Wire `reviewBy`/`volatility` into a maintenance queue** so the corpus stays correct as it grows (Phase 0 §17/§19).
7. **Defer, don’t forget:** human-factors/social-engineering depth and cyber-insurance/risk-transfer as candidate domains; revisit the Kerberos-without-AD `recommends` variant.

---

*Phase 1 maps the territory; it does not pave the roads. The graph is the contract Phase 2’s lessons fulfill — and the cycle check, endpoint resolution, and enumerated/scaffolded honesty are what keep that contract trustworthy as it scales toward thousands of leaves.*
