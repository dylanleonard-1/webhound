import type { StudyModule } from './types'

// Full teaching content per module. "SOC" = System and Organization Controls.
export const MODULES: StudyModule[] = [
  {
    slug: 'sox-icfr', title: 'SOX & ICFR', phase: 1, minutes: 45,
    tagline: 'Why a public manufacturer like PCA tests IT controls every year.',
    keyTerms: ['SOX 404', 'ICFR', 'COSO', 'material weakness', 'significant deficiency', 'key control'],
    sections: [
      { heading: 'What SOX is and why it exists',
        body: [
          'The Sarbanes-Oxley Act of 2002 (SOX) was passed after accounting scandals (Enron, WorldCom) destroyed investor trust. It makes management personally accountable for the accuracy of financial statements and the controls behind them.',
          'For a public company — and PCA is one — the headline requirement is Section 404: management must assess internal control over financial reporting (ICFR), and the external auditor must independently attest to it. That annual cycle is exactly why IT Risk/Audit roles exist.',
        ],
        bullets: [
          'SOX 404(a): management assesses & reports on ICFR effectiveness.',
          'SOX 404(b): the external auditor attests to ICFR independently.',
          'Executives sign off — real accountability, not a checkbox.',
        ] },
      { heading: 'ICFR — Internal Control over Financial Reporting',
        body: [
          'ICFR is the set of controls giving reasonable assurance the financials are reliable. "Reasonable" — not absolute — assurance is the standard.',
          'Most financial data lives in systems (ERP, databases, spreadsheets). So if someone could change a price master, post an unauthorized journal entry, or grant themselves access to the GL, that is a financial-reporting risk. IT controls protect the integrity of that data.',
        ] },
      { heading: 'COSO — the five components',
        body: ['COSO is the framework used to design and evaluate internal control. Memorize the five components (often "CRIME" is overkill — just learn them):'],
        bullets: [
          'Control Environment — tone at the top, ethics, accountability.',
          'Risk Assessment — identify & analyze risks to objectives.',
          'Control Activities — the actual controls (approvals, reviews, access).',
          'Information & Communication — capturing & sharing the right info.',
          'Monitoring Activities — ongoing/periodic evaluation that controls work.',
        ] },
      { heading: 'How IT supports financial reporting',
        body: [
          'IT rarely owns a financial number directly, but it owns the trust in the systems that produce them. This is the ITGC → application control → financial assertion chain.',
          'Example: management asserts revenue is complete and accurate. The billing app calculates it (application control). But you only trust the app if only authorized people can change it (logical access), changes are tested & approved (change management), and it’s backed up/recoverable (operations). Those are IT general controls.',
        ] },
      { heading: 'Deficiencies: severity matters',
        body: ['Not every issue is a crisis. Auditors grade severity by the reasonable possibility and magnitude of a resulting misstatement:'],
        bullets: [
          'Control deficiency — a control is missing or not operating.',
          'Significant deficiency — important enough for the audit committee.',
          'Material weakness — reasonable possibility of a MATERIAL misstatement; publicly disclosed. The outcome everyone works to avoid.',
        ] },
    ],
    interview: [
      { q: 'In plain English, what is SOX and why does it matter to IT?', a: 'SOX is a 2002 law that holds public companies accountable for the accuracy of their financials and the controls behind them. It matters to IT because financial data lives in systems — so controls over who can access and change those systems (IT general controls) directly support reliable financial reporting. That’s the work: testing that those IT controls are designed well and actually operate all year.' },
      { q: 'What’s the difference between a material weakness and a significant deficiency?', a: 'Both are control deficiencies; the difference is severity. A material weakness means there’s a reasonable possibility that a material misstatement of the financials won’t be caught — it gets publicly disclosed. A significant deficiency is less severe but still important enough to escalate to the audit committee. The grading is about the likelihood and size of a potential misstatement, not how "broken" the control feels.' },
      { q: 'Name the five COSO components.', a: 'Control Environment, Risk Assessment, Control Activities, Information & Communication, and Monitoring Activities. The simplest mental model: set the tone, figure out what could go wrong, put controls in place, move the right information around, and keep checking it still works.' },
    ],
  },
  {
    slug: 'gitc', title: 'GITC / ITGC', phase: 1, minutes: 40,
    tagline: 'The four control domains auditors test — and what good evidence looks like.',
    keyTerms: ['GITC', 'ITGC', 'logical security', 'MFA', 'access review', 'backup restore test'],
    sections: [
      { heading: 'What GITC/ITGC means',
        body: [
          'General IT Controls (GITC, also ITGC) are the foundational controls over the IT environment that make application and financial controls trustworthy. If application controls are the locks on each door, ITGCs are the building security that makes those locks mean something.',
          'They’re "general" because they apply across many systems rather than to one transaction.',
        ] },
      { heading: 'The four classic domains',
        body: ['Most ITGC programs organize around these domains. Know them cold:'],
        bullets: [
          'Logical access — who can get in and what they can do (provisioning, deprovisioning, access reviews, privileged access, password/MFA).',
          'Change management — changes to systems are authorized, tested, approved, and segregated before hitting production.',
          'Computer operations — jobs run as expected, incidents are handled, and data is backed up and recoverable.',
          'Program development / SDLC — new systems are built and implemented under control (sometimes folded into change management).',
        ] },
      { heading: 'How GITCs support ICFR',
        body: [
          'Auditors take a top-down view: start at the financial statements, identify significant accounts and the systems supporting them, then test the ITGCs over those systems. A failure in an ITGC can mean the application controls relying on it can’t be trusted — which is why a single broad ITGC gap (e.g. anyone can move code to production) can have outsized impact.',
        ] },
      { heading: 'Good vs bad evidence',
        body: ['Evidence quality is a recurring theme. System-generated beats human-asserted; complete beats partial.'],
        bullets: [
          'Good: a system-generated user listing with a dated, signed access-review record and tickets showing removals actioned.',
          'Bad: a screenshot with no date, a verbal "yes we review access," or a sample with no defined population.',
          'Golden rule: if you can’t tie it to a complete population and a date, it’s weak.',
        ] },
    ],
    interview: [
      { q: 'What are IT general controls and why do auditors care?', a: 'ITGCs are the foundational controls over the IT environment — logical access, change management, and computer operations including backups. Auditors care because financial applications are only trustworthy if the environment around them is controlled: if anyone could change the system or grant themselves access, you can’t rely on the numbers it produces. ITGCs make the application controls relied on for financial reporting credible.' },
      { q: 'Give an example of strong vs weak audit evidence for an access review.', a: 'Strong evidence is a system-generated user list pulled at a known date, a dated review record showing the owner signed off, and tickets proving inappropriate access was actually removed. Weak evidence is an undated screenshot or someone saying "yes, we do reviews" with no population behind it. The difference is whether it’s complete, system-sourced, and tied to a date.' },
    ],
  },
  {
    slug: 'audit', title: 'Audit Lifecycle & Evidence', phase: 2, minutes: 45,
    tagline: 'Walkthroughs, ToD vs ToE, sampling, exceptions, and surviving follow-ups.',
    keyTerms: ['Test of Design', 'Test of Operating Effectiveness', 'roll-forward', 'population', 'sample', 'exception', 'appropriate evidence'],
    sections: [
      { heading: 'The lifecycle',
        body: ['A typical SOX/IT audit cycle runs: scoping & risk assessment → walkthroughs → test of design → test of operating effectiveness (interim) → roll-forward to year-end → evaluate exceptions → report.'],
      },
      { heading: 'Walkthrough',
        body: ['A walkthrough traces one transaction end-to-end with the control owner to confirm you understand how the control actually works (not just how it’s documented). It’s where you validate the control description and spot design gaps early.'] },
      { heading: 'Test of Design vs Test of Operating Effectiveness',
        body: ['These are the two questions every control gets asked, in order:'],
        bullets: [
          'Test of Design (ToD): if this control runs as described, would it catch the risk? Done via inquiry, observation, walkthrough.',
          'Test of Operating Effectiveness (ToE): did it actually run, consistently, all period? Done via re-performance and inspecting evidence across a sample.',
          'A control can pass design but fail operation — e.g. a quarterly review that was skipped in Q3.',
        ] },
      { heading: 'Populations, samples, and frequency',
        body: ['You test a sample drawn from a complete population. Sample size scales with how often the control runs and the risk:'],
        bullets: [
          'Many-times-a-day / daily control → ~25 samples.',
          'Weekly → ~5; Monthly → ~2–5; Quarterly → ~2; Annual → 1.',
          'A wrong or incomplete population invalidates the test — proving completeness of the population is itself evidence.',
        ] },
      { heading: 'Exceptions & remediation',
        body: [
          'An exception is a sampled item that failed (e.g. a change with no approval). You investigate root cause, assess impact (isolated or systemic?), and may expand the sample.',
          'Remediation = the fix plus re-test evidence showing the control now works, with an owner and date. Auditors want to see the loop closed, not just "we’ll fix it."',
        ] },
      { heading: 'Surviving auditor follow-ups',
        body: ['When an auditor pushes back, answer with evidence and precision, not defensiveness: name the population, the sample, the date, and the artifact. If you don’t know, say "let me confirm and get you the source" rather than guessing — credibility comes from accuracy.'] },
    ],
    interview: [
      { q: 'Walk me through the difference between testing design and testing operating effectiveness.', a: 'Test of design asks whether the control, if it runs as described, is capable of catching the risk — I confirm that through a walkthrough and inquiry. Test of operating effectiveness asks whether it actually ran consistently across the whole period — I re-perform and inspect evidence over a sample. Design first, then operation, because there’s no point testing whether a poorly-designed control ran.' },
      { q: 'You pull a sample of 25 changes and one has no approval. What do you do?', a: 'I treat it as an exception and dig into root cause — was approval obtained but not documented, or genuinely missing? Then I assess whether it’s isolated or a pattern, which may mean expanding the sample. I document the exception, its impact, and work with the control owner on remediation and a re-test. One exception doesn’t automatically fail the control, but I don’t hand-wave it either — I let the evidence decide.' },
      { q: 'How do you decide a sample size?', a: 'It’s driven by how frequently the control operates and the risk. A daily or many-times-daily control might be 25 items; weekly around 5; quarterly around 2; annual is 1. And it only means something if the population it’s drawn from is complete and accurate — so I confirm the population first.' },
    ],
  },
  {
    slug: 'iam', title: 'Identity & Access (IAM)', phase: 3, minutes: 45,
    tagline: 'AD/Entra, authN vs authZ, JML, access reviews, privileged & service accounts.',
    keyTerms: ['Active Directory', 'Entra ID', 'authentication', 'authorization', 'JML', 'access review', 'least privilege', 'privileged account', 'service account', 'deprovisioning'],
    sections: [
      { heading: 'AD and Entra ID basics',
        body: [
          'Active Directory (AD) is Microsoft’s on-premises directory — it stores users, computers, and groups and handles authentication via domain controllers. Objects are organized into Organizational Units (OUs); access is granted through security groups; policy is pushed via Group Policy.',
          'Entra ID (formerly Azure AD) is the cloud counterpart for Microsoft 365 and cloud apps, adding conditional access, MFA, and SSO. Many companies sync on-prem AD into Entra, so identities live in both.',
        ] },
      { heading: 'Authentication vs authorization',
        body: ['Two words people mix up — keep them straight:'],
        bullets: [
          'Authentication (authN): proving who you are — password, MFA, certificate.',
          'Authorization (authZ): what you’re allowed to do — roles, groups, permissions.',
          'AuthN always comes before authZ: first verify identity, then decide access.',
        ] },
      { heading: 'Joiner / Mover / Leaver (JML)',
        body: ['The identity lifecycle and where audits focus:'],
        bullets: [
          'Joiner → provisioning: access granted with approval, role-based, least privilege.',
          'Mover → role change: grant new access AND remove the old (the most-missed leg — access accumulates).',
          'Leaver → deprovisioning: access removed promptly on termination (the #1 classic test).',
        ] },
      { heading: 'Access reviews',
        body: [
          'A periodic (usually quarterly) recertification where owners confirm each user still needs their access; anything inappropriate is removed. It’s a detective control catching whatever provisioning/JML missed.',
          'Evidence: the complete user population pulled at a date, the reviewer’s dated sign-off, and tickets proving removals were actioned. Reviews with no removals ever are a yellow flag.',
        ] },
      { heading: 'Privileged & service accounts',
        body: [
          'Privileged accounts (domain admin, DBA) carry the most risk — controls: keep the count small, enforce MFA, log activity, review more often, and consider break-glass accounts for emergencies.',
          'Service accounts (used by apps, not people) are a frequent finding: often over-privileged, shared, and with passwords that never rotate. Auditors check each has an owner, a business need, and managed credentials.',
        ] },
    ],
    interview: [
      { q: 'How would you test that terminated users lose access promptly?', a: 'I’d get the complete population of terminations in the period from HR, then pull a sample and, for each, compare the termination date to when their access was actually disabled in AD/Entra and key apps. Anything still active after the policy window — say more than 24 hours — is an exception, and I’d look at root cause and whether it’s systemic. The key is a complete, HR-sourced population, not just IT’s word.' },
      { q: 'What’s the difference between authentication and authorization?', a: 'Authentication is proving who you are — credentials, MFA. Authorization is what you’re allowed to do once you’re in — your roles and permissions. Authentication always happens first. A simple example: MFA gets you logged into the network (authN), but your security-group membership decides whether you can open the finance share (authZ).' },
      { q: 'Why are service accounts a common audit risk?', a: 'Because they’re used by systems rather than people, they tend to be over-privileged, sometimes shared, and their passwords rarely get rotated since changing them can break an app. So they drift outside the normal joiner/mover/leaver and review processes. I’d check each service account has a named owner, a documented business need, least-privilege rights, and managed/rotated credentials.' },
    ],
  },
  {
    slug: 'change-management', title: 'Change Management & SDLC', phase: 4, minutes: 40,
    tagline: 'RFC → approval → test → migrate, with segregation of duties and a backout plan.',
    keyTerms: ['RFC', 'CAB', 'emergency change', 'backout plan', 'migration', 'SDLC'],
    sections: [
      { heading: 'Why change management is a financial control',
        body: ['If someone can change a financial system without authorization, testing, or review, you can’t trust its output. Change management gives assurance that every production change was requested, approved, tested, and segregated.'] },
      { heading: 'The standard flow',
        body: ['Know the happy path and the artifacts each step produces:'],
        bullets: [
          'RFC (Request for Change) — describes the change, risk, test plan, and backout plan.',
          'Approval — CAB/CCB or designated approver signs off before work proceeds.',
          'Testing — change is tested in a non-prod environment with evidence.',
          'Migration — promoted to production by someone other than the developer (segregation of duties).',
          'Close — ticket records approvals, test results, and deployment.',
        ] },
      { heading: 'Segregation of duties (SoD)',
        body: ['The developer who wrote the change should not be the one who unilaterally approves and deploys it to production. SoD here prevents a single person from pushing unreviewed, untested, or malicious code into a financial system. Where full SoD isn’t possible (small teams), a compensating control like independent review of deployment logs is used.'] },
      { heading: 'Emergency changes',
        body: ['Sometimes you must change production fast (to fix an outage). An emergency change follows an expedited path but still requires documented justification and retrospective approval. Auditors specifically check emergency changes aren’t a backdoor used to skip normal controls — a spike in "emergency" changes is a red flag.'] },
      { heading: 'Evidence for a change ticket',
        body: ['When testing change management, for each sampled change you want: the RFC, evidence of testing, the approval (by the right person, before deployment), and confirmation it matches what actually went to prod. Missing or after-the-fact approvals are the common exceptions.'] },
    ],
    interview: [
      { q: 'What does good change management look like and why does it matter for SOX?', a: 'Every production change starts as a request that documents what’s changing, the risk, a test plan, and a backout plan; it’s approved before work, tested in non-prod with evidence, and deployed by someone other than the developer. It matters for SOX because financial systems are only trustworthy if changes to them are authorized, tested, and segregated — otherwise someone could alter how the numbers are produced without anyone catching it.' },
      { q: 'How should emergency changes be handled?', a: 'They follow an expedited path so you can fix urgent issues, but they still need documented justification and approval after the fact — usually reviewed at the next change board. When I test them I look closely for overuse, because "emergency" can become a way to bypass normal approval and testing. A healthy environment has very few, and each is genuinely justified.' },
      { q: 'What is segregation of duties in a deployment context?', a: 'It means the person who develops a change isn’t the same person who approves and pushes it to production. That separation stops one individual from putting unreviewed or malicious code into a financial system. In small teams where you can’t fully separate it, you lean on a compensating control — like an independent review of deployment logs against approved tickets.' },
    ],
  },
  {
    slug: 'dr-backup', title: 'DR, Backup & Data Center', phase: 5, minutes: 35,
    tagline: 'RTO/RPO, restore testing, DRP/BCP, and physical vs logical security.',
    keyTerms: ['RTO', 'RPO', 'DRP', 'BCP', 'backup restore test', 'data center review', 'physical security'],
    sections: [
      { heading: 'Backups and the restore test',
        body: [
          'Backups protect against data loss. But the control auditors actually trust is the restore test — periodically restoring from backup to prove the data is recoverable.',
          'A backup you have never restored is an assumption, not a control. "Backup job succeeded" logs are necessary but not sufficient; auditors want evidence of a successful restore.',
        ] },
      { heading: 'RTO and RPO',
        body: ['Two objectives that drive DR design — don’t confuse them:'],
        bullets: [
          'RTO (Recovery Time Objective) — how long you can be DOWN before it’s unacceptable.',
          'RPO (Recovery Point Objective) — how much DATA (in time) you can afford to lose.',
          'Example: RPO of 1 hour means you need backups/replication at least hourly.',
        ] },
      { heading: 'DRP vs BCP',
        body: ['BCP (Business Continuity Plan) keeps the whole business running during disruption — people, processes, facilities. DRP (Disaster Recovery Plan) is the IT subset: recovering systems and infrastructure. DR lives inside BCP.'] },
      { heading: 'Data center & physical controls (matters for a manufacturer)',
        body: [
          'For PCA — a manufacturer with plants — physical and environmental controls are real, not abstract. A data-center/plant review looks at badge access, cameras, visitor logs, locked racks (physical security) plus power, cooling, and fire suppression (environmental).',
          'Physical security protects the hardware; logical security protects the systems/data inside it. Auditors expect both.',
        ] },
    ],
    interview: [
      { q: 'What’s the difference between RTO and RPO?', a: 'RTO is about time — how long a system can be down before it’s unacceptable, which drives how fast you need to recover. RPO is about data — how much data, measured in time, you can afford to lose, which drives how often you back up or replicate. A one-hour RPO means hourly backups; a one-hour RTO means you need to be able to bring it back within an hour.' },
      { q: 'Why isn’t a successful backup job enough evidence?', a: 'Because a backup that’s never been restored is an assumption. The control that actually gives assurance is a periodic restore test that proves the data comes back intact and within your RTO/RPO. So I’d want evidence of a real restore, not just logs saying the backup job completed.' },
    ],
  },
  {
    slug: 'vendor-risk', title: 'Vendor Risk & SOC Reports', phase: 6, minutes: 40,
    tagline: 'SOC 1/2/3, Type I/II, CUECs, bridge letters, subservice orgs.',
    keyTerms: ['SOC 1', 'SOC 2', 'SOC 3', 'Type I', 'Type II', 'CUEC', 'bridge letter', 'subservice organization', 'carve-out method'],
    sections: [
      { heading: 'Why vendor risk exists',
        body: ['When you outsource a process to a service organization (payroll, hosting, SaaS), you outsource the activity but not the responsibility. If a vendor processes financially-relevant data, their controls become part of YOUR control environment — so you obtain assurance via a SOC report.',
          'SOC stands for System and Organization Controls — NOT Security Operations Center. That distinction trips people up; say it clearly.'] },
      { heading: 'SOC 1 vs SOC 2 vs SOC 3',
        body: ['Know which report to ask for:'],
        bullets: [
          'SOC 1 — controls relevant to user entities’ financial reporting (ICFR). Use it for vendors touching financially-relevant processing (e.g. payroll).',
          'SOC 2 — controls over the Trust Services Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy). Use it for security/operational assurance.',
          'SOC 3 — a public, general-use summary of SOC 2 with no detailed testing. Marketing-grade; not enough for reliance.',
        ] },
      { heading: 'Type I vs Type II',
        body: ['A Type I opines on whether controls are suitably DESIGNED at a point in time. A Type II covers design AND operating effectiveness over a period (usually 6–12 months) with test results. For real reliance you want a Type II.'] },
      { heading: 'CUECs and bridge letters',
        body: [
          'Complementary User Entity Controls (CUECs) are the controls the report assumes YOU perform for the vendor’s controls to work (e.g. "user is responsible for reviewing application access"). Reviewing CUECs and confirming you actually do them is a required step — skipping it is a common gap.',
          'A bridge letter covers the gap between the SOC report’s period-end and your fiscal year-end, attesting nothing material changed. You need one when the report doesn’t fully cover your year.',
        ] },
      { heading: 'Subservice organizations',
        body: ['A subservice org is the vendor’s vendor (e.g. a SaaS provider’s cloud host). The report handles it two ways: carve-out (excludes the subservice org’s controls — you must get separate assurance, like the cloud host’s own SOC report) or inclusive (includes them in scope). Always check which method, so you don’t assume coverage you don’t have.'] },
      { heading: 'How to review a SOC report (what to flag)',
        body: ['Practical checklist: confirm it’s the right type (SOC 1 Type II for financial reliance), the period covers your year (or get a bridge letter), read the auditor’s opinion (qualified?), review exceptions/test results and their impact, confirm the CUECs and that you perform them, and check the subservice method. Flag a qualified opinion, exceptions on relevant controls, CUECs you don’t actually do, and a period that doesn’t cover you.'] },
    ],
    interview: [
      { q: 'What’s the difference between a SOC 1 and a SOC 2 report?', a: 'A SOC 1 is about a service organization’s controls that are relevant to their customers’ financial reporting — you’d rely on it for a payroll or financial-processing vendor. A SOC 2 is about controls over the Trust Services Criteria like security and availability — you’d use it for operational and security assurance. And just to be clear, SOC there means System and Organization Controls, not Security Operations Center.' },
      { q: 'What are CUECs and why do they matter?', a: 'Complementary User Entity Controls are the controls the SOC report assumes the customer — us — performs for the vendor’s controls to actually be effective. For example, the report might rely on us reviewing who has access to the application. They matter because if I rely on the vendor’s SOC report but we’re not performing our side, there’s a real gap. So part of reviewing a SOC report is listing the CUECs and confirming we do them.' },
      { q: 'A vendor gives you a SOC 1 Type II but the period ends three months before your year-end. Is that a problem?', a: 'It’s a gap I need to close, not necessarily a dealbreaker. I’d request a bridge letter from the vendor covering the period between their report’s end and our fiscal year-end, attesting there were no material changes to the control environment. If they can’t provide that or something material did change, then I’d treat the uncovered period as a risk and look for other assurance.' },
    ],
  },
  {
    slug: 'tools', title: 'Tools & Documentation', phase: 7, minutes: 25,
    tagline: 'Excel, evidence trackers, SharePoint, ServiceNow, Visio, PowerShell.',
    keyTerms: ['audit evidence', 'population', 'access review'],
    sections: [
      { heading: 'Excel — the auditor’s workbench',
        body: ['Most IT-audit work happens in Excel. Be comfortable with pivot tables (summarizing populations), XLOOKUP/VLOOKUP (matching a termination list against an access export to spot users not removed), filtering/conditional formatting, and basic data cleanup. The recurring pattern: take a system export, reconcile it against an expected list, and surface the exceptions.'] },
      { heading: 'Evidence trackers & request lists',
        body: ['Audits run on a PBC ("provided by client") list — a tracker of every evidence request: control, owner, requested date, received date, status, and where the artifact lives. Keeping this current and chasing items is real day-to-day work; a clean tracker is half the job.'] },
      { heading: 'SharePoint / Teams',
        body: ['SharePoint stores evidence with version history (useful for showing a document existed at a point in time); Teams is where you coordinate with control owners. Knowing version control matters — it’s itself a form of change evidence.'] },
      { heading: 'ServiceNow & ticketing',
        body: ['Change and access requests usually flow through ServiceNow (or similar). You’ll pull ticket populations, trace a sampled ticket to its approval and deployment, and rely on the system’s audit trail as evidence.'] },
      { heading: 'Visio & PowerShell',
        body: ['Visio (or similar) is for process/control flow diagrams used in walkthroughs. PowerShell shows up for AD exports — e.g. pulling group membership or last-logon data as a population. You don’t need to be a developer; recognizing what these produce and how to use the output is enough at this level.'] },
      { heading: 'How tools support audit readiness',
        body: ['The throughline: tools exist to produce complete, dated, system-sourced evidence and to track it. An auditor’s confidence comes from artifacts that are reproducible and tied to a population — and that’s exactly what these tools generate.'] },
    ],
    interview: [
      { q: 'How comfortable are you in Excel for audit work?', a: 'Comfortable with the patterns that matter for audit — pivot tables to summarize a population, XLOOKUP to reconcile two lists like terminations against an access export, and filtering and conditional formatting to surface exceptions. The core task is usually taking a system export, comparing it to what it should be, and isolating the differences, and I’m solid on that. I’m also quick to pick up org-specific tools like ServiceNow.' },
      { q: 'How do you keep an audit organized?', a: 'A live evidence/request tracker — every control, the owner, what was requested, when it was received, the status, and where the artifact is stored. I keep it current and follow up on open items rather than letting them pile up at year-end. A clean tracker means nothing falls through and the auditor always knows where things stand.' },
    ],
  },
]

export const MODULE_SLUGS = MODULES.map((m) => m.slug)
export function getModule(slug: string): StudyModule | undefined {
  return MODULES.find((m) => m.slug === slug)
}
