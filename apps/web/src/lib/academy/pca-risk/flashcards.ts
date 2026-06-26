import type { FlashcardGroup } from './types'

export const FLASHCARDS: FlashcardGroup[] = [
  { module: 'SOX & ICFR', cards: [
    { front: 'What is SOX Section 404?', back: 'Management (404a) and the external auditor (404b) must assess the effectiveness of ICFR annually.' },
    { front: 'What is ICFR?', back: 'Internal Control over Financial Reporting — controls giving reasonable assurance the financials are reliable.' },
    { front: 'COSO five components', back: 'Control Environment, Risk Assessment, Control Activities, Information & Communication, Monitoring Activities.' },
    { front: 'Material weakness vs significant deficiency', back: 'Material weakness = reasonable possibility of a MATERIAL misstatement (publicly disclosed). Significant deficiency = less severe, escalated to audit committee.' },
  ] },
  { module: 'GITC / ITGC', cards: [
    { front: 'Four ITGC domains', back: 'Logical access, change management, computer operations (incl. backup), program development/SDLC.' },
    { front: 'Why do ITGCs matter for ICFR?', back: 'They make application/financial controls trustworthy — if the environment isn’t controlled, you can’t rely on the app’s output.' },
    { front: 'Strong vs weak evidence', back: 'Strong = system-generated, dated, tied to a complete population. Weak = undated screenshot or verbal confirmation.' },
  ] },
  { module: 'Audit & Evidence', cards: [
    { front: 'Test of Design (ToD)', back: 'Would the control, if it runs as described, catch the risk? (inquiry, observation, walkthrough)' },
    { front: 'Test of Operating Effectiveness (ToE)', back: 'Did the control actually operate consistently all period? (re-performance, inspection, sampling)' },
    { front: 'Sufficient vs appropriate evidence', back: 'Sufficient = quantity (enough). Appropriate = quality (relevant + reliable). Need both (AS 1105).' },
    { front: 'What is roll-forward?', back: 'Extending interim testing to year-end with inquiry + a smaller sample so the conclusion covers the full year.' },
    { front: 'What is an exception?', back: 'A sampled item where the control did not operate as intended — investigated for root cause and impact.' },
  ] },
  { module: 'Identity & Access', cards: [
    { front: 'Authentication vs Authorization', back: 'AuthN = proving who you are. AuthZ = what you’re allowed to do. AuthN comes first.' },
    { front: 'Joiner / Mover / Leaver', back: 'Joiner = provision; Mover = adjust + remove old access (most-missed); Leaver = deprovision promptly.' },
    { front: 'AD vs Entra ID', back: 'AD = on-prem Microsoft directory (domain controllers, OUs, groups). Entra ID = cloud identity (formerly Azure AD).' },
    { front: 'Why are service accounts risky?', back: 'Often over-privileged, shared, and rarely rotated; drift outside JML/reviews. Need owner, business need, least privilege, managed creds.' },
    { front: 'How to test deprovisioning', back: 'HR-sourced termination population → sample → compare term date to access-disabled date in AD/apps.' },
  ] },
  { module: 'Change Management', cards: [
    { front: 'Standard change flow', back: 'RFC → approval (CAB) → test in non-prod → migrate to prod (segregated) → close with evidence.' },
    { front: 'Segregation of duties in deploys', back: 'Developer ≠ approver/deployer. If not possible, compensating control: independent review of deployment logs.' },
    { front: 'Emergency change control', back: 'Expedited path with documented justification + retrospective approval. Watch for overuse bypassing normal controls.' },
    { front: 'Backout plan', back: 'Documented way to reverse a failed change (rollback/restore). Required before approval.' },
  ] },
  { module: 'DR / Backup', cards: [
    { front: 'RTO vs RPO', back: 'RTO = max downtime (time). RPO = max data loss (time). 1-hr RPO → hourly backups.' },
    { front: 'Why isn’t a backup-success log enough?', back: 'A backup never restored is an assumption. The control is a periodic restore test proving recoverability.' },
    { front: 'DRP vs BCP', back: 'BCP = whole business keeps running. DRP = the IT subset (recovering systems/infrastructure).' },
  ] },
  { module: 'SOC / Vendor', cards: [
    { front: 'What does SOC stand for?', back: 'System and Organization Controls — NOT Security Operations Center.' },
    { front: 'SOC 1 vs SOC 2', back: 'SOC 1 = controls relevant to financial reporting. SOC 2 = Trust Services Criteria (security/availability/etc.).' },
    { front: 'Type I vs Type II', back: 'Type I = design at a point in time. Type II = design + operating effectiveness over a period. Want Type II.' },
    { front: 'What are CUECs?', back: 'Complementary User Entity Controls — controls the report assumes YOU perform for the vendor’s controls to work.' },
    { front: 'What is a bridge letter?', back: 'A gap letter covering between the SOC report period-end and your year-end, attesting no material changes.' },
    { front: 'Carve-out vs inclusive', back: 'Carve-out = subservice org excluded (get separate assurance). Inclusive = subservice org included in scope.' },
  ] },
  { module: 'Risk', cards: [
    { front: 'Inherent vs residual risk', back: 'Inherent = risk before controls. Residual = risk after controls (should be ≤ risk appetite).' },
    { front: 'Compensating control', back: 'An alternative control covering a gap when the primary control is absent — must address the same risk.' },
  ] },
]
