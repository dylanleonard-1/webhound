import type { InterviewCategory } from './types'

// Model answers in Dylan's voice: practical, honest, entry-to-mid level. Positions
// WebHound (a consent-based security scanner he's building) and Log(N) Pacific
// experience as TRANSFERABLE (control thinking, evidence rigor, systematic testing)
// toward IT audit / SOX — without overclaiming seniority.
export const INTERVIEW: InterviewCategory[] = [
  {
    id: 'hr', title: 'HR & Behavioral', blurb: 'Tell-me-about-yourself, strengths, fit.',
    questions: [
      { q: 'Tell me about yourself.', a: 'I’m an early-career technologist focused on security and risk. I’ve been building WebHound, a consent-based security scanner — which means I spend my days thinking about controls: what could go wrong, how you verify something is actually working, and how you prove it with evidence rather than assumption. I’ve also worked with Log(N) Pacific, where I got real exposure to systematic testing and documentation. I’m drawn to this IT Risk Management Associate role because that control-and-evidence mindset is exactly what SOX and IT audit work runs on, and I want to apply it in a structured, public-company environment where it really matters.' },
      { q: 'What’s your greatest strength?', a: 'Systematic, evidence-first thinking. Building a scanner taught me not to trust "it works" — I want to see the proof, tie it to a complete picture, and rule out the edge cases. In an audit context that translates directly: I won’t accept a verbal "yes we review access," I’ll want the population, the dated sign-off, and proof the removals happened. I’m also genuinely organized, which matters when you’re tracking dozens of evidence requests.' },
      { q: 'What’s a weakness you’re working on?', a: 'I can go deep on the technical detail and have to remind myself to zoom back out to what the business actually cares about — for audit, that’s the risk to financial reporting, not the technology for its own sake. I’ve been deliberately practicing framing things in terms of risk and impact, and honestly that’s part of why this role appeals to me: it forces that discipline.' },
      { q: 'How do you handle being early-career on a team of experienced auditors?', a: 'I lean into it — I ask good questions, take detailed notes, and double-check rather than guess. I’d rather say "let me confirm and get you the source" than give a confident wrong answer, because in audit credibility is everything. I learn fast and I’m comfortable owning the legwork — pulling populations, chasing evidence, keeping the tracker clean — which is exactly where an associate adds value while building judgment.' },
    ],
  },
  {
    id: 'why-role', title: 'Why This Role / Company', blurb: 'Motivation & fit for IT Risk at PCA.',
    questions: [
      { q: 'Why IT risk / SOX instead of staying purely technical?', a: 'Because the part of security I love most is the control and assurance side — not just finding issues, but proving the system you rely on is trustworthy. SOX IT audit is that discipline applied to financial reporting: you test that access, change, and operations controls actually work, and you back every conclusion with evidence. It’s the structured, high-stakes version of what I already do informally building WebHound, and I want to do it formally and learn from experienced people.' },
      { q: 'Why do you want to work at a company like PCA?', a: 'A public manufacturer is a great place to learn real IT audit because the controls aren’t abstract — there are ERP systems behind the financials, plants with physical and environmental controls, vendors with SOC reports, and a genuine annual SOX cycle. That breadth is exactly the foundation I want. And I respect that the work matters: reliable financial reporting is something investors and employees depend on.' },
      { q: 'What do you know about the role?', a: 'As an IT Risk Management Associate I’d be supporting the testing of IT general controls that underpin financial reporting — access management, change management, operations and backups — under SOX. Day to day that means walkthroughs with control owners, pulling and testing samples from complete populations, documenting results and exceptions, reviewing vendor SOC reports, and keeping evidence organized. I’d be doing the hands-on testing and learning the judgment from the seniors and managers.' },
    ],
  },
  {
    id: 'sox', title: 'SOX / ICFR', blurb: 'Core financial-control concepts.',
    questions: [
      { q: 'What is SOX and why does IT matter to it?', a: 'SOX is the 2002 law that holds public companies accountable for accurate financials and the controls behind them — Section 404 requires management and the external auditor to assess internal control over financial reporting every year. IT matters because that financial data lives in systems, so controls over who can access and change those systems directly support whether the numbers can be trusted. That’s the whole reason IT general controls get tested.' },
      { q: 'Explain the relationship between ITGCs and financial statement assertions.', a: 'It’s a chain. Management makes assertions about the financials — like revenue is complete and accurate. An application control in the billing system enforces that. But you can only rely on that application control if the environment around it is sound: only authorized people can change the system (logical access), changes are tested and approved (change management), and the data is recoverable (operations). Those are the ITGCs. So a broad ITGC failure can undermine the application controls and, ultimately, the assertion.' },
      { q: 'What’s a material weakness?', a: 'It’s the most severe control deficiency — one where there’s a reasonable possibility that a material misstatement of the financial statements won’t be prevented or detected on time. It’s significant enough that it gets disclosed publicly. The tier below it is a significant deficiency, which is still important enough to escalate to the audit committee but less severe. The grading is about the likelihood and magnitude of a potential misstatement.' },
    ],
  },
  {
    id: 'gitc', title: 'GITC / ITGC', blurb: 'The four control domains.',
    questions: [
      { q: 'What are the main ITGC domains?', a: 'Logical access — who can get in and what they can do; change management — that system changes are authorized, tested, approved, and segregated; and computer operations — that jobs run as expected and data is backed up and recoverable. Some frameworks add program development or SDLC. These are "general" because they apply across the environment rather than to a single transaction, and they’re what make the application-level financial controls trustworthy.' },
      { q: 'A control is well-designed but you find it wasn’t performed in Q3. What does that tell you?', a: 'That it passed test of design but failed test of operating effectiveness — being capable of working isn’t the same as actually operating all period. A skipped quarterly review is an exception; I’d look at why it was missed, whether it’s a one-off or a pattern, and the impact, then work on remediation and a re-test. Design and operation are two separate questions and you need both to rely on the control.' },
    ],
  },
  {
    id: 'audit-evidence', title: 'Audit & Evidence', blurb: 'Testing mechanics and evidence quality.',
    questions: [
      { q: 'What makes audit evidence strong?', a: 'It has to be sufficient and appropriate — enough of it, and relevant and reliable. In practice that means system-generated beats a screenshot beats a verbal confirmation, and it has to tie to a complete, dated population. If I can’t connect a piece of evidence to the full set of items the control acted on and a point in time, I treat it as weak.' },
      { q: 'How do you test a control end to end?', a: 'I start with a walkthrough to confirm I understand how the control really works and that it’s designed to address the risk — that’s test of design. Then I get the complete population for the period, select a sample sized to the control’s frequency and risk, and inspect or re-perform each item to confirm it operated — that’s test of operating effectiveness. Anything that fails is an exception I investigate for root cause and impact, and I document it all so it’s reproducible.' },
      { q: 'An auditor challenges your conclusion. How do you respond?', a: 'With precision, not defensiveness. I’d walk them through the population, how I sampled, the dates, and the actual artifacts behind the conclusion. If they’ve spotted something I missed, I want to know — the goal is the right answer, not winning. And if I’m not certain, I say I’ll confirm and get them the source rather than guessing, because one confident wrong answer costs you credibility for the whole engagement.' },
    ],
  },
  {
    id: 'iam', title: 'Identity & Access', blurb: 'The most-tested domain.',
    questions: [
      { q: 'How would you test deprovisioning of terminated users?', a: 'I’d get the complete list of terminations for the period from HR — that’s my population — then sample from it and, for each person, compare their termination date to when access was actually disabled in AD or Entra and the key applications. Anything still active beyond the policy window is an exception, and I’d check whether it’s isolated or systemic. The important part is sourcing the population from HR, independent of IT, so it’s complete.' },
      { q: 'Authentication vs authorization — explain to a non-technical stakeholder.', a: 'Authentication is proving who you are — like your badge and PIN getting you into the building. Authorization is what you’re allowed to do once you’re in — which rooms your badge actually opens. You always authenticate first, then the system decides what you’re authorized to access. MFA strengthens the authentication side; security-group membership is the authorization side.' },
      { q: 'Why do privileged and service accounts get extra scrutiny?', a: 'Because they carry the most risk. Privileged accounts can change almost anything, so you want few of them, with MFA, logging, and frequent review. Service accounts are used by applications, so they tend to be over-privileged, sometimes shared, and their passwords rarely rotate because changing them can break something — which means they drift outside normal joiner/mover/leaver and review processes. For both, I’d confirm there’s a named owner, a real business need, least privilege, and managed credentials.' },
    ],
  },
  {
    id: 'change-mgmt', title: 'Change Management', blurb: 'Changes reaching production.',
    questions: [
      { q: 'What evidence do you expect for a production change?', a: 'For each change I want the request that describes it and its risk, evidence it was tested in a non-prod environment, an approval by the right person before deployment, and confirmation that what went to production matches what was approved. The common exception is approval that’s missing or granted after the change was already live — that breaks the control because it means a change reached production without authorization.' },
      { q: 'How do segregation of duties apply to deployments?', a: 'The developer who builds a change shouldn’t be the one who approves and pushes it to production — that separation stops a single person from putting unreviewed code into a financial system. In small teams where you genuinely can’t separate those roles, I’d expect a compensating control, like an independent review of deployment logs against the approved tickets, so there’s still an independent check.' },
    ],
  },
  {
    id: 'dr', title: 'DR / Backup', blurb: 'Resilience controls.',
    questions: [
      { q: 'RTO vs RPO?', a: 'RTO is recovery time — how long a system can be down before it’s unacceptable. RPO is recovery point — how much data, measured in time, you can afford to lose. So a one-hour RPO means you need backups or replication at least hourly, and a one-hour RTO means you need to restore within an hour. They drive different parts of the DR design.' },
      { q: 'What evidence proves backups work?', a: 'Not the backup-success log by itself — that just says the job ran. The control that gives real assurance is a periodic restore test that proves the data actually comes back intact and within the RTO and RPO. So I’d ask for evidence of a successful restore, not just confirmation that backups are scheduled.' },
    ],
  },
  {
    id: 'soc-vendor', title: 'SOC / Vendor Risk', blurb: 'Third-party assurance.',
    questions: [
      { q: 'SOC 1 vs SOC 2, and what does SOC stand for?', a: 'SOC stands for System and Organization Controls — not Security Operations Center, which people mix up. A SOC 1 covers a vendor’s controls relevant to their customers’ financial reporting, so you’d use it for something like a payroll processor. A SOC 2 covers the Trust Services Criteria — security, availability, processing integrity, confidentiality, privacy — so it’s for operational and security assurance. For financial reliance you generally want a SOC 1 Type II.' },
      { q: 'What would you check when reviewing a SOC report?', a: 'First that it’s the right type and a Type II so it covers operating effectiveness over a period. Then that the period actually covers our fiscal year, or get a bridge letter for the gap. I’d read the auditor’s opinion for any qualification, review the test results and exceptions for impact on controls we rely on, confirm the complementary user entity controls and that we actually perform our side of them, and check how subservice organizations are handled — carve-out versus inclusive — so I’m not assuming coverage we don’t have.' },
    ],
  },
  {
    id: 'scenario', title: 'Scenario / Case', blurb: 'Applied judgment questions.',
    questions: [
      { q: 'During a walkthrough, the control owner describes a process that doesn’t match the documentation. What do you do?', a: 'I’d note the discrepancy and dig in calmly — the documentation might be stale, or the control might actually be operating differently than intended. I’d confirm what really happens by tracing an actual transaction, then figure out whether the real process still addresses the risk. If it does, the fix may be updating the documentation; if it doesn’t, that’s a potential design gap I’d raise with my senior. Either way I document what I observed with evidence rather than just taking the description at face value.' },
      { q: 'You’re behind on evidence two weeks before year-end testing. How do you handle it?', a: 'I’d triage by risk — prioritize the key controls and the items with the longest lead time, and make the open requests crystal clear to each control owner with specific dates. I’d keep the tracker current so everyone can see status, escalate the genuine blockers to my senior early rather than at the deadline, and confirm exactly what artifact satisfies each request so we don’t do rework. The worst move is going quiet; the right move is transparent prioritization and early escalation.' },
      { q: 'You find one terminated user still had access for 40 days. Is that a material weakness?', a: 'Not on its own, necessarily — I wouldn’t jump straight to the most severe conclusion. I’d investigate: did that account actually get used in that window, did the person have access to anything financially significant, and is this a one-off or a sign the deprovisioning control is systematically failing? Severity depends on the likelihood and magnitude of a resulting misstatement. I’d document the exception, assess the impact, and let my senior and the evidence drive the severity rating rather than guessing.' },
    ],
  },
]
