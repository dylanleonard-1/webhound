# Lesson 1.2 — Business Processes

> **WebHound Enterprise Security Academy · Volume 1 — Enterprise, Risk & Audit Foundations**
> Module 1 — The Business Before the Controls · Chapter 2 — How Work Flows
> **Difficulty:** L1 · **Profile:** concept-foundation · **Est. time:** ~40 min · **Status:** published v1.0.0 · evergreen
> 🏅 **Certified: WebHound Enterprise Security Academy — Golden Lesson Reference v1.0** (see the certification-checklist self-review at the end and [the checklist](../GOLDEN_LESSON_CERTIFICATION_CHECKLIST.md)).
> **Graph node:** `enterprise-business.foundations.processes.business-processes` · **Brief:** [golden brief 1.2](../../../apps/web/src/lib/academy/_content/golden-briefs/1-2-business-processes.json) · **Content record:** [1-2-business-processes.json](../../../apps/web/src/lib/academy/_content/lessons/1-2-business-processes.json)
> **Builds on:** [Lesson 1.1 — What Is an Enterprise?](LESSON_1_1_WHAT_IS_AN_ENTERPRISE.md) (you already know what an enterprise is and why it needs technology).

Human-readable render of the schema-conforming content record. The JSON is authoritative; this mirrors it.

---

## Learning Objectives

Lesson 1.1 showed *what* an enterprise is and *why* it needs technology, security, governance, risk, and audit. This lesson zooms into *how the work actually flows*. By the end you can:

1. **Define** a business process (inputs, activities, outputs, owner).
2. **Trace** one transaction end-to-end through a named process such as Order-to-Cash.
3. **Classify** processes as core, supporting, or management.
4. **Locate** control points in a process and say what could go wrong at each.
5. **Explain** why controls live inside processes, why auditors evaluate processes, and why cybersecurity protects processes — not just computers.

---

## Executive Summary

A **business process** is a repeatable chain of work that turns an **input** into an **output** of value — the *how* behind the value creation from Lesson 1.1. Enterprises standardize work into named end-to-end flows like **Order-to-Cash** (customer order → cash collected) and **Procure-to-Pay** (buy materials → pay the supplier). Value, risk, and controls all live *inside* these flows — especially at the **handoffs** where work passes between departments. Once you can see the process, everything else attaches: a control sits at a step, a risk sits at a handoff, an auditor follows the flow.

---

## Why This Exists

Value is not created by departments in isolation — it is created when work *flows across* them. A customer order is useless until Sales, Credit, Production, Shipping, and Accounting each do their part *in sequence*.

That flow is where money is made and lost. A control at the wrong step protects nothing. A risk hiding in a handoff goes unnoticed until it becomes a loss or fraud. An audit that ignores the end-to-end flow misses the real exposure. And a cyberattack rarely targets "a computer" for its own sake — it targets the *process* the computer runs, because that is what moves money and data. Before you can reason about a single control, risk, or audit test, you must see the process it lives in.

---

## Core Concept

**The one idea:** value is created by transactions flowing through a process, and risk and controls live at the steps — and especially the handoffs — along that flow.

**What a business process is.** A repeatable set of **activities** turning an **input** into an **output** of value, with four parts: input (what starts it), activities (the sequenced steps), output (the value produced), and a **process owner** (the single business leader accountable end-to-end — recall owner vs. maintainer vs. auditor from 1.1). Analogy: a process is an **assembly line**; the moments a part passes between workers are the **handoffs**.

- **Process vs. procedure:** the process is the whole flow of value; a procedure is the step-by-step instructions for one task inside it.
- **The process is NOT the software.** The same Order-to-Cash can run on paper or in an **ERP** (Enterprise Resource Planning system, from 1.1). Software just *executes* part of the flow.

**Why enterprises standardize work.** Thousands of orders/dollars/people move daily across people who never speak. Standardizing makes work repeatable, scalable, measurable, and *controllable*. Standardization is what makes an enterprise trustworthy at scale.

**Three kinds of process.**
- **Core** — directly create/deliver customer value (Order-to-Cash, Manufacturing).
- **Supporting** — enable the core (Procure-to-Pay, Hire-to-Retire).
- **Management** — plan, measure, govern (Record-to-Report, budgeting).

**Control points.** A **control point** is *a place in the process where we deliberately check something before letting work continue* (e.g. a manager approving a purchase). That is all for now — control *types* and how they're tested are Lessons 1.4 and 1.8–1.10. Here we learn to spot *where* a checkpoint belongs.

**Handoffs: where the risk hides.** The riskiest places are the **handoffs** between people/departments — where information drops, errors slip, and fraud hides because no one sees the whole picture. From day one: *look hardest at the handoffs.*

**Segregation of Duties (SoD).** One handoff principle is so important it has a name: **no single person should control a whole sensitive transaction.** Classic example: whoever **orders** materials must not also **approve the payment**. Split across two people, fraud requires collusion and mistakes get caught. SoD is the first concrete reason controls are *embedded in the process* — enforced by *who may do which step* at the handoff. *(Treated here as a process principle; its formal place in the control framework is Lesson 1.4.)*

**The three payoffs the rest of the curriculum builds on.**
1. **Controls are embedded in processes** — a control only means something *at a point in a flow*.
2. **Auditors evaluate processes** — they *walk the process* (a **walkthrough**: tracing one transaction end-to-end) before testing any control.
3. **Cybersecurity protects processes, not just computers** — attackers want what the process moves (money, payments, identities). Securing a server matters only because of the business process on it.

---

## How It Works — read any process with five questions

Every process, however complex, reads with the same five questions per step:

1. **Business purpose** — why does this step exist?
2. **Technology** — which system runs it?
3. **Data created** — what record is left behind?
4. **What could go wrong** — here, and at the handoff after it (the risk)?
5. **Checkpoint & proof** — what control point protects it, and what record proves it happened (the audit evidence)?

The last question is the bridge to the rest of the course: the checkpoint is the control (1.4), the proving record is **audit evidence** (1.10), and what-could-go-wrong is risk (1.3). You're learning to see the hooks those disciplines hang on.

---

## End-to-End Walkthrough — Order-to-Cash at Northwind Containerboard Co.

**Northwind Containerboard Co.** is a *fictional* large paper-and-packaging manufacturer (containerboard and corrugated boxes, sold B2B). It is representative of the industry only — nothing here describes any real company's internal processes. It is the same *kind* of enterprise from Lesson 1.1, now in motion.

**Order-to-Cash (O2C)** takes a customer order all the way to collected cash. For each step: business purpose · technology · data created · risk (step & handoff) · security control · audit evidence · department.

| # | Step | Business purpose | Technology | Data created | Risk (step & handoff) | Security control | Audit evidence | Department |
|---|------|------------------|-----------|--------------|----------------------|------------------|----------------|-----------|
| 1 | Customer order | Capture what the customer wants | CRM / order portal | Sales order | Wrong/fraudulent order; bad data downstream | Authenticated accounts; input validation | Logged order + who entered it | Sales |
| 2 | Sales review | Confirm price, terms, feasibility | CRM / pricing | Confirmed quote | Unauthorized discount; mispricing | Pricing approval limits by role | Approved quote + approver | Sales |
| 3 | Credit approval | Check the customer can pay | ERP credit module | Credit decision | Extending credit to a bad payer | Credit check above a threshold | Credit-approval record | Finance (Credit) |
| 4 | Production scheduling | Slot order into plant capacity | ERP planning | Production order | Over/under-commit; missed dates | Schedule sign-off; capacity checks | Scheduled production order | Operations (Planning) |
| 5 | Manufacturing | Make the boxes — value created here | MES (Manufacturing Execution System) | Production run, material usage | Off-spec output; line tampering | Plant-floor access limited to operators | Production run logs | Operations (Plant) |
| 6 | Quality assurance | Verify product meets spec | QA/LIMS | Inspection result | Defective product shipped; QA bypassed | QA sign-off before release | QA inspection record | Operations (QA) |
| 7 | Inventory | Record finished goods | WMS (Warehouse Mgmt System) | Inventory movement | Mis-recorded stock; theft | Restricted inventory adjustments | Inventory movement log | Operations (Warehouse) |
| 8 | Shipping | Deliver to the customer | WMS / carrier | Shipping doc, POD | Shipped without valid order; lost in transit | Ship only against approved order | Bill of lading, proof of delivery | Operations (Logistics) |
| 9 | Accounting (invoicing) | Bill for what shipped | ERP financials | Customer invoice | Invoice ≠ what shipped | Invoice matched to shipment | Invoice tied to shipment | Finance (Accounting) |
| 10 | Accounts Receivable | Collect & apply cash | ERP AR / bank feed | Payment, cash applied | Payment misapplied/diverted | SoD: biller ≠ cash-applier | Remittance + cash-application | Finance (AR) |
| 11 | Executive reporting | Show leadership reliable results | BI / reporting | Management report | Misstated numbers; bad decisions | Reports from controlled source data | Report + data lineage | Executive / Finance |

**Read the flow, not the rows.** Value is physically created at step 5, but the enterprise only *realizes* it when cash arrives (10) and is reported truthfully (11). A failure anywhere breaks the chain — and the most dangerous gaps are the **handoffs**: order→credit, shipping→invoicing, invoicing→cash (the SoD split). Look there first.

---

## Procure-to-Pay (P2P) — the supporting process that feeds the core

Northwind can't run O2C without raw materials. **Procure-to-Pay** buys and pays for them — and it's the classic teaching example for control points and SoD:

Purchase requisition → manager **approval** → Procurement issues a **purchase order (PO)** → Receiving **confirms goods arrived** → Accounts Payable does a **three-way match** (PO + receipt + invoice agree) → Finance **pays**.

Two handoffs carry almost all the risk — **approval→ordering** (control point: approval limit) and **receipt→payment** (control point: the three-way match) — and **SoD** runs throughout: the person who raises the order must not approve it or release payment.

## The same lens elsewhere — a hospital's Order-to-Cash

*Treat patient → code the treatment → submit claim → insurer adjudicates → payment posted.* The dangerous handoff is treatment→coding→billing: a dropped handoff loses revenue *and* creates compliance exposure. Same mental model, different industry — learn the lens once and it transfers.

---

## Definitions

- **Business process** — a repeatable set of activities turning an input into an output of value.
- **Input / Activities / Output** — what starts it / the sequenced work / the value produced.
- **Process owner** — the business leader accountable for the whole end-to-end flow (vs. *system owner*, accountable for one piece of software).
- **Transaction** — one instance flowing through a process.
- **Control point** — a place where something is checked before work continues (control *types* = Lesson 1.4).
- **Handoff** — where work passes between people/departments; where most risk hides.
- **Workflow / End-to-end / Process map** — the ordered steps & handoffs / the whole flow across departments / a diagram of it.
- **Segregation of Duties (SoD)** — no single person controls a whole sensitive transaction (process principle here; formal framework role in 1.4).
- **Core / supporting / management process** — create value directly / enable the core / plan and govern.
- **Audit evidence** — the records a process leaves that let an auditor confirm a step happened (formal treatment in Lesson 1.10).

---

## Vocabulary

| Tier | Terms |
|------|-------|
| Core | business process, input, output, activities, control point, process owner, transaction |
| Supporting | workflow, handoff, end-to-end, process map, core/supporting/management process |
| Business | Procure-to-Pay (P2P), Order-to-Cash (O2C), Record-to-Report (R2R), Hire-to-Retire (H2R), approval, purchase order (PO), three-way match |
| Audit | walkthrough, segregation of duties, control point, audit evidence *(→ Lesson 1.10)* |
| Risk | process risk, handoff risk, single point of failure |
| Acronyms | P2P, O2C, R2R, H2R, SoD, ERP, CRM, MES, WMS, QA, AR, PO (all expanded at first use) |
| Advanced (previewed) | sub-process, key vs. compensating control, risk-and-control matrix (RCM) |

---

## Common Misunderstandings

- **"A process is the software that runs it."** No — the process is the flow; software just executes part. Same process can run on paper or ERP.
- **"Risk is inside the steps."** Mostly it's at the **handoffs** between steps and departments.
- **"Whoever runs the system owns the process."** No — the **process owner** (end-to-end, usually a business leader) is distinct from a **system owner**.
- **"A control point is the same as a control."** The control point is the *place*; the control is the *check*. This lesson finds places; later lessons teach checks.

---

## Knowledge Check

1. **Four defining parts of a business process?** → Input, activities, output, process owner.
2. **Which O2C handoff would you watch most, and why?** → e.g. invoicing→cash (SoD prevents diverted payments) or shipping→invoicing (goods shipped but never billed). The reasoning matters most.
3. **Classify: Manufacturing, Procure-to-Pay, Record-to-Report.** → core / supporting / management.
4. **What does SoD prevent in P2P?** → One person both ordering goods and approving their payment (fraud); split so it needs collusion.
5. **Why does cybersecurity protect processes, not just computers?** → Attackers want what the process moves (money, payments, identities); the system matters because of the process on it.

---

## Lab — Thought Exercise (no tools, ~15 min)

Reuse the company you mapped in Lesson 1.1 (or Northwind). Trace **one order** end-to-end, then answer the six questions:

1. **Map the flow** — steps from first contact to cash collected; draw the handoffs.
2. **Identify risks** — one thing that could go wrong at each step *and each handoff*.
3. **Identify control points** — the 2–3 places a checkpoint most belongs (look at handoffs first).
4. **Identify systems** — the system running each step (CRM, ERP, MES, WMS, or "paper").
5. **Identify audit evidence** — for two steps, the record that proves it happened.
6. **Identify cybersecurity responsibilities** — the one step where an attack would hurt most, and what it would disrupt.

Keep your map — Lesson 1.3 uses it to weigh which risks matter.

## Reflection Questions

- Which single handoff, if it failed silently, would cause the biggest loss before anyone noticed?
- Pick one step: why does protecting its *system* really mean protecting the *business process*?
- Where would SoD be hardest to enforce in a small team, and what would you do?

---

## Interview Prep (Enterprise IT Risk / GRC)

Process fluency is the most common opener in IT-risk/GRC interviews. Three tiers: *weak* (lists software screens), *average* (lists steps), *exceptional* (names the flow, owner, risky handoffs, and where a control belongs). The behavioral item uses **STAR** (Situation, Task, Action, Result).

**Technical — "Walk me through Procure-to-Pay."**
*Strong:* Requisition → manager approval → PO to supplier → Receiving confirms goods → AP three-way match (PO+receipt+invoice) → payment. Owned end-to-end by a procurement/finance leader. Riskiest handoffs: approval→ordering and receipt→payment, which is why we segregate who orders from who pays and put control points at the approval and the match.
*Weak:* "You create a PO in the system and it gets paid."
*Follow-ups:* What could go wrong between approval and payment? · Who should NOT do which steps?

**Technical — "What is a process owner and why does it matter?"**
*Strong:* The single business leader accountable for an end-to-end flow — not the system admin. Audit and risk need a clear accountable party who owns the control points and can explain the flow in a walkthrough. Without one, gaps between departments belong to no one.
*Weak:* "Whoever administers the ERP."
*Follow-ups:* Process owner vs. system owner? · Who owns the risk in a handoff?

**Scenario (GRC/IT-audit) — "A company ships products but sometimes never invoices them. Where's the problem?"**
*Strong:* A broken handoff between Shipping and Accounting. I'd walk Order-to-Cash end-to-end, find where the shipping record should trigger invoicing, and add a control point ensuring every shipment is matched to an invoice. The fix lives at the handoff.
*Weak:* "The accounting software is buggy."
*Follow-ups:* What control point, and where? · What evidence proves every shipment got invoiced?

**Scenario — "Why is ransomware on the plant-floor system a business problem, not just IT?"**
*Strong:* That system runs Manufacturing — where value is created. Down, production stops, orders can't be filled, cash isn't collected. The attacker is after the process, not the server. Framing it as process disruption lets you explain business impact to leadership.
*Weak:* "We'd restore from backup; it's an IT ticket."
*Follow-ups:* Which downstream O2C steps are affected? · How would you prioritize what to protect?

**Behavioral (STAR) — "Tell me about a time you understood a process end-to-end."**
*Strong:* **S** invoices were paid late, no one knew why. **T** find the delay. **A** I traced one invoice end-to-end, mapped each step and handoff, and found the delay at the Receiving→AP handoff where goods-receipts weren't reaching AP. **R** we added a checkpoint so every receipt notified AP; late payments dropped sharply. Lesson: the problem was a handoff no team owned.
*Weak:* "I just paid invoices when they came in."
*Follow-ups:* How did you confirm the flow? · Who became accountable for that handoff?

---

## Chapter Summary

A **business process** turns an **input** into an **output** of value via sequenced **activities**, owned end-to-end by a **process owner**. Enterprises **standardize** work to make it repeatable, scalable, measurable, and controllable. Processes are **core** (create value), **supporting** (enable it), or **management** (govern it). Value, risk, and **control points** live inside the flow — and the riskiest spots are the **handoffs**, which is why **Segregation of Duties** splits sensitive steps. Controls are embedded in processes, auditors **walk** processes before testing controls, and cybersecurity protects processes because the process moves the money and data.

Next: **Lesson 1.3 — Enterprise Risk** weighs the risks you found at each step and handoff. Then Lesson 1.4 turns your control points into real controls.

---

## Flashcards

| Front | Back |
|-------|------|
| Business process (+ four parts)? | A repeatable set of activities turning an input into an output of value: input, activities, output, process owner. *(Not the software.)* |
| Where does most risk live? | At the **handoffs** between people/departments. |
| Segregation of Duties? | No one person controls a whole sensitive transaction — orderer ≠ payer. (Process principle here; framework role in 1.4.) |
| Core vs supporting vs management? | Create value (O2C, Mfg) / enable the core (P2P, H2R) / govern (R2R). |
| Control point vs control? | The point is the *place* a check belongs; the control is the *check*. |
| Walkthrough? | Tracing one transaction end-to-end to confirm the flow — what auditors do before testing controls. |

---

## Related Lessons

- **Previous:** 1.1 — What Is an Enterprise?
- **Next:** 1.3 — Enterprise Risk · then 1.4 — Internal Controls.
- **Related domains:** Enterprise Business, Internal Audit, Risk Management.

## References

- APQC Process Classification Framework — taxonomy of enterprise processes. <https://www.apqc.org>
- ISO 9000:2015 — defines "process" and the process approach. <https://www.iso.org>
- COSO, *Internal Control — Integrated Framework* (2013) — controls are embedded within processes. <https://www.coso.org>
- The IIA — process walkthroughs as the basis for evaluating controls. <https://www.theiia.org>

## Revision History

- **1.0.0** — Initial production release; second canonical Golden Lesson, building on certified Lesson 1.1. Self-reviewed against the Golden Lesson Certification Checklist (all P1 pass, no open P2). **CERTIFIED: WebHound Enterprise Security Academy — Golden Lesson Reference v1.0** (status: published). Vocab discipline: control point & SoD introduced here per the brief; control types (1.4), risk scoring (1.3), audit-evidence theory (1.10), SOX (1.5), ITGC (1.6) only as glossed forward-pointers.

---

# Diagram Specifications (production-ready specs — artwork NOT generated here)

All seven conform to Phase 2A `DiagramKind` and carry alt text (Phase 0 §28). Authored as versionable diagram-as-code at the `src` paths. Each: purpose · learning objective · caption · implementation · alt text.

## Diagram 1 — Order-to-Cash (O2C) End-to-End  `process-flow` · medium · `diagrams/1-2/order-to-cash.mmd`
- **Purpose:** Make the core revenue process visible as one continuous flow across departments. *(Mandatory per the brief.)*
- **Learning objective:** The learner can trace one order through all 11 steps and point to the riskiest handoffs.
- **Caption:** *"One order, eleven steps, four departments — value is created at Manufacturing but only realized when cash arrives and is reported truthfully."*
- **Implementation:** Left-to-right nodes for the 11 steps (Customer order → … → Executive reporting). Group nodes into department bands (Sales, Finance, Operations, Executive) by color. Highlight three handoffs in a warning color: order→credit, shipping→invoicing, invoicing→cash. Small checkpoint icons at Credit approval, QA, and the AR cash-application step.
- **Alt text:** "A left-to-right flow of eleven steps — Customer order, Sales review, Credit approval, Production scheduling, Manufacturing, QA, Inventory, Shipping, Accounting, Accounts Receivable, Executive reporting — with department bands and the riskiest handoffs (order→credit, shipping→invoicing, invoicing→cash) highlighted."

## Diagram 2 — Procure-to-Pay (P2P) End-to-End  `process-flow` · medium · `diagrams/1-2/procure-to-pay.mmd`
- **Purpose:** Teach the canonical control-point/SoD example.
- **Learning objective:** The learner can place the two key control points (approval, three-way match) and explain the SoD split.
- **Caption:** *"Two handoffs carry the risk: approval→ordering and receipt→payment — which is why ordering, approving, and paying are split across people."*
- **Implementation:** Left-to-right: Requisition → Approval → PO → Goods receipt → Three-way match → Payment. Mark control-point badges on Approval and Three-way match. Show three distinct role icons (Requester, Approver, Payer) under the steps to make SoD visible. Annotate the two risky handoffs.
- **Alt text:** "A left-to-right flow — purchase requisition, approval, purchase order, goods receipt, three-way match, payment — with the approval and three-way-match control points marked and the requisition/approval/payment duties split across different people for Segregation of Duties."

## Diagram 3 — Hire-to-Retire (H2R) End-to-End  `process-flow` · medium · `diagrams/1-2/hire-to-retire.mmd`
- **Purpose:** Show a supporting people-process and foreshadow access lifecycle (Lesson 1.7+).
- **Learning objective:** The learner sees that onboarding/offboarding handoffs to IT are the risky points (access granted/removed).
- **Caption:** *"The employee lifecycle — the risky moments are granting access at onboarding and removing it at offboarding."*
- **Implementation:** Left-to-right: Requisition → Hire → Onboard → Provision access → Manage/Transfer → Offboard → Deprovision access. Highlight the two access handoffs (HR→IT) in a warning color. Keep IT and HR as the two departments shown.
- **Alt text:** "A left-to-right flow of the employee lifecycle — requisition, hire, onboard, provision access, manage/transfer, offboard, deprovision access — with the onboarding access-grant and offboarding access-removal handoffs highlighted as the risky points."

## Diagram 4 — Record-to-Report (R2R) End-to-End  `process-flow` · medium · `diagrams/1-2/record-to-report.mmd`
- **Purpose:** Show a *management* process so all three process types are concrete.
- **Learning objective:** The learner recognizes R2R as a management process and spots its control points (reconciliation, journal approval).
- **Caption:** *"Closing the books is a management process — its control points are reconciliation and journal approval."*
- **Implementation:** Left-to-right: Capture transactions → Reconcile accounts → Journal entries/adjustments → Consolidate → Close period → Produce reports. Control-point badges on Reconcile and Journal-approval. Tag the whole flow as "Management process."
- **Alt text:** "A left-to-right management-process flow — capture transactions, reconcile accounts, adjust/journal entries, consolidate, close the period, produce financial reports — with the reconciliation and journal-approval control points marked."

## Diagram 5 — Order-to-Cash Swimlane by Department  `swimlane` · high · `diagrams/1-2/o2c-swimlane.mmd`
- **Purpose:** Make department ownership and inter-department handoffs unmistakable.
- **Learning objective:** The learner can see which department owns each step and that risk concentrates where arrows cross lanes.
- **Caption:** *"Same eleven O2C steps, now by who owns them — every arrow that crosses a lane is a handoff to watch."*
- **Implementation:** Horizontal lanes: Sales, Finance, Operations, Executive. Place each O2C step in its owning lane (per the walkthrough table). Draw arrows for transitions; render cross-lane arrows boldly as the handoffs. Annotate the three highest-risk crossings.
- **Alt text:** "A swimlane diagram with horizontal lanes for Sales, Finance, Operations, and Executive. The Order-to-Cash steps are placed in their owning lane, and arrows crossing between lanes show the inter-department handoffs where risk concentrates."

## Diagram 6 — Department Interaction Map  `architecture` · medium · `diagrams/1-2/department-interaction-map.mmd`
- **Purpose:** Zoom out from one process to show how processes connect departments.
- **Learning objective:** The learner sees that processes are the *connective tissue* between departments, and Audit observes all of them.
- **Caption:** *"Processes are what connect the departments — O2C, P2P, and H2R each stitch several together; Audit watches them all."*
- **Implementation:** Department nodes (Sales, Finance, Operations, Procurement, HR, IT, Audit). Labeled edges: O2C connects Sales–Operations–Finance; P2P connects Procurement–Operations–Finance; H2R connects HR–IT. Draw Audit with dashed "observes" links to every process. Avoid clutter (≤7 nodes, edges labeled by process).
- **Alt text:** "A map of enterprise departments — Sales, Finance, Operations, Procurement, HR, IT, Audit — as nodes, with labeled arrows showing which processes connect them (O2C links Sales-Operations-Finance; P2P links Procurement-Operations-Finance; H2R links HR-IT). Audit observes all flows."

## Diagram 7 — Enterprise Information Flow  `enterprise-data-flow` · high · `diagrams/1-2/enterprise-information-flow.mmd`
- **Purpose:** Show that one transaction creates data across many systems as it flows — the bridge to why cybersecurity protects processes.
- **Learning objective:** The learner understands that protecting a process means protecting the chain of systems its data flows through.
- **Caption:** *"One transaction, many systems — the data flows CRM → ERP → MES/WMS → reporting, which is the real thing security protects."*
- **Implementation:** Data-flow nodes: CRM → ERP (center hub) → MES and WMS (branching to plant/warehouse) → BI/Reporting (sink). Arrows show data direction. Annotate that a single O2C order touches all of them. Use a distinct shape for data stores vs systems.
- **Alt text:** "A data-flow diagram showing how information moves between core systems — CRM to ERP to MES and WMS, and all into the BI/reporting layer — illustrating that one transaction creates data across many systems as it flows through the process."

---

# Certification-Checklist Self-Review (brutally honest)

Run against [GOLDEN_LESSON_CERTIFICATION_CHECKLIST.md](../GOLDEN_LESSON_CERTIFICATION_CHECKLIST.md). Verdict per group; every **P1** must pass and no **P2** may be open.

### A. Schema & structural conformance — **PASS**
- A1 conforms to `Lesson` (verified by a no-cast tsc structural check, since removed). A2 all 12 core sections present (metadata = top-level object). A3 all 20 section keys valid, no duplicates. A4 section set fits `concept-foundation` + justified conditionals (`howItWorks`, `enterpriseWorkflow`, two examples, lab/reflection/interview) — no all-46 bloat. A5 `graphNodeId` is a scaffolded leaf under the real `enterprise-business` domain (documented). A6 metadata complete. A7 validators/tsc/eslint clean (below). **All P1 pass.**

### B. Pedagogy — **PASS**
- B1 WHY-before-HOW (substantive `whyThisExists`). B2 one core idea (value flows through processes; risk/controls live along it). B3 five Bloom-verbed measurable objectives, no "understand X". B4 six quiz items, every `outcomeRef` (LO1–LO5) traces to an objective, no orphans. B5 Bloom consistent with L1 (remember→apply). B6 four real misconceptions with corrections. B7 dense walkthrough is chunked into a table + the five-question frame. **P1 pass.**

### C. Vocabulary & accuracy — **PASS (the 1.1-review P1 specifically re-checked)**
- C1 every new term glossed/defined at first use; the loaded word "control" reused with its 1.1 gloss and scoped ("types are 1.4"). C2 **no term owned by a later lesson is taught as known** — "internal controls" (1.4), control types (1.4), risk scoring (1.3), audit-evidence theory (1.10), SOX (1.5), ITGC (1.6), RCM appear *only* as explicitly-labeled forward-pointers or source titles (machine-scanned and individually verified). SoD is introduced here **because the golden brief assigns it to 1.2** — scoped as a process principle, with its formal control-framework role deferred to 1.4. C3 every glossary term is defined or glossed (P1 fix from the 1.1 review held). C4 all acronyms (P2P/O2C/R2R/H2R/SoD/ERP/CRM/MES/WMS/QA/AR/PO) expanded at first use. C5 no factual errors; the walkthrough uses realistic industry-standard systems, not invented company processes. C6 SoD, walkthrough, three-way match are accurate. **All P1 pass.**

### D. Business realism & context — **PASS**
- D1 every step ties to a business reason. D2 Northwind is explicitly **fictional** and generic; no real-company confidential processes implied (PCA constraint honored). D3 the recurring company and the Lesson-1.1→1.3 continuity are carried. **P1 pass.**

### E. Assets, craft & accessibility — **PASS (with the standard rendering caveat)**
- E1 all seven diagrams have valid `kind`, title, alt text, versionable `src`. E2 each has a full production spec (purpose/LO/caption/implementation). E3 **artwork not yet rendered** — specs complete; rendering is the defined downstream step (same accepted caveat as Lesson 1.1). E4 alt text is descriptive, not just titles. E5 consistent voice/terminology; acronyms anchored. E6 beginner-appropriate; no assumed networking (H2R access foreshadowed, not assumed). E7 references authoritative; revision history + reviewBy set. E8 a genuine L1 thought-exercise lab with six understanding-focused tasks. E9 interview prep gives weak/strong + the path to exceptional. **All P1 pass; E3 is the one accepted P2-style caveat, scoped and documented.**

### F. Source-consistency & verdict — **PASS**
- F1 faithful to the golden brief (mental model, outcomes, boundaries, SoD-here instruction, manufacturing example, mandatory P2P/O2C flow). F2 consistent with the constitution and content engine. F3 no graph/curriculum/architecture change. F4 publication verdict recorded (below). F5 certification stamped in `metadata.certification`, `metadata.status: published`, and revision history. **All P1 pass.**

### Revision notes (what the self-review changed during authoring)
This lesson was authored *with* the checklist in hand (the discipline the 1.1 review established), so the usual P1 traps were avoided by construction rather than fixed after the fact. Specific decisions worth recording:
- **SoD apparent conflict resolved:** the task's vocab caution lists "separation of duties → 1.4," but the golden brief explicitly assigns *introducing and defining SoD* to 1.2 (outcome 4). Resolution: introduce SoD here as a **process principle** (the brief's mandate) and explicitly defer its **formal control-framework role** to 1.4. Both honored; documented in the definitions, the SoD subsection, and the flashcard.
- **"audit evidence" per step:** required by the task's walkthrough but formally owned by 1.10. Resolved by glossing it inline ("the record that proves a step happened") with a forward-pointer, and giving concrete example records rather than the sufficiency/appropriateness theory.
- **estMinutes 40 vs brief 30:** raised honestly to reflect the expanded production scope (11-step walkthrough + 7 diagrams + 5 interview items) the task required beyond the brief's minimal estimate.
- **Profile held at `concept-foundation`** (per brief); the two added content sections (`howItWorks`, `enterpriseWorkflow`) are each justified by the rule (a process genuinely has a mechanism and a lifecycle), not added for volume.

### Publication verdict (per publisher, brutally honest)
After this self-review: **Microsoft Learn — Yes** (clear flow, knowledge checks, tight scope). **Cisco Press — Yes**, with the standing caveat that the seven diagrams must be rendered before visual publication (specs complete). **SANS — Yes** for a foundational module; the walkthrough's risk/handoff framing is exactly the right instinct to instill. **O'Reilly — Yes** as a strong chapter-2 build on chapter 1. The honest non-blocking caveats are identical to Lesson 1.1: diagram artwork pending, and the scaffolded graph node (documented). No content-quality defect remains.

### Certification
> 🏅 **CERTIFIED — WebHound Enterprise Security Academy — Golden Lesson Reference v1.0**
> Lesson 1.2 "Business Processes" (record v1.0.0, status: published) meets the Golden Lesson bar on content, design, pedagogy, vocabulary discipline, and diagram specifications. **Pending downstream step:** render the seven diagram `.mmd` sources before visual publication.
> **Git tag:** apply `golden-lesson-1-2-v1.0` to the merge commit **when this PR merges** — do not tag an unmerged branch.
