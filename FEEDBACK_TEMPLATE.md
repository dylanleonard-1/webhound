# WebHound Alpha — Tester Feedback Template

Complete this after your testing session and return it to the maintainer.
Your feedback shapes the roadmap — be honest and specific.

---

## Tester Information

| Field | Your value |
|---|---|
| Name / handle | |
| Testing date | |
| Session duration (hours) | |
| OS and Docker version | |
| git commit tested | (output of `git rev-parse --short HEAD`) |

---

## Setup Experience

**Time to get the stack running** (circle one):  
Under 5 min / 5–10 min / 10–20 min / Over 20 min

**Did you hit any blockers during setup?**  
[ ] No — everything worked on first try  
[ ] Minor friction — describe below  
[ ] Major blocker — could not complete setup — describe below

Setup notes:

---

## Demo Flow Ratings

Rate each step: ✓ = smooth / ~ = had friction / ✗ = failed or gave up

| Step | Rating | Notes |
|---|---|---|
| 1. Start stack (`docker compose up --build`) | | |
| 2. Create account | | |
| 3. Log in | | |
| 4. Add authorized website | | |
| 5. Start scan | | |
| 6. Wait for scan to complete | | |
| 7. View scan results and findings | | |
| 8. Download a report (any format) | | |
| 9. Create a weekly schedule | | |
| 10. View notification after scan | | |

---

## Findings Quality

**Did the findings for your test target seem accurate?**  
[ ] Yes, findings were relevant and actionable  
[ ] Mostly — some false positives present  
[ ] No — mostly noise or clearly wrong  
[ ] Couldn't assess (only tested with `example.com`)

**Were any obvious security issues missing from the results?**  
(Describe the issue and the URL, if you're comfortable sharing)

**Were there false positives you're confident about?**  
(Describe the finding and why you believe it's incorrect)

---

## API and Error Messages

**Were API error messages clear and actionable?**  
[ ] Yes / [ ] Mostly / [ ] No  
Examples of unclear errors:

**Did you encounter any 500 errors or unexpected responses?**  
[ ] Yes (describe + include in a bug report) / [ ] No

---

## Frontend Observations

**Which frontend pages worked well?**

**Which frontend pages had problems or were confusing?**

**Was there anything missing from the UI that you expected to find?**

---

## Performance

**How long did the `quick` scan take for your test target?**  
(approximate seconds)

**Did you experience any hangs, timeouts, or unresponsive states?**

**Docker resource usage** (optional — check `docker stats` during a scan):  
CPU spike: ____% | Peak memory: ____MB

---

## Feature Feedback

**Was there a feature you expected but didn't find?**

**Is there anything that felt over-engineered or unnecessary?**

**What was the most useful part of the tool?**

**What was the least useful or most confusing part?**

---

## Documentation

**Were the setup instructions (`TESTER_SETUP.md`) clear enough to follow without help?**  
[ ] Yes / [ ] Mostly / [ ] No — I had to guess at step(s): ____

**Was the `KNOWN_LIMITATIONS.md` honest and accurate based on your experience?**  
[ ] Yes / [ ] Partly — I found limitations not listed there: ____

---

## Overall Assessment

**On a scale of 1–10, how close is this to being ready for a wider beta?**  
(1 = needs significant work / 10 = ship it now)

Score: ___/10

**What is the single most important thing to fix before the next phase?**

**Would you recommend this tool to a colleague once it's polished?**  
[ ] Yes / [ ] Maybe / [ ] No — reason:

**Any other comments or suggestions?**

---

## Consent

[ ] I consent to this feedback being used to improve WebHound.  
[ ] Please keep my name/handle anonymous in any shared summaries.  
[ ] I am happy to be contacted for a follow-up conversation.
