# DalFox — Parameter Mining

**Tool:** DalFox · **Concept:** parameter mining

Many vulnerabilities hide behind **parameters the crawler never saw**. DalFox
**parameter mining** discovers additional injectable inputs by: testing a built-in
dictionary of common parameter names, mining candidate names from the page itself
(form fields, JS variables, `data-` attributes, inline script, comments), and
observing which added parameters change the response (reflection or behavioural
difference). Newly found parameters are then run through the normal reflect→validate
pipeline.

**Why it matters for WebHound:** detection coverage is bounded by input discovery —
a perfect XSS/SQLi check finds nothing on a parameter it never tried. Parameter
mining is a **recall** technique: it widens the attack surface before validation.
For WebHound this informs the crawler/forms engines (extract candidate parameters
from page artefacts) and the Phase-9 audit question *"are we discovering all the
inputs a finding could live on?"* It pairs with strict validation so wider coverage
does not inflate false positives.

**Related:** [[dalfox-xss-validation]], [[xsstrike-payload-generation]], [[scanner-audit-recommendations]].
