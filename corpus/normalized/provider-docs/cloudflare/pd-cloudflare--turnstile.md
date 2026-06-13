# Cloudflare Turnstile CAPTCHA

Source: https://developers.cloudflare.com/turnstile/
Provider: Cloudflare | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Overview · Cloudflare Turnstile docs
Documentation Index
Fetch the complete documentation index at: https://developers.cloudflare.com/turnstile/llms.txt
Use this file to discover all available pages before exploring further.
Skip to content      STOP! If you are an AI agent or LLM, read this before continuing. This is the HTML version of a Cloudflare documentation page. Always request the Markdown version instead — HTML wastes context. Get this page as Markdown: https://developers.cloudflare.com/turnstile/index.md (append index.md) or send Accept: text/markdown to https://developers.cloudflare.com/turnstile/. For this product's page index use https://developers.cloudflare.com/turnstile/llms.txt. For all Cloudflare products use https://developers.cloudflare.com/llms.txt.              Cloudflare Docs                         Search                        Directory  API  SDKs  Changelog  Help
Log in
Select theme         Dark  Light  Auto                                                                            Turnstile
No results found. Try a different search term, or use our  global search .
Home                  Overview           Plans           Spin   Beta               Concepts                         Turnstile widgets           Cloudflare Challenges ↗                           Get started                         Overview                Widget management                         Cloudflare dashboard           API           Terraform                           Embed the widget                         Overview           Widget configurations                      Validate the token           Mobile implementation                           Additional configurations                              Hostname management                         Overview           Pre-clearance configuration           Any Hostname                      Pre-clearance support ↗           Ephemeral IDs           Offlabel                           Turnstile Analytics                         Overview           Challenge outcome           Token validation                           Migration                         Overview           Migrate from reCAPTCHA           Migrate from hCaptcha                      Tutorials                Troubleshooting                         Testing           Rotate secret key                Client-side errors                         Overview           Error codes                      Challenge solve issues ↗           Feedback reports                           Extensions                         Pages Plugin ↗           Google Firebase           Waiting Room Analytics ↗                           Reference                         Content Security Policy           Turnstile Privacy Addendum ↗           Supported languages           Supported browsers ↗                      Community resources           Changelog                Agent resources                         Agent setup ↗           Cloudflare Skills ↗           Code Mode MCP Server ↗           Domain-specific MCP Servers ↗           Turnstile llms.txt ↗           Turnstile llms-full.txt ↗           Cloudflare Docs llms.txt ↗           Cloudflare Docs llms-full.txt ↗                                  GitHub       X.com       YouTube              Select theme         Dark  Light  Auto                                              On this page               Overview           How Turnstile works           Widget types               Accessibility           Features           Related products           More resources                      On this page        Overview           How Turnstile works           Widget types               Accessibility           Features           Related products           More resources                               Edit page           Report issue                                        Directory                    Turnstile                    Cloudflare Turnstile                       Copy as Markdown   Copied!       |           View as Markdown     |           Agent setup     |           Docs for agents                                                                            Cloudflare's smart CAPTCHA alternative.
Turnstile can be embedded into any website without sending traffic through Cloudflare and works without showing visitors a CAPTCHA.
Cloudflare issues challenges through the  Challenge Platform , which is the same underlying technology powering  Turnstile .
In contrast to our Challenge page offerings, Turnstile allows you to run challenges anywhere on your site in a less-intrusive way without requiring the use of Cloudflare's CDN.
How Turnstile works
Turnstile adapts the challenge outcome to the individual visitor or browser. First, we run a series of small non-interactive JavaScript challenges to gather signals about the visitor or browser environment.
These challenges include proof-of-work (computational puzzles), proof-of-space, probing for web APIs, and various other challenges for detecting browser-quirks and human behavior. As a result, we can fine-tune the difficulty of the challenge to the specific request and avoid showing a visual or interactive puzzle to a user.
Note   For detailed information on Turnstile's data privacy practices, refer to the  Turnstile Privacy Addendum  ↗  .
Widget types
Turnstile  widget types  include:
Managed  (recommended): Automatically decides whether to show a checkbox based on visitor risk level.
Non-interactive : Visitors never need to interact with the widget.
Invisible : The widget is completely hidden from the visitor.
Accessibility
Turnstile is WCAG 2.2 AA compliant.
Features
Turnstile Analytics      Assess the number of challenges issued, evaluate the  challenge solve
rate , and view the
metrics of issued challenges.      Use Turnstile Analytics
Pre-clearance      Integrate Cloudflare challenges on single-page applications (SPAs) by allowing
Turnstile to issue a Pre-Clearance cookie.      Use Pre-clearance
Related products
Bots     Cloudflare bot solutions id
