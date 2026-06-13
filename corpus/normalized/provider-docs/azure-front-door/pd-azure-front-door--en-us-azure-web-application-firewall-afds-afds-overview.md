# Azure WAF on Front Door overview

Source: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview
Provider: Azure Front Door + WAF | Authority: Tier A
Ingested: 2026-06-13 | Terms: Azure docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

What is Azure Web Application Firewall on Azure Front Door? | Microsoft Learn
Skip to main content
Skip to Ask Learn chat experience
This browser is no longer supported.
Upgrade to Microsoft Edge to take advantage of the latest features, security updates, and technical support.
Download Microsoft Edge
More info about Internet Explorer and Microsoft Edge
Table of contents
Exit editor mode
Ask Learn
Ask Learn
Reading mode
Table of contents
Read in English
Add
Add to plan
Edit
Copy Markdown
Print
Note
Access to this page requires authorization. You can try  signing in  or  changing directories .
Access to this page requires authorization. You can try  changing directories .
Azure Web Application Firewall on Azure Front Door
Feedback
Summarize this article for me
In this article
Applies to:  ✔️ Front Door Standard/Premium ✔️ Front Door (classic) ✔️ CDN Standard from Microsoft (classic)
Azure Web Application Firewall on Azure Front Door provides centralized protection for your web applications. A web application firewall (WAF) defends your web services against common exploits and vulnerabilities. It keeps your service highly available for your users and helps you meet compliance requirements.
Azure Web Application Firewall on Azure Front Door is a global and centralized solution. It's deployed on Azure network edge locations around the globe. WAF-enabled web applications inspect every incoming request delivered by Azure Front Door at the network edge.
A WAF prevents malicious attacks close to the attack sources before they enter your virtual network. You get global protection at scale without sacrificing performance. A WAF policy easily links to any Azure Front Door profile in your subscription. New rules can be deployed within minutes, so you can respond quickly to changing threat patterns.
Note
For web workloads, we highly recommend that you use  Azure DDoS Protection  and a  web application firewall  to safeguard against emerging DDoS attacks. Another option is to employ  Azure Front Door  along with a web application firewall. Azure Front Door offers  platform-level protection  against network-level DDoS attacks. For more information, see  Security baseline for Azure services .
Azure Front Door has  two tiers :
Standard
Premium
Azure Web Application Firewall is natively integrated with Azure Front Door Premium with full capabilities. For Azure Front Door Standard, only  custom rules  are supported.
Protection
Azure Web Application Firewall protects your:
Web applications from web vulnerabilities and attacks without modifications to back-end code.
Web applications from malicious bots with the IP Reputation Rule Set.
Applications against DDoS attacks. For more information, see  Application DDoS protection .
WAF policy and rules
You can configure a  WAF policy  and associate that policy to one or more Azure Front Door domains for protection. A WAF policy consists of two types of security rules:
Custom rules that the customer created.
Managed rule sets that are a collection of Azure-managed preconfigured sets of rules.
When both are present, custom rules are processed before processing the rules in a managed rule set. A rule is made of a match condition, a priority, and an action. Action types supported are ALLOW, BLOCK, LOG, and REDIRECT. You can create a fully customized policy that meets your specific application protection requirements by combining managed and custom rules.
Rules within a policy are processed in a priority order. Priority is a unique integer that defines the order of rules to process. A smaller integer value denotes a higher priority, and those rules are evaluated before rules with a higher integer value. After a rule is matched, the corresponding action that was defined in the rule is applied to the request. After such a match is processed, rules with lower priorities aren't processed further.
A web application delivered by Azure Front Door can have only one WAF policy associated with it at a time. However, you can have an Azure Front Door configuration without any WAF policies associated with it. If a WAF policy is present, it's replicated to all of our edge locations to ensure consistent security policies across the world.
WAF modes
You can configure a WAF policy to run in two modes:
Detection : When a WAF runs in detection mode, it only monitors and logs the request and its matched WAF rule to WAF logs. It doesn't take any other actions. You can turn on logging diagnostics for Azure Front Door. When you use the portal, go to the  Diagnostics  section.
Prevention : In prevention mode, a WAF takes the specified action if a request matches a rule. If a match is found, no further rules with lower priority are evaluated. Any matched requests are also logged in the WAF logs.
WAF actions
WAF customers can choose to run from one of the actions when a request matches a rule's conditions:
Allow : The request passes through the WAF and is forwarded to the origin. No further lower priority rules can block this request.
Block : The request is blocked and the WAF sends a response to the client without forwarding the request to the origin.
Log : The request is logged in the WAF logs and the WAF continues evaluating lower priority rules.
Redirect : The WAF redirects the request to the specified URI. The URI specified is a policy-level setting. After configuration, all requests that match the  Redirect  action are sent to that URI.
Anomaly score : The total anomaly score is increased incrementally when a rule with this action is matched. This default action is for Default Rule Set 2.0 or later. It isn't applicable for the Bot Manager Rule Set.
WAF rules
A WAF policy can consist of two types of security rules:
Custom rules, authored by the customer and managed rule sets
Azure-managed preconfigured sets of rules
Custom-authored rules
To configure custom rules for a WAF, use the following controls:
IP allow list and block list : You can control access to your web applications based on a 
