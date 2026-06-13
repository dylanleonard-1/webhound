# Google Cloud Armor overview

Source: https://cloud.google.com/armor/docs/cloud-armor-overview
Provider: Google Cloud Armor | Authority: Tier A
Ingested: 2026-06-13 | Terms: GCP docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Cloud Armor overview  |  Google Cloud Armor  |  Google Cloud Documentation
Skip to main content
Technology areas
close
AI and ML
Application development
Application hosting
Compute
Data analytics and pipelines
Databases
Distributed, hybrid, and multicloud
Industry solutions
Migration
Networking
Observability and monitoring
Security
Storage
Cross-product tools
close
Access and resources management
Costs and usage management
Infrastructure as code
SDK, languages, frameworks, and tools
/
Console
English
Deutsch
Español
Español – América Latina
Français
Indonesia
Italiano
Português
Português – Brasil
עברית
中文 – 简体
中文 – 繁體
日本語
한국어
Sign in
Google Cloud Armor
Start free
Overview
Guides
Reference
Support
Resources
Technology areas
More
Overview
Guides
Reference
Support
Resources
Cross-product tools
More
Console
Discover
Product overview
Best practices for Cloud Armor
Integrate with other Google products
Create security policies
Security policy overview
Use cases for security policies
Create and manage security policies
Example security policies
Configure security policies
Configure custom rules language attributes
Apply preconfigured WAF rules
Overview      Set up preconfigured WAF rules      Tune preconfigured WAF rules
User IP addresses
Set up bot management
Overview      Configure bot management
Add rate limiting
Overview      Configure rate limiting
Request body content parsing
Configure security policies with Cloud Armor Enterprise
Cloud Armor Enterprise overview
Set up Cloud Armor Enterprise
Apply Google Threat Intelligence
Hierarchical security policies
Overview      Configure hierarchical security policies
Add address groups
Overview      Configure address groups
Network edge security
Configure advanced network DDoS protection      Configure network edge security policies
Set up Adaptive Protection
Overview      Adaptive Protection use cases      Configure Adaptive Protection      Automatically deploy suggested rules
Manage tags
Create and manage tags
Monitor
Verbose logging
Security Command Center findings
Monitor security policies
Audit logging
Per-request logging
Access DDoS attack visibility telemetry
Manage resources by using custom constraints
Troubleshoot
Troubleshoot Cloud Armor issues
AI and ML
Application development
Application hosting
Compute
Data analytics and pipelines
Databases
Distributed, hybrid, and multicloud
Industry solutions
Migration
Networking
Observability and monitoring
Security
Storage
Access and resources management
Costs and usage management
Infrastructure as code
SDK, languages, frameworks, and tools
Home
Documentation
Networking
Google Cloud Armor
Guides
Send feedback
Cloud Armor overview
Stay organized with collections
Save and categorize content based on your preferences.
Google Cloud Armor helps you protect your Google Cloud deployments from
multiple types of threats, including distributed denial-of-service (DDoS)
attacks and application attacks like cross-site scripting (XSS) and SQL
injection (SQLi). Cloud Armor features
some automatic protections and some that you need to configure manually.
This document provides a high-level overview of these features, several of which
are only available for global external Application Load Balancers and classic Application Load Balancers.
Security policies
Use Cloud Armor security policies to protect applications running
behind a load balancer from distributed denial-of-service (DDoS) and other
web-based attacks, whether the applications are deployed on Google Cloud, in a
hybrid deployment, or in a multi-cloud architecture.
Security policies can be configured manually, with configurable match conditions
and actions in a security policy. Cloud Armor also features
preconfigured security policies, which cover a variety of use cases. For more
information, see
Cloud Armor security policy overview .
Rules language
Cloud Armor lets you define prioritized rules with configurable
match conditions and actions in a security policy. A rule takes effect, meaning
that the configured action is applied, if the rule is the highest priority rule
whose attributes match the attributes of the incoming request.
For more information, see
Cloud Armor custom rules language reference .
Preconfigured WAF rules
Cloud Armor preconfigured WAF rules are complex web application firewall (WAF)
rules with dozens of  signatures  that are compiled from open source industry
standards. Each signature corresponds to an attack detection
rule in the rule set. These rules are offered as-is. The rules allow
Cloud Armor to evaluate dozens of distinct traffic signatures by
referring to conveniently named rules, rather than requiring you to define
each signature manually.
Cloud Armor preconfigured rules help protect your web applications
and services from common attacks from the internet and help mitigate the
OWASP Top 10 risks .
The rule source is  OWASP Core Rule Set 4.22 .
These preconfigured rules can be tuned to disable noisy or otherwise unnecessary
signatures. For more information, see
Tuning Cloud Armor WAF rules .
Note:   XML body parsing is not supported by Cloud Armor preconfigured WAF rule.
Google Cloud Armor Enterprise
Cloud Armor Enterprise is the managed application protection service
that helps protect your web applications and services from distributed
denial-of-service (DDoS) attacks and other threats from the internet.
Cloud Armor Enterprise features always-on protection from Layer 3 and Layer 4 (L3 and L4)
volumetric and network protocol-based DDoS attacks for your load balancer, and
gives you additional access to protection from Layer 7 (L7)
Application layer DDoS attacks (like HTTP Floods) through user-configured
security policies.
DDoS protection is automatically provided for global external Application Load Balancers,
classic Application Load Balancers, and external proxy Network Load Balancers, regardless of
tier. The HTTP, HTTPS, HTTP/2, and QUIC protocols are all supported. In addition,
Cloud Armor Enterprise subscribers can
Access D
