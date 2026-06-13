# AWS WAF rate-based rules

Source: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
Provider: AWS WAF | Authority: Tier A
Ingested: 2026-06-13 | Terms: AWS docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Using rate-based rule statements in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director
View a markdown version of this page              Using rate-based rule statements in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director                   Documentation  AWS WAF  Developer Guide         Introducing a new console experience for AWS WAF   You can now use the updated experience to access AWS WAF functionality anywhere in the console.
For more details, see  Working with the console .
Using rate-based rule statements in AWS WAF        This section explains what a rate-based rule statement is and how it works.  A rate-based rule counts incoming requests and rate limits requests when they are coming at
too fast a rate. The rule aggregates requests according to your criteria, and counts and
rate limits the aggregate groupings, based on the rule's evaluation window, request limit, and
action settings.       Note    You can also rate limit web requests using the targeted protection level
of the Bot Control AWS Managed Rules rule group. Using this managed rule group incurs additional fees. For more
information, see  Options for rate limiting in rate-based rules and targeted Bot Control rules .     AWS WAF tracks and manages web requests separately for each instance of a rate-based rule
that you use. For example, if you provide the same rate-based rule settings in two web
ACLs, each of the two rule statements represents a separate instance of the rate-based
rule and each gets its own tracking and management by AWS WAF. If you define a rate-based
rule inside a rule group, and then use that rule group in multiple places, each use
creates a separate instance of the rate-based rule that gets its own tracking and
management by AWS WAF.   Not nestable  – You can't nest this
statement type inside other statements. You can include it directly in a protection pack (web ACL)
or rule group.    Scope-down statement  – This rule type can take a
scope-down statement, to narrow the scope of the requests that the rule tracks and rate
limits. The scope-down statement can be optional or required, depending on your other
rule configuration settings. The details are covered in this section. For general information about scope-down statements, see
Using scope-down statements in AWS WAF .    WCUs  – 2, as a base cost. For each custom
aggregation key that you specify, add 30 WCUs. If you use a scope-down statement in the
rule, calculate and add the WCUs for that.
Where to find this rule statement
Rule builder  in your protection pack (web ACL), on the
console – Under  Rule , for
Type , choose  Rate-based
rule .
API  –
RateBasedStatement
Topics     Rate-based rule high-level settings in AWS WAF      Rate-based rule caveats in AWS WAF      Aggregating rate-based rules in AWS WAF      Rate-based rule aggregation instances and counts      Applying rate limiting to requests in AWS WAF      Rate-based rule examples in AWS WAF      Listing IP addresses that are being rate limited by rate-based rules                   Javascript is disabled or is unavailable in your browser.   To use the Amazon Web Services Documentation, Javascript must be enabled. Please refer to your browser's Help pages for instructions.         Document Conventions    OR
logic  Rate-based rule high-level settings        Did this page help you? - Yes   Thanks for letting us know we're doing a good job!  If you've got a moment, please tell us what we did right so we can do more of it.         Did this page help you? - No   Thanks for letting us know this page needs work. We're sorry we let you down.  If you've got a moment, please tell us how we can make the documentation better.
