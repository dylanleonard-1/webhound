# AWS WAF managed rule groups

Source: https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html
Provider: AWS WAF | Authority: Tier A
Ingested: 2026-06-13 | Terms: AWS docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Using managed rule groups in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director
View a markdown version of this page              Using managed rule groups in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director                   Documentation  AWS WAF  Developer Guide         Introducing a new console experience for AWS WAF   You can now use the updated experience to access AWS WAF functionality anywhere in the console.
For more details, see  Working with the console .
Using managed rule groups in AWS WAF        This section explains what managed rule groups are and how they work.  Managed rule groups are collections of predefined, ready-to-use rules that AWS and AWS Marketplace sellers
write and maintain for you. Basic AWS WAF pricing applies to your use of any managed rule group.
For AWS WAF pricing information, see   AWS WAF Pricing    .
The AWS Managed Rules rule groups for AWS WAF Bot Control, AWS WAF Fraud Control account takeover prevention (ATP), and AWS WAF Fraud Control account creation fraud prevention (ACFP)  are available
for additional fees, beyond the basic AWS WAF charges. For pricing details, see   AWS WAF Pricing    .
All other AWS Managed Rules rule groups  are available to AWS WAF customers
at no additional cost.
AWS Marketplace rule groups  are available by subscription through AWS Marketplace.
Each of these rule groups is owned and managed by the AWS Marketplace seller. For
pricing information to use an AWS Marketplace rule group, contact the AWS Marketplace seller.
Some managed rule groups are designed to help protect specific types of web applications like
WordPress, Joomla, or PHP. Others offer broad protection against known threats or common web
application vulnerabilities, including some of the ones listed in the   OWASP Top
10    . If you're subject to regulatory
compliance like PCI or HIPAA, you might be able to use managed rule groups to satisfy web
application firewall requirements.  Automatic updates
Keeping up to date on the constantly changing threat landscape can be time consuming and
expensive. Managed rule groups can save you time when you implement and use AWS WAF.
Many AWS and AWS Marketplace sellers automatically update managed rule groups and provide
new versions of rule groups when new vulnerabilities and threats emerge.   In some cases, AWS is notified of new vulnerabilities before public disclosure, due to its
participation in a number of private disclosure communities. In those cases, AWS can
update the AWS Managed Rules rule groups and deploy them for you even before a new threat is widely known.
Restricted access to rules in a managed rule group
Each managed rule group provides a comprehensive description of the types of attacks and
vulnerabilities that it's designed to protect against. To protect the intellectual
property of the rule group providers, you can't view all of the details for the
individual rules within a rule group. This restriction also helps to keep malicious
users from designing threats that specifically circumvent published rules.
Topics     Using versioned managed rule groups in AWS WAF      Working with managed rule groups      AWS Managed Rules for AWS WAF                     Javascript is disabled or is unavailable in your browser.   To use the Amazon Web Services Documentation, Javascript must be enabled. Please refer to your browser's Help pages for instructions.         Document Conventions    AWS WAF rule groups  Using versioned managed rule groups        Did this page help you? - Yes   Thanks for letting us know we're doing a good job!  If you've got a moment, please tell us what we did right so we can do more of it.         Did this page help you? - No   Thanks for letting us know this page needs work. We're sorry we let you down.  If you've got a moment, please tell us how we can make the documentation better.
