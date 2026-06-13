# AWS WAF overview

Source: https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html
Provider: AWS WAF | Authority: Tier A
Ingested: 2026-06-13 | Terms: AWS docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

What are AWS WAF, AWS Shield Advanced, AWS Shield network security director and AWS Firewall Manager? - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director
View a markdown version of this page              What are AWS WAF, AWS Shield Advanced, AWS Shield network security director and AWS Firewall Manager? - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director                   Documentation  AWS WAF  Developer Guide    AWS WAF  Shield Advanced  AWS Shield network security director  AWS Firewall Manager           Introducing a new console experience for AWS WAF   You can now use the updated experience to access AWS WAF functionality anywhere in the console.
For more details, see  Working with the console .
What are AWS WAF, AWS Shield Advanced, AWS Shield network security director and AWS Firewall Manager?        You can use  AWS WAF ,  AWS Shield , and  AWS Firewall Manager  together to create a comprehensive
security solution. AWS WAF is a web application firewall that you can use to monitor web requests
that your end users send to your applications and to control access to your content.
Shield Advanced provides protection against distributed denial of service (DDoS) attacks
for AWS resources, at the network and transport layers (layer 3 and 4) and the application layer (layer 7).
AWS Firewall Manager provides management of protections like AWS WAF and Shield Advanced across accounts and resources,
even as new resources are added.    Topics     What is AWS WAF?      What is AWS Shield Advanced?      What is AWS Shield network security director?      What is AWS Firewall Manager?
What is AWS WAF?
AWS WAF is a web application firewall that lets you monitor the HTTP and HTTPS requests that
are forwarded to your protected web application resources. You can protect the following
resource types:
Amazon CloudFront distribution    Amazon API Gateway REST API    Application Load Balancer    AWS AppSync GraphQL API    Amazon Cognito user pool    AWS App Runner service    AWS Verified Access instance    AWS Amplify
AWS WAF lets you control access to your content. Based on conditions that you specify,
such as the IP addresses that requests originate from or the values of query strings, your
protected resource responds to requests either with the requested content, with an HTTP 403
status code (Forbidden), or with a custom response.
At the simplest level, AWS WAF lets you choose one of the following behaviors:
Allow all requests except the ones that you
specify  – This is useful when you want Amazon CloudFront, Amazon API Gateway, Application Load Balancer, AWS AppSync, Amazon Cognito, AWS App Runner, or AWS Verified Access to
serve content for a public website, but you also want to block requests from
attackers.
Block all requests except the ones that you
specify  – This is useful when you want to serve content for a
restricted website whose users are readily identifiable by properties in web
requests, such as the IP addresses that they use to browse to the website.
Count requests that match your criteria  – You can
use the Count action to track your web traffic without modifying how you handle it.
You can use this for general monitoring and also to test your new web request
handling rules. When you want to allow or block requests based on new properties in
the web requests, you can first configure AWS WAF to count the requests that match
those properties. This lets you confirm your new configuration settings before you
switch your rules to allow or block matching requests.
Run CAPTCHA or challenge checks against requests that match your
criteria  – You can implement CAPTCHA and silent challenge controls
against requests to help reduce bot traffic to your protected resources.
Using AWS WAF has several benefits:
Additional protection against web attacks using criteria that you specify. You
can define criteria using characteristics of web requests such as the
following:
IP addresses that requests originate from.
Country that requests originate from.
Values in request headers.
Strings that appear in requests, either specific strings or strings that
match regular expression (regex) patterns.
Length of requests.
Presence of SQL code that is likely to be malicious (known as  SQL injection ).
Presence of a script that is likely to be malicious (known as  cross-site scripting ).
Rules that can allow, block, or count web requests that meet the specified
criteria. Alternatively, rules can block or count web requests that not only meet
the specified criteria, but also exceed a specified number of requests in a minute
or in five minutes.
Rules that you can reuse for multiple web applications.
Managed rule groups from AWS and AWS Marketplace sellers.
Real-time metrics and sampled web requests.
Automated administration using the AWS WAF API.
If you want granular control over the protections that you add to your resources, AWS WAF
alone might be the right choice. For more information about AWS WAF, see  AWS WAF .
What is AWS Shield Advanced?
You can use AWS WAF web access control lists (web ACLs) to help minimize the effects of a
Distributed Denial of Service (DDoS) attack. For additional protection against DDoS
attacks, AWS also provides AWS Shield Standard and AWS Shield Advanced. AWS Shield Standard is
automatically included at no extra cost beyond what you already pay for AWS WAF and your
other AWS services.
Shield Advanced provides expanded DDoS attack protection for your
Amazon EC2 instances, Elastic Load Balancing load balancers, CloudFront distributions, Route 53 hosted zones, and AWS Global Accelerator standard accelerators.
Shield Advanced incurs additional charges. Shield Advanced options and features include automatic application layer DDoS mitigation, advanced event visibility, and dedicated
support from the Shield Response Team (SRT). If you own high visibility websites or are otherwise
prone to frequent DDoS attacks, 
