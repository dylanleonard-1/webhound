# Azure Front Door overview

Source: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview
Provider: Azure Front Door + WAF | Authority: Tier A
Ingested: 2026-06-13 | Terms: Azure docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Azure Front Door Overview | Microsoft Learn
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
What is Azure Front Door?
Feedback
Summarize this article for me
In this article
Whether you're delivering content and files or developing global applications and APIs, Azure Front Door enhances your user experience by providing higher availability, reduced latency, increased scalability, and improved security. It provides these benefits no matter where your users are located.
Azure Front Door is an advanced content delivery network (CDN) for the cloud. It's designed to provide fast, reliable, and secure access to your applications' static and dynamic web content globally. By using Microsoft's extensive global edge network, Azure Front Door provides efficient content delivery through  global and local points of presence (PoPs)  strategically positioned close to both enterprise and consumer users.
Note
For web workloads, we highly recommend that you use  Azure DDoS Protection  and a  web application firewall  to safeguard against emerging DDoS attacks. Another option is to employ  Azure Front Door  along with a web application firewall. Azure Front Door offers  platform-level protection  against network-level DDoS attacks. For more information, see  Security baseline for Azure services .
Azure Front Door is one of the services in the category of load-balancing and content delivery services in Azure. Other services in this category include  Azure Load Balancer  and  Azure Application Gateway . Each service has its own unique features and use cases. For more information on this service category, see  What is load balancing and content delivery?
Why use Azure Front Door?
Azure Front Door enables internet-facing applications to:
Build and operate modern internet-first architectures  that have dynamic, high-quality digital experiences with highly automated, secure, and reliable platforms.
Accelerate and deliver your applications and content globally  at scale to your users wherever they are. This ability creates opportunities for you to compete and quickly adapt to new demand and markets.
Help secure your digital estate  against known and new threats with intelligent security that embraces a Zero Trust framework.
What are the key benefits?
Global delivery scale through the Microsoft network
Scale out and improve the performance of your applications and content by using Microsoft's global cloud CDN and wide area network (WAN):
Take advantage of more than  118 edge locations  across 100 metro areas connected to Azure by using a private enterprise-grade WAN. Improve latency for applications by up to three times.
Accelerate application performance by using the Azure Front Door  anycast  network and  split TCP  connections.
Terminate SSL offload at the edge and use integrated  certificate management .
Natively support end-to-end IPv6 connectivity and the HTTP/2 protocol.
Delivery of modern apps and architectures
Modernize your internet-first applications on Azure with cloud-native experiences:
Integrate with DevOps-friendly command-line tools across SDKs of different languages, Bicep, Azure Resource Manager templates, the Azure CLI, and PowerShell.
Define your own  custom domain  with flexible domain validation.
Load balance and route traffic across  origins . Use intelligent  health probe  monitoring across apps or content hosted in Azure or anywhere.
Integrate with other Azure services, such as Azure DNS, the Web Apps feature of Azure App Service, Azure Storage, and many more for domain and origin management.
Move your routing business logic to the edge with  enhanced rules engine  capabilities, including regular expressions and server variables.
Analyze  built-in reports  with an all-in-one dashboard for both Azure Front Door and security patterns.
Monitor your Azure Front Door traffic in real time , and configure alerts that integrate with Azure Monitor.
Log each Azure Front Door request  and failed health probes.
Simplicity and cost-effectiveness
Unified static and dynamic delivery offered in a single tier to accelerate and scale your application through caching, SSL offload, and layer 3-4 DDoS protection.
Free,  autorotation-managed SSL certificates  that save time and help quickly secure apps and content.
Low entry fee and a simplified cost model that reduces billing complexity by having fewer meters to plan for.
Integrated egress pricing that removes the separate egress charge from Azure regions to Azure Front Door. For more information, see  Azure Front Door pricing .
Intelligent, secure internet perimeter
Help secure applications with built-in layer 3-4 DDoS protection, a seamlessly attached  WAF , and  Azure DNS to help protect your domains .
Help protect your applications against layer 7 DDoS attacks by using a WAF. For more information, see  Application DDoS protection .
Help protect your applications from malicious actors with bot manager rules based on Microsoft Threat Intelligence.
Privately connect to your origin behind Azure Front Door by using  Azure Private Link , and embrace a Zero Trust access model.
Provide a centralized security experience for your application via Azure Policy and Azure Advisor that provides consistent security features across apps.
How do you choose between Azure Front Door tiers?
For a comparison of supported features in Azure Front Door, see  Tier comparison .
Where is the service available?
Azure Front Door Standard, Pre
