# Google Cloud CDN overview

Source: https://cloud.google.com/cdn/docs/overview
Provider: Google Cloud Armor | Authority: Tier A
Ingested: 2026-06-13 | Terms: GCP docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Cloud CDN overview  |  Google Cloud Documentation
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
Cloud CDN
Start free
Overview
Guides
Reference
Resources
Technology areas
More
Overview
Guides
Reference
Resources
Cross-product tools
More
Console
Discover
Product overview
Choose a CDN product
Best practices
Get started
Set up a backend bucket as an origin
Configure
Set up Cloud CDN
Overview      Set up a managed instance group backend      Set up a Cloud Storage backend bucket      Set up Cloud Run, Cloud Functions, or App Engine      Set up third-party object storage      Set up Cloud CDN for GKE Gateway
Use external backends
Overview      Set up an external backend with an internet NEG
Automate Cloud CDN setup with Terraform
Redirect HTTP requests to HTTPS
Deliver secure and non-secure content over the same hostname
Enable dynamic compression
Use Service Extensions for edge compute
Cache content
Overview
Change cache modes
Customize cache keys
Use negative caching
Change TTL settings and overrides
Serve stale content
Cache invalidation
Overview      Invalidate cached content
Secure and control access
Authenticate content
Use signed URLs
Use signed cookies
Configure private origin authentication
Web security best practices
Monitor
Logs and metrics for backend services
Logs and metrics for caching
Audit logging information
Troubleshoot
Troubleshooting
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
Cloud CDN
Guides
Send feedback
Cloud CDN overview
Stay organized with collections
Save and categorize content based on your preferences.
Cloud CDN (Content Delivery Network) uses Google's global edge network to
serve content closer to users, which accelerates your websites and
applications.
Cloud CDN works with the  global external Application Load Balancer
or the  classic Application Load Balancer
to deliver content to your users. The external Application Load Balancer provides the frontend IP
addresses and ports that receive requests and the backends that respond to the
requests.
Cloud CDN content can be sourced from  various types
of backends .
In Cloud CDN, these backends are also called  origin servers .
Figure 1 illustrates how responses from origin servers that run on
virtual machine (VM) instances flow through an external Application Load Balancer before being
delivered by Cloud CDN. In this situation, the
Google Front End (GFE)
comprises Cloud CDN and the external Application Load Balancer.
Figure 1.  Responses flow from origin servers through Cloud CDN to clients.
How Cloud CDN works
When a user requests content from an external Application Load Balancer, the request
arrives at a GFE that is at the edge of Google's
network as close as possible to the user.
If the load balancer URL map routes traffic to a backend service or backend
bucket that has Cloud CDN configured, the GFE uses Cloud CDN.
Backend services can use Compute Engine, GKE Ingress,
or GKE Gateway backends.
Cache hits and cache misses
A cache is a group of servers that stores and manages content so that
future requests for that content can be served faster. The cached content is a
copy of cacheable content that is stored on origin servers.
If the GFE looks in the Cloud CDN cache and finds a cached response
to the user's request, the GFE sends the cached response to the user. This is
called a  cache hit . When a cache hit occurs, the GFE looks up the content by
its  cache key  and responds directly to the user,
shortening the round-trip time and saving the origin server from having to
process the request.
A  partial hit  occurs when a request is served partially from cache and
partially from a backend. This can happen if only part of the requested content
is stored in a Cloud CDN cache, as described in
Support for byte range requests .
The first time that a piece of content is requested, the GFE determines that it
can't fulfill the request from the cache. This is called a  cache miss . When a
cache miss occurs, the GFE forwards the request to the external Application Load Balancer. The
load balancer then forwards the request to one of your origin servers. When the
cache receives the content, the GFE forwards the content to the user.
If the origin server's response to this request is
cacheable , Cloud CDN stores the
response in the Cloud CDN cache for future requests.
Data transfer from a cache to a client is called  cache egress .
Data transfer to a cache is called  cache fill .
Cache hit and cache miss behavior is consistent across all supported backend
types, including Compute Engine, backend buckets, GKE Ingress,
and GKE Gateway.
Figure 2 shows a cache hit and a cache miss:
Origin servers running on VM instances send HTTP(S) responses.
The external Application Load Balancer distributes the responses to Cloud CDN.
Cloud CDN delivers the responses to end users.
Figure 2.  The initial response is served by the origin server
while subsequent responses are served by the GFE from cache.
For costs related to cache hits and cache misses, see  Pricing .
Cache hit ratio
The  cache hit ratio  is the percentage of times that a requested object is
served from the cache. If the cache hit ratio is 60%, it me
