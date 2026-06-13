# Netlify response headers

Source: https://docs.netlify.com/routing/headers/
Provider: Netlify | Authority: Tier A
Ingested: 2026-06-13 | Terms: Docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Custom headers | Netlify Docs
Skip to content                  Netlify Docs               Start         Build             Fundamentals      Build with AI         Configure builds         Git workflows         Environment variables         Frameworks         Post-processing         User-Agent categories       Primitives      AI Gateway         Serverless Functions         Edge Functions         Image CDN         Blobs         Database         Caching         Async Workloads               Deploy         Manage               Accounts & Billing         Projects         Domains         Data & Storage         Security         Monitoring & Insights         Preview Servers         Forms         Visual Editor         Routing & Redirects               Extend               Install & use         Develop & share         Netlify SDK for extensions
Building code agents         Framework adapter API               Reference               Error reference         Netlify skills
Request processing order         CLI reference
Netlify SDK for extensions
Visual Editor reference
APIs      Netlify API
Database API         Frameworks API         Cache API         Blobs API         Serverless Functions API         Edge Functions API       Dev Tool Guides      API and CLI guides         Terraform provider         Command Palette               Resources               Troubleshooting         Changelog
Examples
Migrate         Support
Checklists         Release phases         Enterprise credits               Prompt Templates                                                                                                                                                               Static Routing & Redirects              Static Routing & Redirects        Overview           Custom headers               Redirects                     Overview           Redirect options           Rewrites proxies           Test redirects locally with Netlify CLI                                           On this page               Overview           Limitations           Syntax for the _headers file           Syntax for the Netlify configuration file           Wildcards and placeholders in paths           Multi-value headers           Custom headers for different branch or deploy contexts           Basic authentication headers                          On this page        Overview           Limitations           Syntax for the _headers file           Syntax for the Netlify configuration file           Wildcards and placeholders in paths           Multi-value headers           Custom headers for different branch or deploy contexts           Basic authentication headers                         For the complete Netlify documentation index, see  llms.txt . Markdown versions of this page are available by appending  .md  to the URL.          Unlimited seats on Netlify Pro for $20/month →  Learn more  👥                Manage
/
Routing
/
Custom headers
For the complete documentation index, see  llms.txt         Copy page                       View as Markdown                       Copy as Markdown                     View as Markdown                           With custom headers, you can make custom adjustments or additions to the default  HTTP headers  that Netlify serves with your site when a client makes a request.
You can configure custom headers for your Netlify site in two ways:
Save a plain text file called  _headers  to the  publish directory  of your site. You can find   _headers  file syntax  details below.
Add one or more  headers  tables to your  Netlify configuration file . This method allows for more structured configuration and additional capabilities, as described in the  Netlify configuration file syntax  section below.
Limitations         Section titled “Limitations”
Custom headers apply only to files Netlify serves from our own backing store. If you are  proxying content to your site  or dealing with a URL handled by a  function  or  edge function  such as a server-side rendered (SSR) page, custom headers won’t be applied to that content. In those cases, the site being proxied to or the function should return any required headers instead. Visit our docs on edge functions to learn how to  configure  cache-control  headers for edge functions .
When you declare headers in a  _headers  file stored in the publish directory or a Netlify configuration file, the headers are global for all builds and cannot be scoped for specific branches or deploy contexts. However, there is a workaround you can use to  set unique headers for each deploy context .
You can set most  HTTP response fields  using custom headers. The following header names are exceptions. Custom headers for these are typically ignored because Netlify’s web servers need to set these headers to work properly.
Accept-Ranges
Age
Allow
Alt-Svc
Connection
Content-Encoding
Content-Length
Content-Range
Date
Location  - use  redirects  instead
Server
Set-Cookie  - may be overridden by Netlify cookie handling
Trailer
Transfer-Encoding
Upgrade
Setting cookies across subdomains only works for custom domains        netlify.app  is listed in the Mozilla Foundation’s  Public Suffix List , which prevents setting cookies across subdomains. You can only set a cookie for all subdomains if your site uses a  custom domain  instead of  mysitename.netlify.app .
Syntax for the  _headers  file         Section titled “Syntax for the _headers file”
In a  _headers  file, you can specify one or several URL paths with their additional headers indented below them:
Any line beginning with  #  will be ignored as a comment.
Header field names are case insensitive.
Paths can contain  wildcards and placeholders .
Here is an example of a  _headers  file with two URL paths:
# a path:      /templates/index.html            # headers for that path:            X-Frame-Options: DENY      # another path:      /templates/index2.html            # headers for that path:            X-Frame-Options: SAMEORIGIN
Here’s an examp
