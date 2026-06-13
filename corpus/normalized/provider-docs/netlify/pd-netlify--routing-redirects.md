# Netlify redirects

Source: https://docs.netlify.com/routing/redirects/
Provider: Netlify | Authority: Tier A
Ingested: 2026-06-13 | Terms: Docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Redirects and rewrites | Netlify Docs
Skip to content                  Netlify Docs               Start         Build             Fundamentals      Build with AI         Configure builds         Git workflows         Environment variables         Frameworks         Post-processing         User-Agent categories       Primitives      AI Gateway         Serverless Functions         Edge Functions         Image CDN         Blobs         Database         Caching         Async Workloads               Deploy         Manage               Accounts & Billing         Projects         Domains         Data & Storage         Security         Monitoring & Insights         Preview Servers         Forms         Visual Editor         Routing & Redirects               Extend               Install & use         Develop & share         Netlify SDK for extensions
Building code agents         Framework adapter API               Reference               Error reference         Netlify skills
Request processing order         CLI reference
Netlify SDK for extensions
Visual Editor reference
APIs      Netlify API
Database API         Frameworks API         Cache API         Blobs API         Serverless Functions API         Edge Functions API       Dev Tool Guides      API and CLI guides         Terraform provider         Command Palette               Resources               Troubleshooting         Changelog
Examples
Migrate         Support
Checklists         Release phases         Enterprise credits               Prompt Templates                                                                                                                                                               Static Routing & Redirects              Static Routing & Redirects        Overview           Custom headers               Redirects                     Overview           Redirect options           Rewrites proxies           Test redirects locally with Netlify CLI                                           On this page               Overview           Syntax for the _redirects file           Syntax for the Netlify configuration file           Rule processing order                          On this page        Overview           Syntax for the _redirects file           Syntax for the Netlify configuration file           Rule processing order                         For the complete Netlify documentation index, see  llms.txt . Markdown versions of this page are available by appending  .md  to the URL.          Unlimited seats on Netlify Pro for $20/month →  Learn more  👥                Manage
/
Routing
/
Redirects
/
Redirects and rewrites
For the complete documentation index, see  llms.txt         Copy page                       View as Markdown                       Copy as Markdown                     View as Markdown                           You can configure redirect and rewrite rules for your Netlify site in two ways:
Save a plain text file called  _redirects  without a file extension to the  publish directory  of your site. You can find   _redirects  file syntax  details below.
Add one or more  redirects  tables to your  Netlify configuration file . This method allows for more structured configuration and additional capabilities, as described in the  Netlify configuration file syntax  section below.
Framework considerations       If your site uses a specific framework, there may be additional redirect options or caveats for you to consider. Learn more in our  framework  docs.
Netlify processes and serializes your redirect rules across the  _redirects  and  netlify.toml  files. If the size of this output is too large, the deploy might fail.
If you need to set up 10,000 redirects or more, we recommend using  wildcards or placeholders  as much as possible. For a more complex redirect setup,  Edge Functions  can be a better option.
Syntax for the  _redirects  file         Section titled “Syntax for the _redirects file”
In a  _redirects  file, each redirect rule must be listed on a separate line, with the original path followed by the new path or URL. Any line beginning with  #  will be ignored as a comment. Paths are case-sensitive and special characters in paths must be url-encoded.
Here is an example:
# Redirects from what the browser requests to what we serve      /home                /      /blog/my-post.php    /blog/my-post      /news                /blog      /cuties              https://www.petsofnetlify.com      /authors/c%C3%A9line /authors/about-c%C3%A9line
You can customize and alter the redirect behavior by adding options to the end of each line such as HTTP status code, country conditions, or language conditions. Visit the  redirect options  doc for more details on these and other configuration options including query parameters,  forced redirects with  !  , domain-level redirects, and more. You can also use redirects for  rewrites and proxies .
Make sure we can access the file       If you’re running a build command or site generator, the  _redirects  file should end up in the folder you’re deploying. Some generators, like Jekyll, may also require additional configuration to avoid exclusion of files that begin with  _ . (For Jekyll, this requires  adding an  include  parameter  to  _config.yml .)
Syntax for the Netlify configuration file         Section titled “Syntax for the Netlify configuration file”
If you specify your redirect rules in your  Netlify configuration file , you can use a more structured configuration format with additional capabilities such as  signed proxy redirects . In a  netlify.toml  file, we use  TOML’s array of tables  to specify each individual redirect rule. The following keywords are available:
from : The case-sensitive path you want to redirect. Special characters must be url-encoded.
to : The URL or path you want to redirect to. Special characters must be url-encoded.
status : The  HTTP status code  you want to use in that redirect;  301  by default.
force : Whether to override any existing c
