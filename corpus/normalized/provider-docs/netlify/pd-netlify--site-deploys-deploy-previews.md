# Netlify deploy previews

Source: https://docs.netlify.com/site-deploys/deploy-previews/
Provider: Netlify | Authority: Tier A
Ingested: 2026-06-13 | Terms: Docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Deploy Previews | Netlify Docs
Skip to content                  Netlify Docs               Start         Build             Fundamentals      Build with AI         Configure builds         Git workflows         Environment variables         Frameworks         Post-processing         User-Agent categories       Primitives      AI Gateway         Serverless Functions         Edge Functions         Image CDN         Blobs         Database         Caching         Async Workloads               Deploy         Manage               Accounts & Billing         Projects         Domains         Data & Storage         Security         Monitoring & Insights         Preview Servers         Forms         Visual Editor         Routing & Redirects               Extend               Install & use         Develop & share         Netlify SDK for extensions
Building code agents         Framework adapter API               Reference               Error reference         Netlify skills
Request processing order         CLI reference
Netlify SDK for extensions
Visual Editor reference
APIs      Netlify API
Database API         Frameworks API         Cache API         Blobs API         Serverless Functions API         Edge Functions API       Dev Tool Guides      API and CLI guides         Terraform provider         Command Palette               Resources               Troubleshooting         Changelog
Examples
Migrate         Support
Checklists         Release phases         Enterprise credits               Prompt Templates                                                                                                                                                               Deploy              Deploy        Deploy overview           Compare preview options               Deploy types                     Production deploy           Branch deploys           Deploy Previews                 Create deploys           Manage deploys           Protect deploys           Deploy notifications               Review deploys                     Heads up display               Netlify Drawer for feedback                     Overview           Netlify Reviewer quickstart           Troubleshoot the Netlify Drawer                       Review a preview server instance                                     On this page               Overview           Get started           Deploy Previews from agent runs           Deploy Previews from pull / merge requests           Status and notifications           Deploy Preview URL for pull / merge requests           Configure Deploy Previews for pull / merge requests           Customize landing page for Deploy Preview               Protect all Deploy Previews with a password           Set environment variable values for Deploy Previews           Deploy Preview URLs           Collaborate on Deploy Previews                          On this page        Overview           Get started           Deploy Previews from agent runs           Deploy Previews from pull / merge requests           Status and notifications           Deploy Preview URL for pull / merge requests           Configure Deploy Previews for pull / merge requests           Customize landing page for Deploy Preview               Protect all Deploy Previews with a password           Set environment variable values for Deploy Previews           Deploy Preview URLs           Collaborate on Deploy Previews                         For the complete Netlify documentation index, see  llms.txt . Markdown versions of this page are available by appending  .md  to the URL.          Unlimited seats on Netlify Pro for $20/month →  Learn more  👥                Deploy
/
Deploy Types
/
Deploy Previews
For the complete documentation index, see  llms.txt         Copy page                       View as Markdown                       Copy as Markdown                     View as Markdown                           Deploy Previews allow you and your team to preview, review, and experience changes to any part of your site without having to publish them to production.
Get started         Section titled “Get started”
By default, Netlify automatically builds Deploy Previews when you do one of the following:
start an  agent run  that makes a file change to your site/app
open pull / merge requests in a connected site repository from GitHub, GitLab, Bitbucket, or Azure DevOps.
Deploy Previews from agent runs         Section titled “Deploy Previews from agent runs”
When you start an agent run that makes a file change to your site/app, Netlify automatically builds a Deploy Preview for you.
The URL will include an  agent-  prefix, followed by the run ID. For example,  agent-69a6140cc823ebba94b8ef32--mysitename.netlify.app .
Learn more in our docs on  Agent Runners .
Deploy Previews from pull / merge requests         Section titled “Deploy Previews from pull / merge requests”
When you open a pull / merge request in a connected site repository from GitHub, GitLab, Bitbucket, or Azure DevOps, Netlify automatically builds a Deploy Preview for you.
The base branch must either be a  production branch , or a branch that has  branch deploys enabled .
Once the deploy is complete, you can access the Deploy Preview at the unique  Deploy Preview URL . The Deploy Preview remains available until the deploy is deleted either  automatically  or  manually .
To change these settings or to control who can access your previews, review the section below on how to  configure Deploy Previews .
Status and notifications         Section titled “Status and notifications”
As Netlify starts to generate your Deploy Preview, a Deploy Preview status will appear on your pull / merge request. The status automatically updates to reflect the deploy progression. Once the status is marked as complete, you can access your Deploy Preview at the unique  Deploy Preview URL .
If you have  deploy notifications  enabled, Netlify will also add a comment to your pull / merge request with a link to the Deploy Preview o
