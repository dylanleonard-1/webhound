# Fly.io custom domains

Source: https://fly.io/docs/networking/custom-domain/
Provider: Fly.io | Authority: Tier A
Ingested: 2026-06-13 | Terms: Docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Custom domains · Fly Docs
Skip to content
Fly
App performance optimization
Docs
Need a Logo?
View Our Brand Assets
Open main menu
Fly
App performance optimization
Docs
Pricing
Support
Sign In
Sign Up
Getting Started
Toggle Getting Started section
Quickstart: Launch your app
Launch HelloFly Demo App
Deep Dive Demo App
Choose a Language or Framework
Fly.io Essentials
Migrate from Heroku
Troubleshoot Deployments
Guides (Blueprints)
Toggle Guides (Blueprints) section
Guides Overview
Apps on Fly.io
Toggle Apps on Fly.io section
Fly Apps Overview
Fly Launch
Secrets
Production Checklist
Languages & Frameworks
Toggle Languages & Frameworks section
Elixir
Rails
Laravel
Django
JavaScript
Rust
Python
More...
Fly Machines
Toggle Fly Machines section
Introduction to Fly Machines
Machines API
Run a New Machine
Update a Machine
Machine Sizing
Machine Restart Policy
Machine States
Run User Code on Fly Machines
One App Per Customer - Why?
The Machine Runtime Environment
Managed Postgres
Toggle Managed Postgres section
Create and Connect to a Managed Postgres Cluster
Cluster Configuration Options
Phoenix with Managed Postgres
Monitoring and Metrics
Import data from another postgres cluster
Supported Postgres Extensions
Fly GPUs
Toggle Fly GPUs section
GPU Quickstart
Getting Started with GPU Machines
Python GPU Dev Machine
Databases & Storage
Toggle Databases & Storage section
Fly Managed Postgres
Tigris Object Storage
Upstash for Redis®
Fly Volumes
Toggle Fly Volumes section
Fly Volumes Overview
Create and Manage Volumes
Manage Volume Snapshots
Volume States
Fly Kubernetes
Toggle Fly Kubernetes section
Fly Kubernetes Quickstart
Fly Kubernetes Features
Create an FKS Cluster
Connect to an FKS Cluster
Configure FKS Services
Use GPUs with FKS
Use Volumes with FKS
Networking
Toggle Networking section
Connect to an App Service
Public Networking
Private Networking
Custom Private Networks
Flycast - Private Proxy Services
Egress IP Addresses
Dynamic Request Routing
Custom Domains
Understanding Cloudflare
Request Headers
Run UDP Services
TLS Support
Monitoring
Toggle Monitoring section
Metrics
Sentry Error Tracking
Logging
Toggle Logging section
Live Tail Logs
Logs API Options
Search Logs
Export Logs
Error Codes
Security
Toggle Security section
Organization Roles and Permissions
SSO for Organizations
Remove a Member from an Org
TLS Termination
App Security by Arcjet
Access Tokens
OpenID Connect
Shared Responsibility Model
Security Practices and Compliance
Reference
Toggle Reference section
flyctl
App Config Reference (fly.toml)
Architecture
Autoscaling
AWS to Fly Overview
Builders
Content Encoding
Fly Launch
Health Checks
Load Balancing
Machine Migration
Multiple Processes in Apps
Fly Proxy
Fly Proxy Autostop/Autostart
Regions
Suspend/Resume
About
Toggle About section
Pricing
Billing
Cost Management
Free Trial
Support
Engineering Jobs
Healthcare on Fly.io
Extensions Program
Extensions API
Merch
Open Source
Using Our Brand
Privacy Policy
Terms of Service
---
title: Custom domains
layout: docs
nav: firecracker
redirect_from:
- /docs/apps/custom-domain/
- /docs/app-guides/custom-domains-with-fly/
- /docs/networking/custom-domains-with-fly/
---
<figure>
<img src="/static/images/docs-ui.webp" alt="">
</figure>
When you create a Fly App, it is automatically given a `fly.dev` subdomain, based on the app's name. This is great for testing, but when you want to go to full production you'll want your application to appear on your own domain and have HTTPS set up for you as it is with your `.fly.dev` domain. You can do this by adding your domain to your Fly App, then configuring DNS records through your DNS provider.
## Add a custom domain for your app
To add a custom domain, first attach your domain to your Fly App to get DNS configuration instructions, then configure your DNS records with your DNS provider.
### Add your domain to your app
Attach your domain to your Fly App. This prepares your app to generate TLS certificates and handle traffic for your custom domain, and shows you the DNS configuration options for your setup.
You can add your domain with flyctl or in your app [dashboard](https://fly.io/dashboard/) under **Certificates**.
For example, using the CLI:
```cmd
fly certs add example.com
```
This command will show you the applicable DNS configuration options for your setup.
If you are adding a wildcard domain with the CLI, put quotes around the hostname to avoid shell expansion:
```cmd
fly certs add "*.example.com"
```
Use `fly certs check <hostname>` to check the certificate status and validation progress, or `fly certs setup <hostname>` to view all setup options.
### Configure DNS records
Now that you've added your domain to your app, configure DNS records with your DNS provider to direct traffic to your Fly App. The setup instructions in the dashboard, or from `fly certs add`, show the recommended DNS configuration for your situation.
Choose the DNS setup that matches your needs:
<div class="important">
**Important:** To issue or renew a certificate, Fly.io needs to verify your domain through at least one of: an IPv6 address (AAAA record) pointing to your app, a [CNAME `_acme-challenge`](#dns-challenge), or a [`_fly-ownership` TXT record](#domain-ownership-verification).
</div>
#### A and AAAA records (recommended)
Use A and AAAA records for most direct connections to your app. These records point your domain directly to your app's IP addresses.
The A and AAAA records you need to set will be shown in your dashboard, and in the output from `fly certs add`. If your app doesn't have IPv4 and IPv6 addresses, allocate them with `fly ips allocate`.
#### CNAME records
CNAME records work well for subdomains (like `www.example.com` or `app.example.com`). A CNAME points your custom domain at a unique `.fly.dev` hostname for your app.
CNAME records are also a good option if you have many IP addresses assigned to your app, or expect to change them in the future.
Set the CNAME record with your DNS provider. Each app has a un
