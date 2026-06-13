# Fly.io docs overview

Source: https://fly.io/docs/
Provider: Fly.io | Authority: Tier A
Ingested: 2026-06-13 | Terms: Docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Fly.io developer documentation · Fly Docs
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
title: "Fly.io developer documentation"
layout: docs
toc: false
breadcrumbs: false
nav: firecracker
---
<div class="grid grid-cols-2 items-center">
<div>
## Ready to get started?
**Step 1:** Install `flyctl`
```cmd
brew install flyctl
```
<small>Not using `brew`? Check out the [installation guide](/docs/flyctl/install/)</small>
**Step 2:** Run `fly launch`
</div>
<figure>
<img src="/static/images/doc-main.png" alt="Illustration by Annie Ruygt of Frankie the hot air balloon waving to a bird sitting on a hour roof" class="w-full max-w-lg mx-auto">
</figure>
</div>
## Explore Fly.io by features
<div class="note">
<ul class="grid grid-cols-2 sm:grid-cols-3 text-lg font-medium gap-6 px-4 py-6">
<li><a href="/docs/machines/">Fly Machines</a></li>
<li><a href="/docs/volumes/">Fly Volumes</a></li>
<li><a href="/docs/security/">Security</a></li>
<li><a href="/docs/networking/">Networking</a></li>
<li><a href="/docs/mpg/">Managed Postgres</a></li>
<li><a href="/docs/kubernetes/">Fly Kubernetes</a></li>
<li><a href="/docs/database-storage-guides/">Database & Storage</a></li>
<li><a href="/docs/monitoring/">Monitoring</a></li>
</ul>
</div>
<div class="grid grid-cols-2 py-8">
<div>
## Get answers in your language
Or framework. You know what we mean. Check out the docs specific to your tech so you can move faster.
</div>
<div class="h-full">
<div class="grid grid-cols-3 h-full gap-2">
<a
href="/docs/elixir/getting-started/"
class="btn h-full rounded-xl"
>
Phoenix
</a>
<a
href="/docs/languages-and-frameworks/static/"
class="btn h-full rounded-xl"
>
Static
</a>
<a
href="/docs/rails/getting-started/"
class="btn h-full rounded-xl"
>
Ruby on Rails
</a>
<a
href="/docs/languages-and-frameworks/dockerfile/"
class="btn h-full rounded-xl"
>
Docker
</a>
<a
href="/docs/languages-and-frameworks/golang/"
class="btn h-full rounded-xl"
>
Go
</a>
<a
href="/docs/rust/"
class="btn h-full rounded-xl"
>
Rust
</a>
<a
href="/docs/django/getting-started/"
class="btn h-full rounded-xl"
>
Django
</a>
<a
href="/docs/laravel/"
class="btn h-full rounded-xl"
>
Laravel
</a>
<a
href="/docs/js/"
class="btn h-full rounded-xl"
>
JavaScript
</a>
</div>
</div>
</div>
<div class="flex justify-center">
## How does Fly.io work?
</div>
<figure>
<img src="/static/images/fly-map.png" alt="" class="w-full">
</figure>
<div class="grid grid-cols-2 items-center">
<figure>
<img src="/static/images/help.png" alt="Illustration by Annie Ruygt of Frankie the hot air balloon waving to a bird sitting on a hour roof" class="w-full max-w-lg mx-auto">
</figure>
<div class="space-y-2">
<h2>Could you use more help?</h2>
<p>Our Community forum and Support team have the answers.</p>
</div>
</div>
<div class="grid grid-cols-2 gap-6">
<div class="note">
<h3>Community Forum</h3>
<ul class="ml-1">
<li>Free to use</li>
<li>Discuss Fly.io with other users</li>
<li>See new Fly.io developments first</li>
<li>Searchable backlog</li>
<li>Quick answers to common issues</li>
</ul>
<a href="https://community.fly.io" class="btn mt-4"
