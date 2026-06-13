+++
title = "Dalfox — Powerful XSS Scanner"
description = "A powerful open-source XSS scanner and automation utility. Reflected, Stored, DOM-based with AST-level verification."
template = "landing"
+++

        Hunt every XSS
        before it hunts you.

        Dalfox is a powerful open-source XSS scanner and automation utility. Reflected, Stored, DOM-based: discovered, verified, and reported with AST-level precision across every parameter in your app.

          Get Started

          Star on GitHub

            brew

            Homebrew
            Snap
            Arch (AUR)
            Nix
            Cargo

        $
        brew install dalfox
        copy

          dalfox — scan

          $dalfox scan https://xss-game.appspot.com/level1/frame
          6:42PM INF start scan to https://xss-game.appspot.com/level1/frame
          6:42PM INF found reflected 1 params
          └── query valid_specials="/\'{`<>"();=|}[.:]+,$-" invalid_specials=""

          6:42PM WRN XSS found 1 XSS
          [POC][V][GET][inHTML] ...?query=%3Csvg%2Fonload%3Dalert%281%29%3E
            ├── Issue: XSS payload DOM object identified
            ├── Payload: &lt;svg/onload=alert(1)&gt;
            └── L13: s were found for &#x3c;b&#x3e;&#x3c;svg/onload=alert(1)&#x3e;&#x3c;/b&#x3e;..

          6:42PM INF scan completed in 3.482 seconds

      6
      Scan Modes

      AST
      DOM Verification

      MCP
      AI Ready

      OSS
      MIT Licensed

    // Capabilities
    Everything you need to catch cross-site scripting
    From a single URL to full pipelines, Dalfox adapts to how you work: CLI, file batch, pipe, server mode, or MCP. Every finding is parsed, verified, and reported with context you can act on.

        Deep XSS discovery
        Reflected, Stored, and DOM-based XSS with payload optimization. AST-backed DOM verification means no more false positives from blind reflections.

          reflected
          stored
          dom
          ast-verify

        Parameter intelligence
        Mining, static analysis, BAV testing, and context-aware charset probing give every parameter a full attack profile.

        WAF aware
        Fingerprints popular WAFs and mutates payloads with encoding, casing, and polyglot tactics to slip through.

        Built for pipelines
        Pipe, file-batch, and server modes drop into CI/CD. Pair with your proxy, crawler, or recon stack without friction.

        REST API &amp; MCP
        Run Dalfox as a long-lived server with REST control, or expose it as an MCP tool to agents and IDEs.

        Reports you can ship
        Export to the format your workflow speaks, from terse CLI output to SARIF for GitHub code scanning.

          JSON
          JSONL
          Markdown
          SARIF
          TOML
          Plain
          Silence

    // Modes
    Six ways to run Dalfox
    Pick the shape that fits your target. Every mode shares the same discovery and verification engine.

        URL
        Single target scan

        FILE
        Batch from list

        PIPE
        stdin pipeline

        SXSS
        Stored XSS

        SERVER
        REST + daemon

        MCP
        Agent-native

    // Workflow
    From install to verified finding in three steps
    Dalfox is designed to drop into whatever you already have. No fancy setup, no heavy orchestration.

        Install
        Grab Dalfox through Homebrew, Snap, Nix, cargo, or a prebuilt binary. One command, no runtime to manage.
        brew install dalfox

        Point at a target
        Give it a URL, a file, or pipe in a crawl. Dalfox mines parameters, probes contexts, and adapts.
        dalfox scan https://target.app

        Ship the findings
        Export to SARIF, JSON, or Markdown, or proxy results to your pipeline. Findings come verified, not guessed.
        dalfox scan urls.txt -o report.sarif

    // Community
    Built in the open, by hunters everywhere
    Dalfox is shaped by the people who run it. Open an issue, send a pull request, or trade payloads with the community. Every contribution sharpens the hunt.

      Contributing guide
      Browse open issues →

    Thanks to our contributors

    Ready to hunt?
    Thousands of scans, zero fuss. Star the repo, read the docs, or drop Dalfox in your next recon loop.

      Install Dalfox
      CLI Reference
      GitHub →
