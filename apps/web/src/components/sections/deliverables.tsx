'use client'

import { useState } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { SectionContainer } from '@/components/layout/section-container'
import { GradientDivider } from '@/components/ui/gradient-divider'
import { AnimatedFadeIn } from '@/components/effects/animated-fade-in'
import { PrimaryButton } from '@/components/ui/primary-button'

// ── Data ──────────────────────────────────────────────────────────────────────

const TABS = [
  { label: 'Prioritized Finding Report', sub: 'CVSS-ranked vulnerabilities with scores' },
  { label: 'Remediation Playbook',       sub: 'Step-by-step fixes with code patches' },
  { label: 'Threat Intelligence Digest', sub: 'Global feed matches and breach exposure' },
  { label: 'Continuous Alert Feed',      sub: 'Real-time CVE and anomaly notifications' },
]

// ── Preview panels ────────────────────────────────────────────────────────────

const SEV_STYLE: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.08)' },
  MEDIUM:   { color: '#eab308', bg: 'rgba(234,179,8,0.07)' },
  LOW:      { color: '#8BFF3E', bg: 'rgba(139,255,62,0.06)' },
}

const FINDINGS = [
  { sev: 'CRITICAL', text: 'SQL injection — /api/user?id= (boolean-blind confirmed)', score: '9.8' },
  { sev: 'HIGH',     text: 'TLS 1.0 active — POODLE/BEAST downgrade viable',          score: '7.5' },
  { sev: 'HIGH',     text: 'CORS wildcard — Access-Control-Allow-Origin: *',           score: '7.2' },
  { sev: 'MEDIUM',   text: 'X-Frame-Options absent — clickjacking exposure',           score: '5.3' },
  { sev: 'MEDIUM',   text: 'Session cookie missing Secure + HttpOnly flags',           score: '5.1' },
  { sev: 'LOW',      text: '12 subdomains via certificate transparency',               score: '2.4' },
]

function FindingReport() {
  return (
    <div className="rounded-[16px] border border-[rgba(139,255,62,0.12)] overflow-hidden"
      style={{ background: 'rgba(3,7,18,0.9)', backdropFilter: 'blur(6px)' }}>
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(139,255,62,0.08)]"
        style={{ background: 'rgba(139,255,62,0.03)' }}>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-black text-[rgba(139,255,62,0.6)] tracking-[0.15em]">WEBHOUND</span>
          <span className="text-[rgba(255,255,255,0.2)] text-[10px]">/</span>
          <span className="text-[10px] text-[rgba(255,255,255,0.5)] font-mono">security-report-2024.pdf</span>
        </div>
        <span className="text-[8px] font-black text-[rgba(139,255,62,0.5)] tracking-widest border border-[rgba(139,255,62,0.2)] px-2 py-0.5 rounded-full">
          EXPORT
        </span>
      </div>

      {/* Column headers */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[rgba(139,255,62,0.05)]">
        <span className="text-[8px] font-black text-[rgba(255,255,255,0.2)] tracking-[0.15em] w-16">SEVERITY</span>
        <span className="text-[8px] font-black text-[rgba(255,255,255,0.2)] tracking-[0.15em] flex-1">FINDING</span>
        <span className="text-[8px] font-black text-[rgba(255,255,255,0.2)] tracking-[0.15em] w-10 text-right">CVSS</span>
      </div>

      {/* Findings */}
      <div className="flex flex-col divide-y divide-[rgba(139,255,62,0.04)]">
        {FINDINGS.map((f, i) => {
          const s = SEV_STYLE[f.sev]
          return (
            <motion.div
              key={i}
              className="flex items-center gap-3 px-4 py-2.5"
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.06, duration: 0.3 }}
            >
              <span
                className="text-[7.5px] font-black tracking-wider px-1.5 py-[3px] rounded-[3px] w-16 text-center flex-shrink-0"
                style={{ color: s.color, background: s.bg }}
              >
                {f.sev}
              </span>
              <span className="text-[11px] text-[rgba(255,255,255,0.58)] leading-tight flex-1 font-mono">{f.text}</span>
              <span className="text-[11px] font-black font-mono flex-shrink-0 w-10 text-right" style={{ color: s.color }}>
                {f.score}
              </span>
            </motion.div>
          )
        })}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between px-4 py-2.5 border-t border-[rgba(139,255,62,0.06)]"
        style={{ background: 'rgba(139,255,62,0.02)' }}>
        <span className="text-[9px] font-mono text-[rgba(255,255,255,0.3)]">6 findings · 2 CRITICAL · 2 HIGH</span>
        <span className="text-[9px] font-mono text-[rgba(255,255,255,0.2)]">Generated 2024-11-28</span>
      </div>
    </div>
  )
}

const REMEDIATIONS = [
  {
    sev: 'CRITICAL',
    title: 'SQL Injection — /api/user?id=',
    effort: 'Low · ~30 min',
    desc: 'Replace raw string interpolation with parameterized queries to prevent injection.',
    code: `// ✗ Vulnerable\ndb.query(\`SELECT * FROM users WHERE id=\${req.params.id}\`)\n\n// ✓ Fixed\ndb.query('SELECT * FROM users WHERE id=?', [req.params.id])`,
    verify: 'Passes OWASP SQLi test suite after patch',
  },
  {
    sev: 'HIGH',
    title: 'TLS 1.0 Active on Port 443',
    effort: 'Low · Config change',
    desc: 'Disable legacy TLS protocol versions in your web server configuration.',
    code: `# nginx.conf\nssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers ECDH+AESGCM:!RC4:!MD5:!aNULL;`,
    verify: 'Verified with SSL Labs A+ rating',
  },
]

function RemediationPlaybook() {
  const [idx, setIdx] = useState(0)
  const r = REMEDIATIONS[idx]
  const s = SEV_STYLE[r.sev]

  return (
    <div className="rounded-[16px] border border-[rgba(139,255,62,0.12)] overflow-hidden"
      style={{ background: 'rgba(3,7,18,0.9)', backdropFilter: 'blur(6px)' }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(139,255,62,0.08)]"
        style={{ background: 'rgba(139,255,62,0.03)' }}>
        <span className="text-[10px] font-black text-[rgba(255,255,255,0.55)] tracking-wider">
          REMEDIATION PLAYBOOK
        </span>
        <div className="flex gap-1.5">
          {REMEDIATIONS.map((_, i) => (
            <button
              key={i}
              onClick={() => setIdx(i)}
              className="w-5 h-5 rounded-full text-[8px] font-bold transition-all duration-200"
              style={{
                background: idx === i ? 'rgba(139,255,62,0.2)' : 'rgba(255,255,255,0.05)',
                color: idx === i ? '#8BFF3E' : 'rgba(255,255,255,0.3)',
                border: idx === i ? '1px solid rgba(139,255,62,0.3)' : '1px solid rgba(255,255,255,0.08)',
              }}
            >
              {i + 1}
            </button>
          ))}
        </div>
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={idx}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="p-4 flex flex-col gap-3"
        >
          {/* Finding */}
          <div className="flex items-start gap-3">
            <span className="text-[8px] font-black px-1.5 py-[3px] rounded-[3px] flex-shrink-0 mt-0.5"
              style={{ color: s.color, background: s.bg }}>{r.sev}</span>
            <div>
              <span className="text-[13px] font-semibold text-white block">{r.title}</span>
              <span className="text-[10px] text-[rgba(255,255,255,0.35)] font-mono">{r.effort}</span>
            </div>
          </div>

          {/* Description */}
          <p className="text-[11px] text-[rgba(255,255,255,0.48)] leading-relaxed">{r.desc}</p>

          {/* Code block */}
          <div className="rounded-[10px] p-3 font-mono text-[10px] leading-relaxed"
            style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(139,255,62,0.08)', color: 'rgba(139,255,62,0.75)', whiteSpace: 'pre' }}>
            {r.code}
          </div>

          {/* Verify */}
          <div className="flex items-center gap-2">
            <span className="text-[#8BFF3E] text-[10px]">✓</span>
            <span className="text-[10px] text-[rgba(255,255,255,0.35)]">{r.verify}</span>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

const THREAT_MATCHES = [
  { indicator: 'IP 104.21.x.x',    source: 'AlienVault OTX',  type: 'Malicious IP',     conf: 'HIGH' },
  { indicator: 'target.com domain', source: 'PhishTank',       type: 'Phishing domain',  conf: 'HIGH' },
  { indicator: 'ASN 13335',         source: 'Emerging Threats', type: 'Bulletproof host', conf: 'MED' },
  { indicator: '3 credentials',     source: 'HaveIBeenPwned',  type: 'Breach exposure',  conf: 'CONF' },
]

function ThreatDigest() {
  return (
    <div className="rounded-[16px] border border-[rgba(139,255,62,0.12)] overflow-hidden"
      style={{ background: 'rgba(3,7,18,0.9)', backdropFilter: 'blur(6px)' }}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(139,255,62,0.08)]"
        style={{ background: 'rgba(139,255,62,0.03)' }}>
        <span className="text-[10px] font-black text-[rgba(255,255,255,0.55)] tracking-wider">THREAT INTELLIGENCE DIGEST</span>
        <span className="text-[8px] font-mono text-[rgba(255,255,255,0.25)]">4 feeds matched</span>
      </div>

      <div className="p-4 flex flex-col gap-3">
        {THREAT_MATCHES.map((m, i) => (
          <motion.div
            key={i}
            className="rounded-[10px] border border-[rgba(139,255,62,0.07)] px-3.5 py-2.5 flex items-center justify-between gap-3"
            style={{ background: 'rgba(139,255,62,0.02)' }}
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.07, duration: 0.3 }}
          >
            <div className="flex-1 min-w-0">
              <span className="text-[12px] font-semibold text-white block truncate">{m.indicator}</span>
              <span className="text-[10px] text-[rgba(255,255,255,0.35)] font-mono">{m.type} · {m.source}</span>
            </div>
            <span
              className="text-[8px] font-black tracking-wider px-2 py-0.5 rounded-full flex-shrink-0"
              style={{
                color: m.conf === 'HIGH' ? '#ef4444' : m.conf === 'MED' ? '#eab308' : '#f97316',
                background: m.conf === 'HIGH' ? 'rgba(239,68,68,0.1)' : m.conf === 'MED' ? 'rgba(234,179,8,0.08)' : 'rgba(249,115,22,0.08)',
              }}
            >
              {m.conf}
            </span>
          </motion.div>
        ))}
      </div>

      <div className="px-4 py-3 border-t border-[rgba(139,255,62,0.06)]"
        style={{ background: 'rgba(139,255,62,0.02)' }}>
        <p className="text-[10px] text-[rgba(255,255,255,0.38)] leading-relaxed">
          <span className="text-[rgba(139,255,62,0.6)] font-semibold">Recommended:</span>{' '}
          Rotate all exposed credentials and request AlienVault OTX delisting.
        </p>
      </div>
    </div>
  )
}

const ALERTS = [
  { sev: 'crit', time: '2m ago',  title: 'New CVE — Next.js 13.x',      detail: 'CVE-2024-34351 · Patch available: upgrade to 14.1.0' },
  { sev: 'high', time: '1h ago',  title: 'SSL certificate expiring',     detail: 'target.webhound.io · expires in 12 days' },
  { sev: 'med',  time: '3h ago',  title: 'Port scan activity detected',  detail: '198.51.100.0/24 probing TCP 22, 443, 8080' },
  { sev: 'info', time: '6h ago',  title: 'DNS propagation anomaly',      detail: 'api.target.com — 2 resolvers returning stale record' },
]

const ALERT_DOT: Record<string, string> = {
  crit: '#ef4444', high: '#f97316', med: '#eab308', info: '#8BFF3E',
}

function AlertFeed() {
  return (
    <div className="rounded-[16px] border border-[rgba(139,255,62,0.12)] overflow-hidden"
      style={{ background: 'rgba(3,7,18,0.9)', backdropFilter: 'blur(6px)' }}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-[rgba(139,255,62,0.08)]"
        style={{ background: 'rgba(139,255,62,0.03)' }}>
        <div className="flex items-center gap-2">
          <motion.span
            className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E] flex-shrink-0"
            animate={{ opacity: [1, 0.2, 1] }}
            transition={{ duration: 0.9, repeat: Infinity }}
            style={{ boxShadow: '0 0 4px rgba(139,255,62,1)' }}
          />
          <span className="text-[10px] font-black text-[rgba(255,255,255,0.55)] tracking-wider">LIVE ALERT FEED</span>
        </div>
        <span className="text-[8px] font-bold text-[rgba(139,255,62,0.55)] tracking-wider border border-[rgba(139,255,62,0.2)] px-2 py-0.5 rounded-full">
          1 NEW
        </span>
      </div>

      <div className="flex flex-col divide-y divide-[rgba(139,255,62,0.04)]">
        {ALERTS.map((a, i) => (
          <motion.div
            key={i}
            className="flex items-start gap-3 px-4 py-3"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: i * 0.08, duration: 0.35 }}
          >
            <div className="flex-shrink-0 mt-1">
              <div
                className="w-2 h-2 rounded-full"
                style={{ background: ALERT_DOT[a.sev], boxShadow: `0 0 5px ${ALERT_DOT[a.sev]}` }}
              />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-semibold text-white truncate">{a.title}</span>
                <span className="text-[9px] font-mono text-[rgba(255,255,255,0.25)] flex-shrink-0">{a.time}</span>
              </div>
              <span className="text-[10px] text-[rgba(255,255,255,0.38)] font-mono">{a.detail}</span>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="px-4 py-2.5 border-t border-[rgba(139,255,62,0.06)]"
        style={{ background: 'rgba(139,255,62,0.02)' }}>
        <span className="text-[9px] font-mono text-[rgba(255,255,255,0.25)]">
          Monitoring: attack surface · certificate · CVE feeds · anomaly detection
        </span>
      </div>
    </div>
  )
}

const PREVIEWS = [FindingReport, RemediationPlaybook, ThreatDigest, AlertFeed]

// ── Section ───────────────────────────────────────────────────────────────────

export function Deliverables() {
  const [active, setActive] = useState(0)

  return (
    <section id="reports" className="relative overflow-hidden bg-[#030712] py-28 sm:py-36 section-contain">
      <GradientDivider className="absolute top-0 left-0 right-0" glow />

      {/* Grid — GPU layer */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.022] grid-anim-layer"
        style={{
          backgroundImage: `
            linear-gradient(rgba(139,255,62,1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,255,62,1) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          animation: 'gridScroll 30s linear infinite',
        }}
      />

      {/* Glow */}
      <div
        aria-hidden
        className="absolute top-1/2 right-[-5%] -translate-y-1/2 pointer-events-none"
        style={{
          width: 700, height: 700,
          background: 'radial-gradient(circle, rgba(139,255,62,0.03) 0%, transparent 65%)',
          filter: 'blur(50px)',
        }}
      />

      <SectionContainer size="xl">
        <div className="grid grid-cols-1 lg:grid-cols-[42fr_58fr] gap-14 xl:gap-20 items-start">

          {/* ── Left — tabs ──────────────────────────────────────────────── */}
          <div className="lg:sticky lg:top-24">
            <AnimatedFadeIn delay={0.06}>
              <div className="inline-flex items-center gap-2 mb-7">
                <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
                <span className="text-[10px] font-bold text-[#8BFF3E] tracking-[0.22em] uppercase">
                  What You Receive
                </span>
                <span className="w-4 h-px bg-[rgba(139,255,62,0.4)]" />
              </div>
            </AnimatedFadeIn>

            <AnimatedFadeIn delay={0.14}>
              <h2
                className="font-bold leading-[0.92] tracking-[-0.025em] mb-5"
                style={{ fontSize: 'clamp(2.2rem, 3.5vw, 3.4rem)' }}
              >
                <span className="text-white block">Reports Built</span>
                <span
                  className="block text-[#8BFF3E]"
                  style={{ textShadow: '0 0 40px rgba(139,255,62,0.28)' }}
                >
                  for Action.
                </span>
              </h2>
            </AnimatedFadeIn>

            <AnimatedFadeIn delay={0.22}>
              <p className="text-[rgba(255,255,255,0.44)] text-base leading-relaxed max-w-[400px] mb-10">
                Every scan produces four structured outputs — designed for security teams, developers,
                and executives who need clarity, not raw data.
              </p>
            </AnimatedFadeIn>

            {/* Tab list */}
            <div className="flex flex-col gap-2 mb-10">
              {TABS.map((tab, i) => (
                <button
                  key={i}
                  onClick={() => setActive(i)}
                  className="flex items-start gap-4 px-4 py-3.5 rounded-[12px] text-left transition-all duration-250"
                  style={{
                    background: active === i ? 'rgba(139,255,62,0.06)' : 'transparent',
                    border: active === i
                      ? '1px solid rgba(139,255,62,0.2)'
                      : '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  <div
                    className="w-1 rounded-full flex-shrink-0 mt-1 transition-all duration-300"
                    style={{
                      height: active === i ? 36 : 16,
                      background: active === i ? '#8BFF3E' : 'rgba(255,255,255,0.12)',
                      boxShadow: active === i ? '0 0 8px rgba(139,255,62,0.5)' : 'none',
                    }}
                  />
                  <div>
                    <span
                      className="text-[13px] font-semibold block transition-colors duration-250"
                      style={{ color: active === i ? '#fff' : 'rgba(255,255,255,0.45)' }}
                    >
                      {tab.label}
                    </span>
                    <span className="text-[11px] text-[rgba(255,255,255,0.28)] mt-0.5 block">
                      {tab.sub}
                    </span>
                  </div>
                </button>
              ))}
            </div>

            <AnimatedFadeIn delay={0.4}>
              <Link href="/dashboard" tabIndex={-1}>
                <PrimaryButton>Start Free Scan</PrimaryButton>
              </Link>
            </AnimatedFadeIn>
          </div>

          {/* ── Right — preview ───────────────────────────────────────── */}
          <div>
            <AnimatePresence mode="wait">
              <motion.div
                key={active}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.28, ease: [0.25, 0.46, 0.45, 0.94] }}
              >
                {(() => {
                  const Preview = PREVIEWS[active]
                  return <Preview />
                })()}
              </motion.div>
            </AnimatePresence>
          </div>

        </div>
      </SectionContainer>

      <GradientDivider className="absolute bottom-0 left-0 right-0" />
    </section>
  )
}
