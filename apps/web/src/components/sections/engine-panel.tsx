'use client'

import { useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { LAYER_THEMES } from './engine-stack'

// ── Layer data with real findings ─────────────────────────────────────────────

type Sev = 'CRIT' | 'HIGH' | 'MED' | 'INFO'

interface Finding { sev: Sev; text: string }
interface LayerData {
  title: string
  purpose: string
  findings: Finding[]
  checks: number
  crits: number
  highs: number
  tip: string
}

const SEV: Record<Sev, { label: string; color: string; bg: string }> = {
  CRIT: { label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239,68,68,0.08)' },
  HIGH: { label: 'HIGH',     color: '#f97316', bg: 'rgba(249,115,22,0.08)' },
  MED:  { label: 'MEDIUM',   color: '#eab308', bg: 'rgba(234,179,8,0.07)'  },
  INFO: { label: 'INFO',     color: '#8BFF3E', bg: 'rgba(139,255,62,0.06)' },
}

const LAYERS: LayerData[] = [
  {
    title: 'Reconnaissance',
    purpose: 'Passive and active discovery of all exposed assets, subdomains, and entry points.',
    findings: [
      { sev: 'CRIT', text: 'Admin panel accessible at /admin — no auth required' },
      { sev: 'HIGH', text: 'MySQL port 3306 externally reachable' },
      { sev: 'MED',  text: 'Wildcard *.api.target.com resolves to production' },
      { sev: 'INFO', text: '12 subdomains discovered via certificate transparency' },
    ],
    checks: 1240, crits: 1, highs: 3,
    tip: 'Restrict admin interfaces to VPN or IP allowlists immediately.',
  },
  {
    title: 'DNS & Infrastructure',
    purpose: 'DNS configuration, hosting chain analysis, and infrastructure relationship mapping.',
    findings: [
      { sev: 'HIGH', text: 'Zone transfer enabled — full DNS zone exposed (AXFR)' },
      { sev: 'HIGH', text: 'Dangling CNAME → s3.amazonaws.com (subdomain takeover)' },
      { sev: 'MED',  text: 'DNSSEC absent — DNS spoofing attack viable' },
      { sev: 'INFO', text: 'SPF allows 14 IP ranges — over-permissive policy' },
    ],
    checks: 890, crits: 0, highs: 2,
    tip: 'Disable AXFR zone transfer and audit all CNAMEs for dangling records.',
  },
  {
    title: 'SSL / TLS Analysis',
    purpose: 'Encryption strength, certificate validity, and protocol downgrade attack testing.',
    findings: [
      { sev: 'HIGH', text: 'TLS 1.0 accepted — POODLE and BEAST attacks viable' },
      { sev: 'HIGH', text: 'RC4 cipher suite active on port 443' },
      { sev: 'MED',  text: 'Certificate expires in 14 days — no auto-renew detected' },
      { sev: 'MED',  text: 'HSTS max-age below 1-year recommended threshold' },
    ],
    checks: 640, crits: 0, highs: 2,
    tip: 'Disable TLS 1.0/1.1 and remove RC4 suites. Enable HSTS preloading.',
  },
  {
    title: 'Vulnerability Scanning',
    purpose: 'CVE database correlation and known exploit detection across all detected services.',
    findings: [
      { sev: 'CRIT', text: 'CVE-2023-44487 HTTP/2 Rapid Reset — CVSS 7.5' },
      { sev: 'CRIT', text: 'Log4Shell variant in Spring Boot 2.6.x (CVE-2021-44228)' },
      { sev: 'HIGH', text: 'jQuery 1.9.1 — 4 unpatched CVEs including stored XSS' },
      { sev: 'MED',  text: 'WordPress 6.2.1 — security update pending' },
    ],
    checks: 18400, crits: 2, highs: 5,
    tip: 'Patch CVE-2023-44487 and upgrade Log4j to ≥2.17.1 immediately.',
  },
  {
    title: 'Web App Scanning',
    purpose: 'Dynamic OWASP Top 10 testing including injection, broken auth, and misconfiguration.',
    findings: [
      { sev: 'CRIT', text: 'SQL injection in /api/user?id= — boolean-blind confirmed' },
      { sev: 'HIGH', text: 'Reflected XSS in search param ?q= — no sanitization' },
      { sev: 'HIGH', text: 'CSRF token absent on account settings endpoint' },
      { sev: 'MED',  text: 'IDOR at /api/orders/{id} — sequential enumerable' },
    ],
    checks: 9200, crits: 1, highs: 4,
    tip: 'Parameterize queries and add CSRF tokens + strict CSP to all forms.',
  },
  {
    title: 'Configuration Review',
    purpose: 'Security headers, CORS policies, cookie flags, and server-level hardening audit.',
    findings: [
      { sev: 'HIGH', text: 'CORS: Access-Control-Allow-Origin: * — all origins allowed' },
      { sev: 'MED',  text: 'X-Frame-Options absent — clickjacking exposure confirmed' },
      { sev: 'MED',  text: 'Session cookies lack Secure + HttpOnly + SameSite flags' },
      { sev: 'INFO', text: 'Server: nginx/1.18.0 header leaks version information' },
    ],
    checks: 2100, crits: 0, highs: 1,
    tip: 'Restrict CORS to explicit origins and add all security response headers.',
  },
  {
    title: 'Threat Intelligence',
    purpose: 'Global threat feed correlation, blocklist matching, and breach database lookup.',
    findings: [
      { sev: 'HIGH', text: 'IP 104.21.x.x present in 4 threat intelligence feeds' },
      { sev: 'HIGH', text: 'Domain flagged in PhishTank as of 2023-09-14' },
      { sev: 'MED',  text: '3 credential pairs exposed in known breach datasets' },
      { sev: 'INFO', text: 'ASN linked to bulletproof hosting infrastructure' },
    ],
    checks: 6800, crits: 0, highs: 2,
    tip: 'Rotate all exposed credentials and request delisting from threat feeds.',
  },
  {
    title: 'Monitoring & Alerts',
    purpose: 'Continuous post-scan surveillance with real-time alerting for emerging threats.',
    findings: [
      { sev: 'HIGH', text: 'New CVE affecting Next.js 13.x — patch available (CVE-2024-34351)' },
      { sev: 'MED',  text: 'SSL certificate renewal required within 12 days' },
      { sev: 'MED',  text: 'Port scan activity detected from 198.51.100.0/24' },
      { sev: 'INFO', text: 'DNS propagation anomaly for api.target.com (2 resolvers)' },
    ],
    checks: 3400, crits: 0, highs: 1,
    tip: 'Enable automated certificate renewal and configure anomaly thresholds.',
  },
]

// ── Findings row (no animation — parent crossfade handles it) ─────────────────

function FindingRow({ f }: { f: Finding }) {
  const s = SEV[f.sev]
  return (
    <div className="flex items-start gap-2.5 py-2 border-b border-[rgba(255,255,255,0.05)] last:border-0">
      <span
        className="flex-shrink-0 text-[8px] font-black tracking-wider mt-[2px] px-1.5 py-[2px] rounded-[4px]"
        style={{ color: s.color, background: s.bg, border: `1px solid ${s.color}25`, minWidth: 44, textAlign: 'center' }}
      >
        {s.label}
      </span>
      <span className="text-[10.5px] text-[rgba(255,255,255,0.75)] leading-snug">{f.text}</span>
    </div>
  )
}

// ── Active layer detail card ───────────────────────────────────────────────────

function LayerDetail({ activeLayer }: { activeLayer: number }) {
  const idx   = Math.max(0, Math.min(7, activeLayer))
  const d     = LAYERS[idx]
  const theme = LAYER_THEMES[idx]

  return (
    <div
      className="rounded-[14px] overflow-hidden flex flex-col"
      style={{
        background: 'rgba(8,12,22,0.85)',
        border: `1px solid ${theme.color}22`,
      }}
    >
      {/* Header — color shifts per layer */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b flex-shrink-0"
        style={{
          background: `${theme.color}0c`,
          borderColor: `${theme.color}1e`,
        }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="text-[9px] font-black font-mono tracking-wider flex-shrink-0"
            style={{ color: theme.color + '80' }}
          >
            {String(idx + 1).padStart(2, '0')}
          </span>
          <span className="text-[11px] font-bold text-white tracking-wide truncate">
            {d.title}
          </span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
          <motion.span
            className="w-1.5 h-1.5 rounded-full flex-shrink-0"
            animate={{ opacity: [1, 0.25, 1] }}
            transition={{ duration: 1.1, repeat: Infinity }}
            style={{ background: theme.color, boxShadow: `0 0 4px ${theme.color}` }}
          />
          <span
            className="text-[8px] font-black tracking-[0.15em]"
            style={{ color: theme.color + 'b3' }}
          >
            ACTIVE
          </span>
        </div>
      </div>

      {/* Single crossfade wrapping ALL dynamic content — non-blocking popLayout */}
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.div
          key={idx}
          className="flex flex-col flex-1 min-h-0"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.16 }}
        >
          {/* Purpose */}
          <p className="text-[10px] text-[rgba(255,255,255,0.52)] leading-relaxed px-4 py-2.5 border-b border-[rgba(255,255,255,0.05)] flex-shrink-0">
            {d.purpose}
          </p>

          {/* Findings */}
          <div className="px-4 py-2.5 flex-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[8px] font-black text-[rgba(139,255,62,0.55)] tracking-[0.18em] uppercase">
                Live Findings
              </span>
              <span className="text-[8px] text-[rgba(255,255,255,0.35)] font-mono">
                {d.checks.toLocaleString()} checks run
              </span>
            </div>
            {d.findings.map((f, i) => <FindingRow key={i} f={f} />)}
          </div>

          {/* Severity bar */}
          <div
            className="flex items-center gap-3 px-4 py-2.5 border-t border-[rgba(255,255,255,0.05)] flex-shrink-0"
            style={{ background: 'rgba(255,255,255,0.01)' }}
          >
            {d.crits > 0 && (
              <span className="text-[9px] font-bold" style={{ color: '#ef4444' }}>
                {d.crits} CRIT
              </span>
            )}
            <span className="text-[9px] font-bold" style={{ color: '#f97316' }}>{d.highs} HIGH</span>
            <div className="flex-1" />
            <span className="text-[9px] text-[rgba(255,255,255,0.3)] font-mono">
              Layer {idx + 1}/8
            </span>
          </div>

          {/* Remediation tip */}
          <div className="px-4 py-3 border-t border-[rgba(255,255,255,0.05)] flex-shrink-0" style={{ background: 'rgba(255,255,255,0.01)' }}>
            <span className="text-[8px] font-black text-[rgba(139,255,62,0.5)] tracking-[0.18em] uppercase block mb-1.5">
              Fix First
            </span>
            <p className="text-[10.5px] text-[rgba(255,255,255,0.62)] leading-snug">{d.tip}</p>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

// ── Scan status ───────────────────────────────────────────────────────────────

const TOTAL = 45231
const PROGRESS = 72

function ScanStatus() {
  const countRef = useRef<HTMLSpanElement>(null)
  const barRef   = useRef<HTMLDivElement>(null)
  const rafRef   = useRef<number>(0)
  const startRef = useRef<number>(0)

  useEffect(() => {
    cancelAnimationFrame(rafRef.current)
    startRef.current = 0
    const tick = (ts: number) => {
      if (!startRef.current) startRef.current = ts
      const p = Math.min(1, (ts - startRef.current) / 1600)
      const e = 1 - Math.pow(1 - p, 3)
      if (countRef.current) countRef.current.textContent = Math.round(e * TOTAL).toLocaleString()
      if (barRef.current)   barRef.current.style.width = `${e * PROGRESS}%`
      if (p < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [])

  return (
    <div
      className="rounded-[14px] p-3.5"
      style={{ background: 'rgba(8,12,22,0.85)', border: '1px solid rgba(139,255,62,0.12)' }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <motion.span
            className="w-1.5 h-1.5 rounded-full bg-[#8BFF3E]"
            animate={{ opacity: [1, 0.2, 1] }}
            transition={{ duration: 0.95, repeat: Infinity }}
            style={{ boxShadow: '0 0 4px rgba(139,255,62,1)' }}
          />
          <span className="text-[9px] font-mono text-[rgba(255,255,255,0.4)]">target.webhoundsecurity.com</span>
        </div>
        <span className="text-[8px] font-black text-[rgba(139,255,62,0.6)] tracking-wider">SCANNING</span>
      </div>
      <div className="flex items-center gap-2 mb-2">
        <div className="flex-1 h-1 rounded-full bg-[rgba(139,255,62,0.08)] overflow-hidden">
          <div
            ref={barRef}
            className="h-full rounded-full transition-none"
            style={{ width: '0%', background: '#8BFF3E', boxShadow: '0 0 8px rgba(139,255,62,0.55)' }}
          />
        </div>
        <span className="text-[9px] font-bold text-[rgba(139,255,62,0.6)] font-mono w-7 text-right">
          {PROGRESS}%
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-[9px] text-[rgba(255,255,255,0.32)] font-mono">
          <span ref={countRef}>0</span> checks performed
        </span>
        <span className="text-[9px] text-[rgba(249,115,22,0.75)] font-mono font-bold">
          12 vulnerabilities
        </span>
      </div>
    </div>
  )
}

// ── Export ────────────────────────────────────────────────────────────────────

export function EnginePanel({ activeLayer }: { activeLayer: number }) {
  return (
    <div className="flex flex-col gap-3" style={{ width: 316, isolation: 'isolate', position: 'relative' }}>
      <LayerDetail activeLayer={activeLayer} />
      <ScanStatus />
    </div>
  )
}
