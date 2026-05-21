export function MockDashboard() {
  return (
    <div className="relative mx-auto max-w-2xl">
      <div className="absolute -inset-4 rounded-3xl bg-accent-green/5 blur-3xl pointer-events-none" />
      <div className="relative rounded-2xl border border-white/[0.10] bg-[#111827] overflow-hidden shadow-2xl">
        {/* Browser chrome */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.07] bg-[#0D1520]">
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
          </div>
          <div className="flex-1 mx-3 px-3 py-1 rounded bg-[#0B0F19] border border-white/[0.06] text-center">
            <span className="text-[10px] text-gray-500 font-mono">app.webhound.io/dashboard</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
            <span className="text-[10px] text-accent-green font-mono">LIVE</span>
          </div>
        </div>

        {/* Grid panels */}
        <div className="p-4 grid grid-cols-3 gap-3">
          {/* Risk gauge */}
          <div className="rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
            <p className="text-[9px] text-gray-600 font-mono uppercase tracking-widest mb-2">Risk Score</p>
            <div className="flex flex-col items-center py-1">
              <div className="relative w-16 h-16 flex items-center justify-center">
                <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 64 64">
                  <circle cx="32" cy="32" r="26" stroke="#1F2937" strokeWidth="5" fill="none" />
                  <circle
                    cx="32" cy="32" r="26"
                    stroke="#EAB308"
                    strokeWidth="5"
                    fill="none"
                    strokeDasharray={`${2 * Math.PI * 26 * 0.42} ${2 * Math.PI * 26 * (1 - 0.42)}`}
                    strokeLinecap="round"
                  />
                </svg>
                <span className="text-lg font-bold font-mono text-yellow-400">42</span>
              </div>
              <p className="text-[10px] text-yellow-400 font-medium mt-1.5">Medium Risk</p>
            </div>
            <div className="space-y-1 mt-2">
              {[
                { l: '1 HIGH', c: 'text-orange-400 bg-orange-500/10 border-orange-500/25' },
                { l: '3 MEDIUM', c: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25' },
                { l: '5 LOW', c: 'text-blue-400 bg-blue-500/10 border-blue-500/25' },
              ].map(b => (
                <span
                  key={b.l}
                  className={`block text-center text-[9px] font-mono px-1.5 py-0.5 rounded border ${b.c}`}
                >
                  {b.l}
                </span>
              ))}
            </div>
          </div>

          {/* Top findings */}
          <div className="col-span-2 rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
            <p className="text-[9px] text-gray-600 font-mono uppercase tracking-widest mb-2">Top Findings</p>
            <div className="space-y-1.5">
              {[
                { dot: 'bg-orange-400', t: 'Missing Content-Security-Policy' },
                { dot: 'bg-yellow-400', t: 'Third-party script: analytics.io' },
                { dot: 'bg-yellow-400', t: 'Cookie missing Secure flag' },
                { dot: 'bg-blue-400', t: 'No Subresource Integrity (SRI)' },
                { dot: 'bg-blue-400', t: 'X-Frame-Options not set' },
              ].map((f, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg bg-[#111827] px-2.5 py-1.5">
                  <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${f.dot}`} />
                  <span className="text-[9px] text-gray-400 truncate">{f.t}</span>
                </div>
              ))}
            </div>
          </div>

          {/* External domains */}
          <div className="col-span-2 rounded-xl border border-white/[0.06] bg-[#0B0F19] p-3">
            <p className="text-[9px] text-gray-600 font-mono uppercase tracking-widest mb-2">External Domains</p>
            <div className="space-y-1.5">
              {[
                { d: 'cdn.jsdelivr.net', c: 'CDN', cc: 'text-blue-400 bg-blue-500/10' },
                { d: 'analytics.google.com', c: 'Analytics', cc: 'text-purple-400 bg-purple-500/10' },
                { d: 'fonts.googleapis.com', c: 'CDN', cc: 'text-blue-400 bg-blue-500/10' },
                { d: 'unknown-tracker.io', c: 'Unknown', cc: 'text-yellow-400 bg-yellow-500/10' },
              ].map((d, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg bg-[#111827] px-2.5 py-1.5">
                  <span className="text-[9px] text-gray-400 font-mono truncate flex-1">{d.d}</span>
                  <span className={`text-[8px] px-1.5 py-0.5 rounded font-medium ${d.cc}`}>{d.c}</span>
                </div>
              ))}
            </div>
          </div>

          {/* WADE status */}
          <div className="rounded-xl border border-accent-green/20 bg-accent-green/[0.03] p-3">
            <p className="text-[9px] text-accent-green/70 font-mono uppercase tracking-widest mb-2">WADE</p>
            <div className="space-y-2.5">
              <div>
                <p className="text-[9px] text-gray-500 mb-0.5">Anomaly Score</p>
                <div className="flex items-center gap-1.5">
                  <div className="flex-1 h-1 rounded-full bg-white/[0.06]">
                    <div className="h-full w-[22%] rounded-full bg-accent-green" />
                  </div>
                  <span className="text-[9px] text-accent-green font-mono">0.22</span>
                </div>
              </div>
              <div>
                <p className="text-[9px] text-gray-500">New scripts</p>
                <p className="text-[10px] text-white font-semibold">0 detected</p>
              </div>
              <div>
                <p className="text-[9px] text-gray-500">New domains</p>
                <p className="text-[10px] text-yellow-400 font-semibold">1 flagged</p>
              </div>
              <span className="inline-block text-[9px] px-1.5 py-0.5 rounded-full bg-accent-green/15 text-accent-green border border-accent-green/20">
                Baseline active
              </span>
            </div>
          </div>
        </div>

        {/* Footer strip */}
        <div className="px-4 py-2.5 border-t border-white/[0.06] bg-[#0D1520] flex items-center justify-between">
          <span className="text-[9px] text-gray-600 font-mono">Powered by WADE · Passive scan · example.com</span>
          <span className="text-[9px] text-accent-green font-mono">Export SARIF / CSV / MD →</span>
        </div>
      </div>
    </div>
  )
}
