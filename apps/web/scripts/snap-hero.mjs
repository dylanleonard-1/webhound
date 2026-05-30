#!/usr/bin/env node
// WebHound — apps/web/scripts/snap-hero.mjs
//
// Self-iterate screenshot loop for the landing hero (and any
// other route).
//
// What it does:
//   1. Checks the local Next.js dev server is reachable.
//   2. Headless Chromium navigates to the URL.
//   3. Waits for fonts + images + animations to settle.
//   4. Screenshots at one or more viewports.
//   5. Writes the PNGs into /tmp/webhound-hero/ where the
//      assistant (or you) can open them.
//
// Usage:
//   node apps/web/scripts/snap-hero.mjs                  # default: home page, all breakpoints
//   node apps/web/scripts/snap-hero.mjs /scan            # different route
//   node apps/web/scripts/snap-hero.mjs / desktop,mobile # subset of breakpoints
//
// The dev server is NOT started by this script (Turbopack
// boot takes ~10-20s and stays warm between iterations).
// Start it once with `npm run dev` in another shell:
//
//   cd apps/web && npm run dev
//
// If the server isn't up, this script exits non-zero with a
// clear hint.

import { chromium } from 'playwright'
import { existsSync, mkdirSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { setTimeout as sleep } from 'node:timers/promises'

const BASE_URL = process.env.SNAP_BASE_URL || 'http://localhost:3000'
const OUT_DIR  = process.env.SNAP_OUT_DIR  || '/tmp/webhound-hero'

// Breakpoints we care about for the hero. Width × height in CSS
// pixels. devicePixelRatio kept at 1 so PNGs are file-size
// friendly; bump to 2 if you want retina-sharp captures.
const VIEWPORTS = {
  desktop:  { width: 1920, height: 1080, deviceScaleFactor: 1 },
  laptop:   { width: 1366, height: 768,  deviceScaleFactor: 1 },
  tablet:   { width: 1024, height: 768,  deviceScaleFactor: 1 },
  mobile:   { width: 390,  height: 844,  deviceScaleFactor: 1 },
}

// ── argv ─────────────────────────────────────────────────────
const route = process.argv[2] || '/'
const requested = (process.argv[3] || '').split(',').filter(Boolean)
const targets = requested.length
  ? requested.filter(name => VIEWPORTS[name])
  : Object.keys(VIEWPORTS)

if (!targets.length) {
  console.error(`No valid breakpoint in: ${requested.join(',')}`)
  console.error(`Available: ${Object.keys(VIEWPORTS).join(', ')}`)
  process.exit(2)
}

// ── ensure out dir ───────────────────────────────────────────
if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true })

// ── ping the dev server ──────────────────────────────────────
async function ping(url) {
  try {
    const res = await fetch(url, { method: 'HEAD' })
    return res.ok || res.status < 500
  } catch {
    return false
  }
}

if (!(await ping(BASE_URL))) {
  console.error(`✖  Dev server not reachable at ${BASE_URL}`)
  console.error(`   Start it first:`)
  console.error(`     cd apps/web && npm run dev`)
  process.exit(1)
}

// ── shoot ────────────────────────────────────────────────────
const browser = await chromium.launch({ headless: true })
try {
  for (const name of targets) {
    const vp = VIEWPORTS[name]
    const ctx = await browser.newContext({
      viewport: { width: vp.width, height: vp.height },
      deviceScaleFactor: vp.deviceScaleFactor,
      // Reduce motion so animated frames don't randomize captures.
      // Toggle off if you specifically want to see animation state.
      reducedMotion: process.env.SNAP_REDUCED_MOTION === '0' ? 'no-preference' : 'reduce',
      colorScheme: 'dark',
    })
    const page = await ctx.newPage()

    const url = `${BASE_URL}${route}`
    console.log(`→ ${name.padEnd(8)} ${vp.width}×${vp.height}  ${url}`)
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 })

    // Belt-and-suspenders: wait for fonts + images.
    await page.evaluate(() => document.fonts?.ready)
    await page.waitForFunction(() => {
      const imgs = Array.from(document.images)
      return imgs.every(i => i.complete && (i.naturalWidth > 0 || i.loading === 'lazy'))
    }, { timeout: 10_000 }).catch(() => {})
    // One extra paint frame.
    await sleep(250)

    const slug = route.replace(/\W+/g, '_').replace(/^_|_$/g, '') || 'home'
    const file = `${OUT_DIR}/hero_${slug}_${name}.png`
    const buf = await page.screenshot({
      fullPage: false,            // hero is above-the-fold, viewport-only is what we want
      type: 'png',
      omitBackground: false,
    })
    await writeFile(file, buf)
    console.log(`  ✓ ${file}  (${(buf.length / 1024).toFixed(0)} KB)`)

    await ctx.close()
  }
} finally {
  await browser.close()
}

console.log(`\nDone. Open with:`)
for (const name of targets) {
  const slug = route.replace(/\W+/g, '_').replace(/^_|_$/g, '') || 'home'
  console.log(`  ${OUT_DIR}/hero_${slug}_${name}.png`)
}
