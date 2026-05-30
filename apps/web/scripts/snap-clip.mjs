import { chromium } from 'playwright'
const browser = await chromium.launch({ headless: true })
const ctx = await browser.newContext({
  viewport: { width: 1920, height: 1080 },
  colorScheme: 'dark',
  reducedMotion: 'reduce',
})
const page = await ctx.newPage()
await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' })
await page.evaluate(() => document.fonts?.ready)
await new Promise(r => setTimeout(r, 400))
// Clip to the right half of the hero — that's where the tablet+puck+hologram live.
await page.screenshot({
  path: '/tmp/webhound-hero/hologram_zoom.png',
  clip: { x: 1100, y: 60, width: 780, height: 620 },
})
await browser.close()
console.log('done')
