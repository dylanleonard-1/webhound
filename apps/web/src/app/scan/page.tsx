// WebHound — apps/web/src/app/scan/page.tsx
// Phase-rebuild Slice 1: canonical destination for every "Start Free
// Scan" CTA on the public site. Today this 308-redirects to the
// existing /scanner page so all CTAs land somewhere real with no
// 404 risk. A subsequent slice will replace this with the
// frictionless URL-entry experience (Q5 long-term intent: URL →
// instant demo scan → register to save).
//
// Server-component redirect — zero client JS, zero flash.

import { redirect } from 'next/navigation'

export default function ScanEntryRedirect() {
  redirect('/scanner')
}
