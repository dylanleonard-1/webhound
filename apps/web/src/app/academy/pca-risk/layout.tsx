import type { Metadata } from 'next'
import { AcademyShell } from '@/components/academy/academy-shell'

// Private/unlinked study tool. noindex so it never shows in search; NOTE this is
// NOT access-controlled (the app has no route middleware) — it's only unlinked.
export const metadata: Metadata = {
  title: 'PCA Risk Academy (private)',
  robots: { index: false, follow: false },
}

export default function AcademyLayout({ children }: { children: React.ReactNode }) {
  return <AcademyShell>{children}</AcademyShell>
}
