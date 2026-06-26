import type { Metadata } from 'next'
import { AcademyGuard } from '@/components/academy/academy-guard'
import { AcademyShell } from '@/components/academy/academy-shell'

// Private study tool. Two layers: (1) noindex + unlinked from public nav, and
// (2) a route-level auth gate (AcademyGuard) that mirrors the dashboard guard —
// unauthenticated users are redirected to /login. Scoped to /academy/* only.
export const metadata: Metadata = {
  title: 'PCA Risk Academy (private)',
  robots: { index: false, follow: false },
}

export default function AcademyLayout({ children }: { children: React.ReactNode }) {
  return (
    <AcademyGuard>
      <AcademyShell>{children}</AcademyShell>
    </AcademyGuard>
  )
}
