import type { Metadata } from 'next'
import type { ReactNode } from 'react'

export const metadata: Metadata = {
  title: 'Contact',
  description: 'How to reach WebHound for support, security disclosures, sales, abuse, and legal.',
}

export default function ContactLayout({ children }: { children: ReactNode }) {
  return children
}
