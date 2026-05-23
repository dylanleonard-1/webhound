import { redirect } from 'next/navigation'

// /how-it-works was a duplicate of /scanner with a different headline.
// Consolidated into /scanner so visitors stop seeing the same content twice.
export default function HowItWorksPage() {
  redirect('/scanner')
}
