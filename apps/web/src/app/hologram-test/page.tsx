/* 🧪 DEV-ONLY SANDBOX ROUTE — NOT part of the live site UX.
   This is the /hologram-test tuning lab (noindex). It is NOT linked from any
   nav/page and is NOT the homepage hologram. It renders the SHARED
   HologramPrototype in standalone mode purely for tuning.
   The LIVE hologram users see is app/page.tsx → hero.tsx → <HologramPrototype
   embedded />. Visit /hologram-test (add ?holo-debug for the tuning panel). */
import HologramPrototype from '@/components/experiments/HologramPrototype'

export const metadata = {
  title: 'Hologram Prototype',
  robots: { index: false, follow: false },
}

export default function HologramTestPage() {
  return (
    <main className="fixed inset-0 bg-black">
      <HologramPrototype />
    </main>
  )
}
