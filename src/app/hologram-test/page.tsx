/* Standalone hologram sandbox — not linked from anywhere in the app.
   Visit /hologram-test (add ?holo-debug for the tuning panel). */
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
