import { Loader2 } from 'lucide-react'

interface LoadingStateProps {
  message?: string
}

export function LoadingState({ message }: LoadingStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <div className="relative">
        <div
          className="w-10 h-10 rounded-full"
          style={{ border: '1px solid rgba(139,255,62,0.15)' }}
        />
        <Loader2
          className="w-5 h-5 animate-spin absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
          style={{ color: '#8BFF3E' }}
        />
      </div>
      <p className="text-[12px] font-medium" style={{ color: 'rgba(255,255,255,0.32)' }}>
        {message ?? 'Loading…'}
      </p>
    </div>
  )
}
