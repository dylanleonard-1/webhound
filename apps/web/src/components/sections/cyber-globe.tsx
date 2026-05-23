'use client'

import { useRef, useMemo, useEffect, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { Cpu, Shield, Radar, Building2, Eye } from 'lucide-react'
import { cn } from '@/lib/utils'

// ── Constants ─────────────────────────────────────────────────────────────────

const R         = 5
const EDGE_DIST = 2.4
const EDGE_DEG  = 4

// ── Geometry helpers ──────────────────────────────────────────────────────────

function fibSphere(n: number, r: number): THREE.Vector3[] {
  const phi = Math.PI * (3 - Math.sqrt(5))
  return Array.from({ length: n }, (_, i) => {
    const y   = 1 - (i / (n - 1)) * 2
    const rad = Math.sqrt(Math.max(0, 1 - y * y))
    const t   = phi * i
    return new THREE.Vector3(Math.cos(t) * rad * r, y * r, Math.sin(t) * rad * r)
  })
}

function buildEdges(pts: THREE.Vector3[], maxD: number, maxDeg: number): [number, number][] {
  const edges: [number, number][] = []
  const deg = new Int32Array(pts.length)
  for (let i = 0; i < pts.length; i++) {
    if (deg[i] >= maxDeg) continue
    for (let j = i + 1; j < pts.length; j++) {
      if (deg[j] >= maxDeg) continue
      if (pts[i].distanceTo(pts[j]) < maxD) {
        edges.push([i, j]); deg[i]++; deg[j]++
        if (deg[i] >= maxDeg) break
      }
    }
  }
  return edges
}

// ── Dark sphere base — pure black so dots read like a holographic display ─────

function GlobeBase() {
  return (
    <mesh renderOrder={0}>
      <sphereGeometry args={[R * 0.995, 64, 64]} />
      <meshBasicMaterial color="#000308" />
    </mesh>
  )
}

// ── Dense white particle cloud ────────────────────────────────────────────────

function GlobeParticles({ count }: { count: number }) {
  const positions = useMemo(() => {
    const pts = fibSphere(count, R)
    const arr = new Float32Array(count * 3)
    pts.forEach((p, i) => { arr[i*3] = p.x; arr[i*3+1] = p.y; arr[i*3+2] = p.z })
    return arr
  }, [count])

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        color="#d8eeff"
        size={0.024}
        transparent
        opacity={0.85}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  )
}

// ── Surface green nodes (sparse) ──────────────────────────────────────────────

const _m4 = new THREE.Matrix4()
const _q  = new THREE.Quaternion()
const _sv = new THREE.Vector3()

function NodeField({ pts, scale, color }: { pts: THREE.Vector3[]; scale: number; color: string }) {
  const meshRef = useRef<THREE.InstancedMesh>(null)

  useEffect(() => {
    const m = meshRef.current; if (!m) return
    pts.forEach((p, i) => {
      _sv.setScalar(scale); _m4.compose(p, _q, _sv); m.setMatrixAt(i, _m4)
    })
    m.instanceMatrix.needsUpdate = true
  }, [pts, scale])

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, pts.length]}>
      <sphereGeometry args={[1, 8, 8]} />
      <meshBasicMaterial color={color} toneMapped={false} />
    </instancedMesh>
  )
}

// ── Outer network shell — sits just beyond the globe surface ──────────────────

function OuterMesh({ inner, outer, edges }: { inner: THREE.Vector3[]; outer: THREE.Vector3[]; edges: [number, number][] }) {
  // Build lines that connect outer nodes to each other (the mesh) AND to a few
  // inner-surface dots (anchor strands). Together it reads as a polyhedral
  // shell hovering around the globe.
  const pos = useMemo(() => {
    const arr = new Float32Array((edges.length + outer.length) * 6)
    let o = 0
    edges.forEach(([a, b]) => {
      const pa = outer[a], pb = outer[b]
      arr.set([pa.x, pa.y, pa.z, pb.x, pb.y, pb.z], o); o += 6
    })
    // Each outer node also drops a thin strand down to the nearest inner point.
    outer.forEach((op, i) => {
      const ip = inner[Math.floor((i / outer.length) * inner.length)]
      if (!ip) return
      arr.set([op.x, op.y, op.z, ip.x, ip.y, ip.z], o); o += 6
    })
    return arr
  }, [inner, outer, edges])

  return (
    <lineSegments>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[pos, 3]} />
      </bufferGeometry>
      <lineBasicMaterial color="#7CFF00" transparent opacity={0.32} depthWrite={false} />
    </lineSegments>
  )
}

// ── Subtle rim shell — soft halo at the edge ──────────────────────────────────

function RimShell() {
  return (
    <mesh scale={1.04}>
      <sphereGeometry args={[R, 36, 36]} />
      <meshBasicMaterial
        color="#9bd8ff"
        side={THREE.BackSide}
        transparent
        opacity={0.05}
        depthWrite={false}
      />
    </mesh>
  )
}

// ── Globe scene ───────────────────────────────────────────────────────────────

function GlobeScene({ nParticles, nSurfaceNodes, nOuterNodes }: {
  nParticles: number; nSurfaceNodes: number; nOuterNodes: number
}) {
  const groupRef = useRef<THREE.Group>(null)

  const innerPts  = useMemo(() => fibSphere(nSurfaceNodes, R), [nSurfaceNodes])
  // Surface green nodes are a thinned subset of the inner field.
  const surfaceNodes = useMemo(
    () => innerPts.filter((_, i) => i % 5 === 0),
    [innerPts],
  )
  // Outer nodes ride at 1.18 * R — close enough to feel attached, far enough
  // to read as a separate mesh shell.
  const outerPts = useMemo(() => fibSphere(nOuterNodes, R * 1.18), [nOuterNodes])
  const outerEdges = useMemo(() => buildEdges(outerPts, EDGE_DIST, EDGE_DEG), [outerPts])

  useFrame((_, delta) => {
    if (!groupRef.current) return
    groupRef.current.rotation.y += delta * 0.035
  })

  return (
    <>
      <ambientLight intensity={0.7} />

      <group ref={groupRef}>
        <GlobeBase />
        <RimShell />
        <GlobeParticles count={nParticles} />
        <NodeField pts={surfaceNodes} scale={0.045} color="#9CFF3E" />
        <NodeField pts={outerPts}     scale={0.08}  color="#7CFF00" />
        <OuterMesh inner={innerPts} outer={outerPts} edges={outerEdges} />
      </group>
    </>
  )
}

// ── Floating label badges (HTML overlay) ──────────────────────────────────────

interface Tag {
  icon: React.FC<{ className?: string }>
  label: string
  /** top/left/right/bottom as % of parent. */
  pos: { top?: string; left?: string; right?: string; bottom?: string }
}

const TAGS: Tag[] = [
  { icon: Cpu,        label: 'AI-DRIVEN',        pos: { top: '22%',    left: '14%'  } },
  { icon: Shield,     label: '24/7 PROTECTION',  pos: { top: '34%',    right: '4%'  } },
  { icon: Radar,      label: 'REAL-TIME DETECTION', pos: { top: '54%', left: '10%'  } },
  { icon: Building2,  label: 'ENTERPRISE GRADE', pos: { top: '62%',    right: '8%'  } },
  { icon: Eye,        label: 'ZERO BLIND SPOTS', pos: { bottom: '22%', left: '34%'  } },
]

function TagBadges() {
  return (
    <div className="absolute inset-0 pointer-events-none">
      {TAGS.map(({ icon: Icon, label, pos }) => (
        <div
          key={label}
          className="absolute flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold tracking-[0.12em] uppercase whitespace-nowrap"
          style={{
            ...pos,
            background: 'rgba(8,12,22,0.78)',
            border: '1px solid rgba(124,255,0,0.28)',
            color: '#9CFF3E',
            backdropFilter: 'blur(4px)',
            boxShadow: '0 0 14px rgba(124,255,0,0.12), 0 4px 14px rgba(0,0,0,0.45)',
          }}
        >
          <Icon className="w-3 h-3" />
          {label}
        </div>
      ))}
    </div>
  )
}

// ── Export ────────────────────────────────────────────────────────────────────

export default function CyberGlobe({ className }: { className?: string }) {
  const [cfg] = useState(() => {
    const mobile = typeof window !== 'undefined' && window.innerWidth < 768
    return {
      nParticles:    mobile ? 2800 : 5200,
      nSurfaceNodes: mobile ? 160  : 280,
      nOuterNodes:   mobile ? 32   : 56,
    }
  })

  return (
    <div className={cn('relative w-full h-full', className)}>
      <Canvas
        camera={{ position: [0, 0, 12], fov: 45 }}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
        dpr={[1, 1.5]}
        style={{ background: 'transparent' }}
      >
        <GlobeScene
          nParticles={cfg.nParticles}
          nSurfaceNodes={cfg.nSurfaceNodes}
          nOuterNodes={cfg.nOuterNodes}
        />
      </Canvas>
      <TagBadges />
    </div>
  )
}
