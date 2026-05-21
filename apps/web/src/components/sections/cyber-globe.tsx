'use client'

import { useRef, useMemo, useEffect, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { cn } from '@/lib/utils'

// ── Constants ─────────────────────────────────────────────────────────────────

const R         = 5
const EDGE_DIST = 2.1
const EDGE_DEG  = 3

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

// ── Dark sphere base ──────────────────────────────────────────────────────────

function GlobeBase() {
  return (
    <mesh renderOrder={0}>
      <sphereGeometry args={[R * 0.998, 64, 64]} />
      <meshStandardMaterial color="#010308" roughness={1} metalness={0} />
    </mesh>
  )
}

// ── Static white particle cloud ───────────────────────────────────────────────

function GlobeParticles({ count }: { count: number }) {
  const positions = useMemo(() => {
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      const theta = Math.random() * Math.PI * 2
      const phi   = Math.acos(2 * Math.random() - 1)
      arr[i * 3]     = R * Math.sin(phi) * Math.cos(theta)
      arr[i * 3 + 1] = R * Math.sin(phi) * Math.sin(theta)
      arr[i * 3 + 2] = R * Math.cos(phi)
    }
    return arr
  }, [count])

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        color="#cce8ff"
        size={0.016}
        transparent
        opacity={0.32}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  )
}

// ── Static sparse green nodes ─────────────────────────────────────────────────

const _m4 = new THREE.Matrix4()
const _q  = new THREE.Quaternion()
const _sv = new THREE.Vector3()

function NodeField({ pts }: { pts: THREE.Vector3[] }) {
  const meshRef = useRef<THREE.InstancedMesh>(null)

  useEffect(() => {
    const m = meshRef.current; if (!m) return
    pts.forEach((p, i) => {
      _sv.setScalar(0.032); _m4.compose(p, _q, _sv); m.setMatrixAt(i, _m4)
    })
    m.instanceMatrix.needsUpdate = true
  }, [pts])

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, pts.length]}>
      <sphereGeometry args={[1, 5, 5]} />
      <meshStandardMaterial
        color="#7CFF00"
        emissive="#7CFF00"
        emissiveIntensity={0.9}
        toneMapped={false}
      />
    </instancedMesh>
  )
}

// ── Static thin green connection lines ────────────────────────────────────────

function ConnectionLines({ pts, edges }: { pts: THREE.Vector3[]; edges: [number, number][] }) {
  const { pos, col } = useMemo(() => {
    const pos = new Float32Array(edges.length * 6)
    const col = new Float32Array(edges.length * 6)
    edges.forEach(([a, b], i) => {
      const pa = pts[a], pb = pts[b]
      pos.set([pa.x, pa.y, pa.z, pb.x, pb.y, pb.z], i * 6)
      // Uniform low-opacity green
      const c = 0.09
      col.set([0.35 * c, c, 0.5 * c, 0.35 * c, c, 0.5 * c], i * 6)
    })
    return { pos, col }
  }, [pts, edges])

  return (
    <lineSegments>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[pos, 3]} />
        <bufferAttribute attach="attributes-color"    args={[col, 3]} />
      </bufferGeometry>
      <lineBasicMaterial vertexColors transparent depthWrite={false} />
    </lineSegments>
  )
}

// ── Subtle static rim shell ───────────────────────────────────────────────────

function RimShell() {
  return (
    <mesh scale={1.055}>
      <sphereGeometry args={[R, 36, 36]} />
      <meshBasicMaterial
        color="#aaccee"
        side={THREE.BackSide}
        transparent
        opacity={0.028}
        depthWrite={false}
      />
    </mesh>
  )
}

// ── Globe scene ───────────────────────────────────────────────────────────────

function GlobeScene({ nParticles, nNodes }: { nParticles: number; nNodes: number }) {
  const groupRef = useRef<THREE.Group>(null)

  const allPts  = useMemo(() => fibSphere(nNodes, R), [nNodes])
  const nodePts = useMemo(
    // Pick every 4th node for sparse green dots (~25% of total)
    () => allPts.filter((_, i) => i % 4 === 0),
    [allPts],
  )
  const edges = useMemo(() => buildEdges(allPts, EDGE_DIST, EDGE_DEG), [allPts])

  // Only rotation — no floating, no oscillation
  useFrame((_, delta) => {
    if (!groupRef.current) return
    groupRef.current.rotation.y += delta * 0.03
  })

  return (
    <>
      {/* Static lighting — never animates */}
      <ambientLight intensity={0.12} />
      <directionalLight position={[8, 6, 8]}  intensity={0.55} color="#ffffff" />
      <pointLight      position={[-7, 3, 3]}  intensity={0.28} color="#8BFF3E" />

      <group ref={groupRef}>
        <GlobeBase />
        <RimShell />
        <GlobeParticles count={nParticles} />
        <NodeField  pts={nodePts} />
        <ConnectionLines pts={allPts} edges={edges} />
      </group>
    </>
  )
}

// ── Export ────────────────────────────────────────────────────────────────────

export default function CyberGlobe({ className }: { className?: string }) {
  const [cfg] = useState(() => {
    const mobile = typeof window !== 'undefined' && window.innerWidth < 768
    return {
      nParticles: mobile ? 1600 : 3800,
      nNodes:     mobile ? 120  : 240,
    }
  })

  return (
    <div className={cn('w-full h-full', className)}>
      <Canvas
        camera={{ position: [0, 0, 12], fov: 45 }}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
        dpr={[1, 1.5]}
        style={{ background: 'transparent' }}
      >
        <GlobeScene nParticles={cfg.nParticles} nNodes={cfg.nNodes} />
      </Canvas>
    </div>
  )
}
