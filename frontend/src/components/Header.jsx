export default function Header() {
  return (
    <header className="relative px-6 pt-10 pb-4 text-center">
      {/* Banner */}
      <div className="mb-3.5 inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-[#c6f135]/25 bg-[#c6f135]/5 text-[#c6f135] text-[11px] font-medium tracking-[0.25em] uppercase">
        SIH 2026 · PS SIH26141 · Egreen Quanta
      </div>

      <h1 className="text-4xl sm:text-5xl lg:text-6xl font-normal tracking-[0.08em] mb-2 text-white flex items-center justify-center">
        <span style={{ fontFamily: "'Cinzel', serif" }}>Q-SENTINEL</span>
      </h1>

      <p className="text-[#8b8e97] text-sm sm:text-base font-light tracking-wide max-w-2xl mx-auto">
        Teleportation-Based Quantum Digital Signature Threat Detection System
      </p>

      {/* Divider */}
      <div className="mt-6 h-px bg-gradient-to-r from-transparent via-[#c6f135]/20 to-transparent max-w-4xl mx-auto" />
    </header>
  )
}
