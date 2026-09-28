import { useState, useMemo } from 'react'
import { ChevronDown, ChevronRight, ShieldCheck, ShieldAlert, RefreshCw, Database, Loader2 } from 'lucide-react'
import { verifyLedgerChain } from '../services/api'

const DECISION_TEXT_COLOR = {
  ACCEPT: 'text-[#c6f135]',
  REJECT: 'text-rose-400',
  QUARANTINE: 'text-amber-400',
  INTEGRITY_ALARM: 'text-rose-400',
  INTEGRITY_VIOLATION: 'text-rose-400',
  DISTRIBUTED: 'text-cyan-400',
  INFO: 'text-slate-400',
}

function HashCell({ hash }) {
  if (!hash) return <span className="text-[#8b8e97] font-mono text-xs">—</span>
  return (
    <span className="font-mono text-xs text-[#8b8e97] tracking-tight select-all" title={hash}>
      {hash.slice(0, 8)}…{hash.slice(-8)}
    </span>
  )
}

function EventRow({ event, index }) {
  const [expanded, setExpanded] = useState(false)
  const textColor = DECISION_TEXT_COLOR[event.decision] || 'text-slate-300'

  const seqDisplay = event.seq_num !== undefined && event.seq_num !== null
    ? `#${event.seq_num}`
    : `idx-${index + 1}`

  return (
    <>
      <tr
        onClick={() => setExpanded(v => !v)}
        className="border-b border-white/5 hover:bg-white/[0.04] cursor-pointer transition-colors"
      >
        <td className="px-3 py-2.5 text-xs font-mono whitespace-nowrap text-slate-400">
          {seqDisplay}
        </td>
        <td className="px-3 py-2.5">
          <span className="font-mono text-xs text-[#c6f135]/90 select-all">
            {event.event_id || event.evidence_id || '—'}
          </span>
        </td>
        <td className="px-3 py-2.5 text-[#8b8e97] text-xs whitespace-nowrap font-mono">
          {(() => {
            const t = event.timestamp
            const ms = typeof t === 'number' && t < 1e11 ? t * 1000 : t
            try {
              return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
            } catch {
              return '—'
            }
          })()}
        </td>
        <td className="px-3 py-2.5 text-slate-300 text-xs font-mono">{event.signer_id}</td>
        <td className="px-3 py-2.5 text-[#8b8e97] text-xs font-mono">{event.verifier_id}</td>
        <td className="px-3 py-2.5">
          <span className={`font-mono text-xs font-bold tracking-wide ${textColor}`}>
            {event.decision}
          </span>
        </td>
        <td className="px-3 py-2.5"><HashCell hash={event.previous_hash} /></td>
        <td className="px-3 py-2.5"><HashCell hash={event.current_hash} /></td>
        <td className="px-3 py-2.5 text-slate-600 text-right">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </td>
      </tr>

      {expanded && (
        <tr className="bg-black/60 border-b border-white/5">
          <td colSpan={9} className="px-6 py-4">
            <div className="flex flex-col gap-2.5 mb-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                <span className="text-white font-semibold flex items-center gap-1.5">
                  <Database size={13} className="text-[#c6f135]" />
                  Block #{event.seq_num} Cryptographic Proof
                </span>
                <span className="text-slate-400 text-[11px]">
                  Signer: <span className="text-slate-200">{event.signer_id}</span> → Verifier: <span className="text-slate-200">{event.verifier_id}</span>
                </span>
              </div>
              {event.reason && (
                <div className="text-xs font-mono p-2.5 rounded-lg bg-slate-900/90 border border-white/10 flex items-start gap-2">
                  <span className={`font-bold ${textColor} flex-shrink-0`}>[{event.decision}]</span>
                  <span className="text-slate-300 leading-relaxed">{event.reason}</span>
                </div>
              )}
            </div>
            <pre className="text-xs font-mono text-slate-400 whitespace-pre-wrap max-h-64 overflow-y-auto bg-slate-950 p-3 rounded-lg border border-white/10">
              {JSON.stringify(event, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

export default function LedgerInspector({ events = [], onRefresh }) {
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState(null)

  const totalCount = events?.total_records ?? events?.length ?? 0

  // Guarantee most recent event is always at index 0 (top of the ledger)
  const sortedEvents = useMemo(() => {
    const list = Array.isArray(events) ? [...events] : []
    return list.sort((a, b) => {
      const seqA = a.seq_num != null ? Number(a.seq_num) : null
      const seqB = b.seq_num != null ? Number(b.seq_num) : null
      if (seqA !== null && seqB !== null) return seqB - seqA
      const tA = typeof a.timestamp === 'number' ? a.timestamp : 0
      const tB = typeof b.timestamp === 'number' ? b.timestamp : 0
      return tB - tA
    })
  }, [events])

  const handleAudit = async () => {
    setAuditing(true)
    const res = await verifyLedgerChain()
    setAuditResult(res)
    setAuditing(false)
  }

  return (
    <section className="px-6 pb-8">
      {/* Section Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-2.5">
          <Database size={17} className="text-[#c6f135]" />
          <h2 className="text-base font-semibold text-white">Tamper-Evident Evidence Ledger</h2>
          <span className="text-xs text-[#8b8e97] font-mono">
            ({totalCount > sortedEvents.length ? `${sortedEvents.length} of ${totalCount}` : sortedEvents.length} records · Newest on top)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
              border border-white/10 bg-slate-900/60 text-[#8b8e97]
              hover:border-[#c6f135]/40 hover:text-white transition-all"
          >
            <RefreshCw size={11} /> Refresh
          </button>
          <button
            onClick={handleAudit}
            disabled={auditing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
              border border-[#c6f135]/40 bg-[#c6f135]/10 text-[#c6f135]
              hover:bg-[#c6f135]/20 transition-all disabled:opacity-50"
          >
            {auditing
              ? <><Loader2 size={11} className="animate-spin" /> Auditing Chain…</>
              : <><ShieldCheck size={11} /> Verify Hash Chain</>
            }
          </button>
        </div>
      </div>

      {/* Audit result banner */}
      {auditResult && (
        <div className={`mb-4 flex items-center gap-3 px-4 py-3 rounded-xl border text-xs font-mono animate-slide-in
          ${auditResult.valid
            ? 'border-[#c6f135]/40 bg-[#c6f135]/10 text-[#c6f135]'
            : 'border-rose-500/40 bg-rose-500/10 text-rose-300'
          }`}>
          {auditResult.valid
            ? <><ShieldCheck size={15} /> Cryptographic hash chain verified intact: {auditResult.events_checked ?? totalCount} records audited via HMAC-SHA256.</>
            : <><ShieldAlert size={15} /> INTEGRITY VIOLATION DETECTED: Chain broken at block #{auditResult.broken_at}. HMAC or previous_hash mismatch.</>
          }
          {auditResult._mock && <span className="ml-auto text-xs opacity-60">[mock]</span>}
        </div>
      )}

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/8 bg-slate-900/50">
                {['Seq / Block', 'Event ID', 'Timestamp', 'Signer', 'Verifier', 'Decision', 'Prev Hash', 'Curr Hash', ''].map(h => (
                  <th key={h} className="px-3 py-2.5 text-slate-500 text-xs font-semibold uppercase tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-slate-600 text-sm font-mono">
                    No ledger events recorded yet. Run a verification trial to populate blocks.
                  </td>
                </tr>
              ) : (
                sortedEvents.map((evt, i) => (
                  <EventRow key={evt.event_id || evt.evidence_id || evt.seq_num || i} event={evt} index={i} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
