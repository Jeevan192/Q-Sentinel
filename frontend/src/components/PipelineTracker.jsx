import { CheckCircle, XCircle, AlertTriangle, Clock, ChevronRight } from 'lucide-react'

const STAGES = [
  { id: 'L3', label: 'L3 Security Guard', desc: 'Identity · Nonce · Replay · Auth' },
  { id: 'L1', label: 'L1 Quantum Core', desc: 'QDS Teleportation · Pauli Verification' },
  { id: 'L2', label: 'L2 Statistical Detector', desc: 'Deviation · χ² · Policy Evaluation' },
  { id: 'L4', label: 'L4 Evidence Ledger', desc: 'SHA-256 Hash-Chain · Immutable Record' },
]

// Map pipeline_stages array to per-stage status
// Stage values: 'L3_PASS','L3_FAIL','L1_PASS','L1_FAIL','L1_SKIP','L2_PASS','L2_WARN','L2_FAIL','L2_SKIP','L4_PASS','L4_FAIL'
function parseStageStatus(pipelineStages) {
  if (!pipelineStages) return { L3: 'pending', L1: 'pending', L2: 'pending', L4: 'pending' }
  const map = {}
  for (const s of pipelineStages) {
    const [layer, status] = s.split('_')
    if (status === 'PASS') map[layer] = 'pass'
    else if (status === 'FAIL') map[layer] = 'fail'
    else if (status === 'WARN') map[layer] = 'warn'
    else if (status === 'SKIP') map[layer] = 'skip'
  }
  return map
}

function StageNode({ stage, status, isLast }) {
  const stateConfig = {
    pass: {
      ring: 'ring-[#c6f135]/50 shadow-[#c6f135]/15',
      bg: 'bg-[#c6f135]/10',
      icon: <CheckCircle size={18} className="text-[#c6f135]" />,
      label: 'PASSED',
      labelColor: 'text-[#c6f135]',
      text: 'text-white',
    },
    fail: {
      ring: 'ring-rose-500/60 shadow-rose-500/20',
      bg: 'bg-rose-500/15',
      icon: <XCircle size={18} className="text-rose-400 animate-pulse" />,
      label: '✕ CAUGHT HERE',
      labelColor: 'text-rose-400',
      text: 'text-rose-300',
    },
    warn: {
      ring: 'ring-amber-500/60 shadow-amber-500/20',
      bg: 'bg-amber-500/15',
      icon: <AlertTriangle size={18} className="text-amber-400 animate-pulse" />,
      label: '⚠ ANOMALY',
      labelColor: 'text-amber-400',
      text: 'text-amber-300',
    },
    skip: {
      ring: 'ring-slate-700/40',
      bg: 'bg-slate-800/30',
      icon: <Clock size={18} className="text-[#8b8e97]" />,
      label: 'SKIPPED',
      labelColor: 'text-[#8b8e97]',
      text: 'text-[#8b8e97]',
    },
    pending: {
      ring: 'ring-slate-700/40',
      bg: 'bg-slate-800/30',
      icon: <Clock size={18} className="text-[#8b8e97]" />,
      label: 'PENDING',
      labelColor: 'text-[#8b8e97]',
      text: 'text-[#8b8e97]',
    },
  }

  const cfg = stateConfig[status] || stateConfig.pending

  return (
    <div className="flex items-center gap-2 flex-1 min-w-0">
      <div className={`flex-1 flex flex-col items-center gap-2 p-3 rounded-xl ring-1 shadow-lg transition-all duration-500 ${cfg.ring} ${cfg.bg}`}>
        <div className="flex items-center gap-2">
          {cfg.icon}
          <span className={`text-xs font-semibold ${cfg.text}`}>{stage.label}</span>
        </div>
        <span className="text-[#8b8e97] text-xs text-center hidden md:block">{stage.desc}</span>
        <span className={`text-xs font-mono font-semibold ${cfg.labelColor}`}>{cfg.label}</span>
      </div>

      {!isLast && (
        <ChevronRight size={16} className="text-slate-600 flex-shrink-0" />
      )}
    </div>
  )
}

export default function PipelineTracker({ result }) {
  const stageStatuses = parseStageStatus(result?.pipeline_stages)

  return (
    <div className="glass-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-2 h-2 rounded-full bg-[#c6f135] shadow-[0_0_6px_#c6f135]" />
        <h3 className="text-sm font-semibold text-white">Pipeline Stage Tracker</h3>
        {result && (
          <span className="ml-auto text-xs font-mono text-[#8b8e97]">
            evt: {result.evidence_id?.slice(0, 20)}…
          </span>
        )}
      </div>

      <div className="flex items-stretch gap-1">
        {STAGES.map((stage, i) => (
          <StageNode
            key={stage.id}
            stage={stage}
            status={stageStatuses[stage.id] || 'pending'}
            isLast={i === STAGES.length - 1}
          />
        ))}
      </div>

      {result && (
        <div className="mt-4 pt-4 border-t border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                result.decision === 'ACCEPT' || result.decision === 'SECURE' ? 'bg-[#c6f135]/15 text-[#c6f135] border border-[#c6f135]/30' :
                result.decision === 'QUARANTINE' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
                'bg-rose-500/15 text-rose-400 border border-rose-500/30'
              }`}>
                {result.decision}
              </span>
              <span className="text-xs font-semibold text-slate-200">
                Decision Rationale & Pipeline Attribution
              </span>
            </div>
            <p className="text-xs text-slate-300 font-mono leading-relaxed bg-black/40 p-2.5 rounded-lg border border-white/5">
              {result.reason || (result.decision === 'ACCEPT' ? 'Nominal baseline quantum parameters verified.' : 'Anomalous signature or disturbance intercepted.')}
            </p>
          </div>
          <div className="flex md:flex-col items-end gap-1.5 font-mono text-xs text-[#8b8e97] flex-shrink-0 self-stretch md:self-auto justify-between md:justify-start pt-1 md:pt-0">
            <div>Latency: <span className="text-white font-semibold">{Math.round(result.latency_ms)} ms</span></div>
            {result.deviation_score !== null && (
              <div>Mismatch D: <span className="text-white font-semibold">{Number(result.deviation_score).toFixed(4)}</span></div>
            )}
            {result.chi_square !== null && (
              <div>χ² Divergence: <span className="text-white font-semibold">{Number(result.chi_square).toFixed(1)}</span></div>
            )}
          </div>
        </div>
      )}

      {!result && (
        <p className="text-center text-slate-600 text-xs mt-3 font-mono">
          Run a scenario above to activate telemetry…
        </p>
      )}
    </div>
  )
}
