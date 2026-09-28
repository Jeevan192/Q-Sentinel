from fastapi import APIRouter, HTTPException
from src.ledger.hash_chain import global_ledger
from src.ledger.verifier import verify_ledger

router = APIRouter()

import sqlite3
import json

@router.get("/verify/{event_id}")
def verify_event(event_id: str):
    event = global_ledger.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event

from src.ledger.hash_chain import LEDGER_SECRET
import hmac
import hashlib

@router.get("/verify-chain")
def verify_chain():
    try:
        with sqlite3.connect(global_ledger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence ORDER BY seq_num ASC")
            rows = cursor.fetchall()
            if not rows:
                return {"chain_valid": True, "total_records": 0}
            genesis = rows[0]
            if genesis['event_id'] != 'genesis':
                return {"chain_valid": False, "broken_at": 0, "reason": "Genesis block tampered"}
            expected_sig = hmac.new(LEDGER_SECRET, genesis['current_hash'].encode('utf-8'), hashlib.sha256).hexdigest()
            if genesis['signature'] != expected_sig:
                return {"chain_valid": False, "broken_at": 0, "reason": "Genesis signature invalid"}
            previous_hash = genesis['current_hash']
            for i in range(1, len(rows)):
                row = rows[i]
                if row['previous_hash'] != previous_hash:
                    return {"chain_valid": False, "broken_at": row['seq_num'], "reason": "Linkage broken"}
                canonical_fields = {
                    "seq_num": row['seq_num'],
                    "event_id": row['event_id'],
                    "timestamp": row['timestamp'],
                    "session_id": row['session_id'],
                    "signer_id": row['signer_id'],
                    "verifier_id": row['verifier_id'],
                    "decision": row['decision'],
                    "findings": row['findings'],
                    "experiment_id": row['experiment_id']
                }
                canonical_event = json.dumps(canonical_fields, sort_keys=True).encode('utf-8')
                hash_input = previous_hash.encode('utf-8') + canonical_event
                expected_hash = hashlib.sha256(hash_input).hexdigest()
                if row['current_hash'] != expected_hash:
                    return {"chain_valid": False, "broken_at": row['seq_num'], "reason": f"Hash mismatch at seq_num {row['seq_num']}"}
                expected_sig = hmac.new(LEDGER_SECRET, row['current_hash'].encode('utf-8'), hashlib.sha256).hexdigest()
                if row['signature'] != expected_sig:
                    return {"chain_valid": False, "broken_at": row['seq_num'], "reason": f"HMAC signature mismatch at seq_num {row['seq_num']}"}
                previous_hash = row['current_hash']
            return {"chain_valid": True, "total_records": len(rows)}
    except Exception as e:
        return {"chain_valid": False, "error": str(e)}

@router.get("/events")
def get_recent_events(limit: int = 100):
    """Retrieve recent evidence blocks for live hash chain visualization."""
    try:
        with sqlite3.connect(global_ledger.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM evidence")
            total_records = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM evidence ORDER BY seq_num DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            events = []
            for r in rows:
                item = dict(r)
                if "event_id" in item and "evidence_id" not in item:
                    item["evidence_id"] = item["event_id"]
                if isinstance(item.get("findings"), str):
                    try:
                        item["findings"] = json.loads(item["findings"])
                    except Exception:
                        pass

                # Derive rich explanatory reason if not already present
                if not item.get("reason"):
                    decision = item.get("decision")
                    findings_list = item.get("findings") if isinstance(item.get("findings"), list) else []
                    rejecting = [f for f in findings_list if f.get("severity") in ["REJECT", "QUARANTINE"]]
                    
                    if decision == "ACCEPT":
                        qd = next((f for f in findings_list if f.get("detector") == "QuantumDetector" or f.get("detector_name") == "QuantumDetector"), None)
                        if qd and "metrics" in qd:
                            m = qd["metrics"]
                            d_val = m.get("mismatch_rate", 0.0)
                            tl = m.get("tau_low", 0.1333)
                            sub = m.get("matched_subset_size", 50)
                            item["reason"] = f"Nominal transmission accepted: Mismatch rate D = {d_val:.4f} < tau_low ({tl:.4f}) over {sub} matched bits. PQC signature authentic."
                        else:
                            item["reason"] = "Nominal transmission accepted: Quantum key distribution verified within baseline thresholds with valid ML-DSA-65 envelope."
                    elif decision in ["REJECT", "QUARANTINE"]:
                        if rejecting:
                            reasons = []
                            for f in rejecting[:2]:
                                det = f.get("detector_name") or f.get("detector") or "Detector"
                                desc = f.get("description", "")
                                m = f.get("metrics", {})
                                if "mismatch_rate" in m:
                                    d_val = m["mismatch_rate"]
                                    th = m.get("tau_high", 0.1667)
                                    reasons.append(f"{det}: Mismatch rate D = {d_val:.4f} > tau_high ({th:.4f})")
                                elif desc:
                                    reasons.append(f"{det}: {desc}")
                                else:
                                    reasons.append(det)
                            item["reason"] = f"Action {decision}: " + "; ".join(reasons)
                        else:
                            item["reason"] = f"Security pipeline enforced {decision} on envelope presentation."
                    else:
                        item["reason"] = f"Ledger block recorded with status: {decision}"

                events.append(item)
            return {"total_records": total_records, "events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/tamper")
def tamper_latest_event():
    """Adversarial tamper trigger: modifies stored decision in latest evidence record."""
    try:
        with sqlite3.connect(global_ledger.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT seq_num, decision FROM evidence ORDER BY seq_num DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="No ledger events to tamper.")
            seq_num, decision = row
            new_decision = "REJECT" if decision == "ACCEPT" else "ACCEPT"
            cursor.execute("UPDATE evidence SET decision = ? WHERE seq_num = ?", (new_decision, seq_num))
            conn.commit()
            return {"status": "TAMPERED", "seq_num": seq_num, "new_decision": new_decision}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
