"""
Q-SENTINEL 100-Event Large-Scale Statistical Benchmark
Runs an un-synthesized, empirical 100-event trial evaluation against the live application:
- 100 Blind Randomized Trials (ground-truth concealed from detector)
- Multi-trial statistical dynamics across all 11 explicit attack vectors
- Wall-clock latency distribution (Mean, Median, P95, StdDev, Min, Max)
- Confusion Matrix (TP, TN, FP, FN, Recall, Specificity, Precision, F1)
- Quantum Mismatch Rate distributions
- Evidence Ledger cryptographic audit throughput
"""
import time
import json
import statistics
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from starlette.testclient import TestClient
from apps.api.main import app

def run_large_scale_benchmark():
    client = TestClient(app)
    
    # 1. Warmup
    client.get("/v1/health")
    
    print("[1/3] Executing 100 Autonomous Blind Randomized Trials...")
    t0_blind = time.perf_counter()
    blind_resp = client.post("/v1/testbed/blind-batch", json={"batch_size": 100})
    dt_blind_total = (time.perf_counter() - t0_blind) * 1000.0
    
    if blind_resp.status_code == 200:
        blind_data = blind_resp.json()
        print(f"      Blind Batch completed in {dt_blind_total:.1f}ms")
        print(f"      Accuracy: {blind_data['metrics']['accuracy']*100:.2f}% | "
              f"Recall: {blind_data['metrics']['recall']*100:.2f}% | "
              f"FPR: {(blind_data['confusion_matrix']['FP'] / max(1, blind_data['confusion_matrix']['TN'] + blind_data['confusion_matrix']['FP']))*100:.2f}%")
    else:
        print(f"      Error running blind batch: {blind_resp.status_code} {blind_resp.text}")
        blind_data = {}

    # 2. Vector-by-Vector Multi-Trial Latency & Detection Dynamics (10 trials x 11 scenarios = 110 events)
    print("\n[2/3] Executing 110 Targeted Scenario Trials (10 trials each across 11 vectors)...")
    scenarios = [
        {"name": "legitimate", "endpoint": "/v1/testbed/attack/legitimate", "payload": {}, "expected": "ACCEPT", "category": "Honest Traffic"},
        {"name": "forgery", "endpoint": "/v1/testbed/attack/forgery", "payload": {}, "expected": "REJECT", "category": "Quantum Key Tampering"},
        {"name": "replay", "endpoint": "/v1/testbed/attack/replay", "payload": {}, "expected": "REJECT", "category": "Cryptographic Replay"},
        {"name": "impersonation", "endpoint": "/v1/testbed/attack/impersonation", "payload": {}, "expected": "REJECT", "category": "Identity Forgery"},
        {"name": "unauthorized", "endpoint": "/v1/testbed/attack/unauthorized", "payload": {}, "expected": "REJECT", "category": "Unauthorized Node"},
        {"name": "channel_high_noise", "endpoint": "/v1/testbed/attack/channel", "payload": {"disturbance_probability": 0.25}, "expected": "REJECT", "category": "Severe Channel Disturbance"},
        {"name": "channel_quarantine", "endpoint": "/v1/testbed/attack/channel", "payload": {"disturbance_probability": 0.10}, "expected": "QUARANTINE", "category": "Marginal Channel Noise"},
        {"name": "adaptive_x", "endpoint": "/v1/testbed/attack/adaptive_x", "payload": {"disturbance_prob": 0.35}, "expected": "REJECT", "category": "Coherent Basis Rotation"},
        {"name": "ledger_tamper", "endpoint": "/v1/testbed/attack/ledger_tamper", "payload": {}, "expected": "INTEGRITY_VIOLATION", "category": "Ledger Database Mutation"},
        {"name": "timing_oracle", "endpoint": "/v1/testbed/attack/timing_oracle", "payload": {}, "expected": "SECURE", "category": "Side-Channel Timing Probe"},
        {"name": "transferability", "endpoint": "/v1/testbed/attack/transferability", "payload": {}, "expected": "REJECT", "category": "Cross-Recipient State Forgery"},
    ]
    
    TRIALS_PER_VECTOR = 10
    scenario_stats = {}
    
    for sc in scenarios:
        sname = sc["name"]
        latencies = []
        outcomes = []
        mismatch_rates = []
        reasons = []
        layers = []
        
        for trial in range(TRIALS_PER_VECTOR):
            t0 = time.perf_counter()
            resp = client.post(sc["endpoint"], json=sc["payload"])
            dt_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(dt_ms)
            
            if resp.status_code == 200:
                data = resp.json()
                outcome = data.get("actual_outcome") or data.get("decision", "UNKNOWN")
                outcomes.append(outcome)
                reasons.append(data.get("reason", ""))
                layers.append(data.get("expected_primary_layer", "L3"))
                
                findings = data.get("findings", [])
                qd = next((f for f in findings if f.get("detector") == "QuantumDetector" or f.get("detector_name") == "QuantumDetector"), None)
                if qd and "metrics" in qd and "mismatch_rate" in qd["metrics"]:
                    mismatch_rates.append(qd["metrics"]["mismatch_rate"])
                elif "parameters" in data and "mismatch_rate" in data["parameters"]:
                    mismatch_rates.append(data["parameters"]["mismatch_rate"])
            else:
                outcomes.append(f"HTTP_{resp.status_code}")
                reasons.append(f"Error: {resp.text[:80]}")
        
        mean_lat = statistics.mean(latencies)
        median_lat = statistics.median(latencies)
        std_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
        p95_lat = sorted(latencies)[int(0.95 * len(latencies))]
        
        expected = sc["expected"]
        # Accept QUARANTINE or REJECT as threat detection for attack scenarios
        if expected in ["REJECT", "QUARANTINE"]:
            detected_count = sum(1 for o in outcomes if o in ["REJECT", "QUARANTINE"])
        else:
            detected_count = sum(1 for o in outcomes if o == expected)
            
        det_rate = (detected_count / TRIALS_PER_VECTOR) * 100.0
        
        scenario_stats[sname] = {
            "category": sc["category"],
            "expected_outcome": expected,
            "trials_run": TRIALS_PER_VECTOR,
            "actual_outcomes": outcomes,
            "detection_rate_pct": det_rate,
            "mean_latency_ms": round(mean_lat, 2),
            "median_latency_ms": round(median_lat, 2),
            "p95_latency_ms": round(p95_lat, 2),
            "std_dev_ms": round(std_lat, 2),
            "min_latency_ms": round(min(latencies), 2),
            "max_latency_ms": round(max(latencies), 2),
            "observed_mismatch_rate": round(statistics.mean(mismatch_rates), 4) if mismatch_rates else None,
            "sample_reason": reasons[-1] if reasons else "",
            "primary_layer": layers[-1] if layers else "N/A"
        }
        print(f"      {sname:20s}: {det_rate:5.1f}% detected | Mean: {mean_lat:6.2f}ms | P95: {p95_lat:6.2f}ms | Mismatch D: {scenario_stats[sname]['observed_mismatch_rate']}")

    # 3. Evidence Ledger Cryptographic Hash Chain Audit
    print("\n[3/3] Auditing Ledger Hash Chain...")
    t0_chain = time.perf_counter()
    chain_resp = client.get("/v1/ledger/verify-chain")
    chain_time_ms = (time.perf_counter() - t0_chain) * 1000.0
    chain_data = chain_resp.json()
    
    total_records = chain_data.get("total_records", 0)
    per_block_us = (chain_time_ms / max(1, total_records)) * 1000.0
    print(f"      Verified {total_records} records in {chain_time_ms:.2f}ms ({per_block_us:.1f}us / block). Chain valid: {chain_data.get('chain_valid')}")
    
    # Calibration Info
    cal_resp = client.get("/v1/calibration/status").json()

    output = {
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "calibration_parameters": {
            "policy_version": cal_resp.get("policy_version"),
            "tau_low": cal_resp.get("threshold_low"),
            "tau_high": cal_resp.get("threshold_high"),
            "derivation_method": "analytical_binomial_quantile (binom.ppf)",
            "base_disturbance_e_honest": 0.0253,
            "target_fpr_alpha": 1e-4
        },
        "blind_batch_100_events": blind_data,
        "targeted_scenarios_110_events": scenario_stats,
        "ledger_audit": {
            "total_records_checked": total_records,
            "audit_latency_ms": round(chain_time_ms, 2),
            "per_record_us": round(per_block_us, 2),
            "chain_valid": chain_data.get("chain_valid", False)
        }
    }
    
    out_file = os.path.join(os.path.dirname(__file__), "benchmark_100_results.json")
    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)
        
    print(f"\n[*] 100+ Event Benchmark successfully written to {out_file}")
    return output

if __name__ == "__main__":
    run_large_scale_benchmark()
