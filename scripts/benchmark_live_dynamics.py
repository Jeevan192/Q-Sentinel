"""
Q-SENTINEL Live Statistical Dynamics Benchmark
Executes rigorous, un-synthesized live benchmark trials across all attack scenarios
against the active backend application, measuring empirical response times, 
confusion matrices, mismatch rates, and layer attribution.
"""
import time
import json
import statistics
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from starlette.testclient import TestClient
from apps.api.main import app

def run_benchmarks():
    client = TestClient(app)
    
    # Warmup
    client.get("/v1/health")
    
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
    
    N_TRIALS = 7
    results = {}
    
    print(f"[*] Starting live benchmark suite: {len(scenarios)} scenarios x {N_TRIALS} trials...")
    
    for sc in scenarios:
        sname = sc["name"]
        latencies = []
        outcomes = []
        mismatch_rates = []
        reasons = []
        layers = []
        
        for trial in range(N_TRIALS):
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
                
                # Check for mismatch rate in findings or params
                findings = data.get("findings", [])
                qd = next((f for f in findings if f.get("detector") == "QuantumDetector" or f.get("detector_name") == "QuantumDetector"), None)
                if qd and "metrics" in qd and "mismatch_rate" in qd["metrics"]:
                    mismatch_rates.append(qd["metrics"]["mismatch_rate"])
                elif "parameters" in data and "mismatch_rate" in data["parameters"]:
                    mismatch_rates.append(data["parameters"]["mismatch_rate"])
            else:
                outcomes.append(f"HTTP_{resp.status_code}")
                reasons.append(f"Error: {resp.text[:80]}")
        
        # Calculate statistics
        mean_lat = statistics.mean(latencies)
        median_lat = statistics.median(latencies)
        std_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
        p95_lat = sorted(latencies)[int(0.95 * len(latencies))]
        
        # Accuracy / Detection verification
        expected = sc["expected"]
        correct_count = sum(1 for o in outcomes if o == expected)
        accuracy = (correct_count / N_TRIALS) * 100.0
        
        results[sname] = {
            "category": sc["category"],
            "expected_outcome": expected,
            "actual_outcomes": outcomes,
            "detection_rate_pct": accuracy,
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
        print(f" [+] {sname:20s}: {accuracy:.0f}% match | Mean Latency: {mean_lat:6.2f}ms | Outcome: {outcomes[-1]}")

    # Chain Audit Benchmark
    t0 = time.perf_counter()
    chain_resp = client.get("/v1/ledger/verify-chain")
    chain_time_ms = (time.perf_counter() - t0) * 1000.0
    chain_data = chain_resp.json()
    
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_trials_per_scenario": N_TRIALS,
        "scenarios": results,
        "ledger_chain_audit": {
            "status_code": chain_resp.status_code,
            "valid": chain_data.get("chain_valid", False),
            "total_records_verified": chain_data.get("total_records", 0),
            "audit_latency_ms": round(chain_time_ms, 2)
        }
    }
    
    output_path = os.path.join(os.path.dirname(__file__), "live_benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n[*] Benchmark complete. Results written to {output_path}")
    return summary

if __name__ == "__main__":
    run_benchmarks()
