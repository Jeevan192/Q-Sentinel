"""
Q-SENTINEL Decision Policy.

Defines the QUARANTINE and REJECT thresholds.
"""
import json
import os
from typing import Tuple
from src.calibration.analytical import derive_thresholds

class TransferableResult(str):
    """Result of dual-threshold transferability evaluation, usable as str or (decision, findings) tuple."""
    def __new__(cls, decision: str, findings=None):
        obj = str.__new__(cls, decision)
        obj.decision = decision
        obj.findings = findings or []
        return obj

    def __iter__(self):
        yield self.decision
        yield self.findings


class DecisionPolicy:
    def __init__(self, filepath: str = "data/calibration/thresholds.json"):
        self.filepath = filepath
        self.tau_low = 0.05
        self.tau_high = 0.15
        self.version = "uncalibrated"
        self.provenance = {}
        self.load_thresholds()

    def load_thresholds(self):
        """Load thresholds from disk. If corrupt, fails closed to uncalibrated."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    data = json.load(f)
                    if not isinstance(data, dict) or "tau_low" not in data or "tau_high" not in data:
                        raise ValueError("Corrupt thresholds format")
                    self.tau_low = float(data["tau_low"])
                    self.tau_high = float(data["tau_high"])
                    self.version = str(data.get("version", "uncalibrated"))
                    self.provenance = data.get("provenance", {})
            except Exception:
                self.version = "uncalibrated"
        else:
            self.version = "uncalibrated"

    def save_thresholds(self, tau_low: float, tau_high: float, version: str, provenance: dict = None):
        """Save thresholds to disk."""
        self.tau_low = tau_low
        self.tau_high = tau_high
        self.version = version
        self.provenance = provenance or {}
        if "calibrated_at" not in self.provenance:
            import time
            self.provenance["calibrated_at"] = time.time()
        
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        with open(self.filepath, 'w') as f:
            data = {
                "tau_low": self.tau_low,
                "tau_high": self.tau_high,
                "version": self.version
            }
            if self.provenance:
                data["provenance"] = self.provenance
            json.dump(data, f, indent=2)

    def calibrate(self, n: int, p_err_honest: float, alpha: float = 1e-4,
                  version: str = "analytical_v92"):
        """Calibrate thresholds analytically from a MEASURED honest baseline."""
        import time
        tau_low = derive_thresholds(n, p_err_honest, alpha)
        tau_high = derive_thresholds(n, p_err_honest, alpha / 100.0)
        if tau_high <= tau_low:
            tau_high = min(1.0, tau_low + 1.0 / max(n, 1))
        self.save_thresholds(tau_low, tau_high, version,
                             provenance={"n": n, "e_honest": p_err_honest,
                                         "alpha": alpha, "derivation": "binom.ppf",
                                         "calibrated_at": time.time()})
        reset_verification_counter()
        return tau_low, tau_high

    def get_thresholds(self) -> Tuple[float, float]:
        return self.tau_low, self.tau_high
        
    def get_version(self) -> str:
        return self.version

    def evaluate(self, D: float) -> str:
        if D <= self.tau_low:
            return "ACCEPT"
        elif D <= self.tau_high:
            return "QUARANTINE"
        else:
            return "REJECT"

    def evaluate_transferable(self, m_hat_primary: float, m_hat_secondary: float):
        """
        Dual-threshold transferability rule.
        Returns ACCEPT only when primary is below tau_low AND secondary is below tau_high.
        Records disagreement between the two verifiers as a distinct finding.
        """
        primary_accept = m_hat_primary <= self.tau_low
        secondary_accept = m_hat_secondary <= self.tau_high
        
        if primary_accept and secondary_accept:
            decision = "ACCEPT"
        else:
            decision = "REJECT"
            
        findings = []
        if primary_accept != secondary_accept:
            from src.detection.findings import Finding, Severity
            findings.append(Finding(
                detector_name="TransferabilityDetector",
                severity=Severity.REJECT,
                description=(
                    f"Transferability violation: primary verifier accepted={primary_accept} (m={m_hat_primary:.4f}), "
                    f"secondary verifier accepted={secondary_accept} (m={m_hat_secondary:.4f})."
                ),
                metrics={
                    "m_hat_primary": m_hat_primary,
                    "m_hat_secondary": m_hat_secondary,
                    "tau_low": self.tau_low,
                    "tau_high": self.tau_high,
                    "disagreement": True
                }
            ))
            
        self.last_transferability_findings = findings
        return TransferableResult(decision, findings)

# Global policy instance
global_policy = DecisionPolicy()

import threading

_verifications_since_recal = 0
_recalibration_lock = threading.Lock()

def reset_verification_counter():
    global _verifications_since_recal
    _verifications_since_recal = 0

def increment_verification_counter() -> bool:
    global _verifications_since_recal
    _verifications_since_recal += 1
    recal_every_n = int(os.environ.get("QS_RECAL_EVERY_N", "50"))
    if _verifications_since_recal >= recal_every_n:
        _verifications_since_recal = 0
        return True
    return False

def perform_recalibration() -> bool:
    """
    Perform periodic/event-driven analytical recalibration from an empirical honest baseline.
    Protected by _recalibration_lock against overlapping executions.
    Never crashes caller or drops existing thresholds on error.
    """
    if not _recalibration_lock.acquire(blocking=False):
        print("[Recalibration] Skipping: recalibration already in progress.", flush=True)
        return False
    try:
        from src.calibration.measure_honest import measure_honest_baseline
        configured_dist = float(os.environ.get("QS_CHANNEL_DISTURBANCE", "0.02"))
        baseline = measure_honest_baseline(disturbance=configured_dist, trials=10, L=90)
        global_policy.calibrate(n=int(round(baseline["n_mean"])), p_err_honest=baseline["e_honest"])
        print(f"[Recalibration] Recalibration complete: version={global_policy.get_version()}, thresholds={global_policy.get_thresholds()}", flush=True)
        return True
    except Exception as e:
        print(f"[Recalibration] Error during recalibration: {e}", flush=True)
        return False
    finally:
        _recalibration_lock.release()

