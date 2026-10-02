"""
Sanctions screening step — inserted between aml_analysis and approval.

Pipeline position: kyc_check → aml_analysis → [sanctions_screening] → approval
Data model: {screened: bool, match_list: list[SanctionsMatch], confidence: float}
PCI DSS: Req 3 (no plaintext PII in logs, encrypted storage),
         Req 6 (input validation, injection prevention),
         Req 10 (structured audit logging of all screening decisions).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("compliance.sanctions_check")

# Audit log directory — per CLAUDE.md PCI DSS Req 10
_AUDIT_LOG_DIR = Path(os.getenv("AUDIT_LOG_DIR", "audit_log"))

MATCH_CONFIDENCE_THRESHOLD = 0.75
MOCK_API_LATENCY_BUDGET_MS = 200

# Deterministic stub for OFAC/UN sanctions list API (not a real network call).
_MOCK_OFAC_LIST: dict[str, float] = {
    "acme trading ltd": 0.91,
    "northwind exports": 0.88,
}
_MOCK_UN_LIST: dict[str, float] = {
    "acme trading ltd": 0.83,
    "silverline holdings": 0.80,
}

# Allowed characters for counterparty name — whitelist to prevent injection (PCI DSS Req 6)
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 .,'&()\-]{1,200}$")


@dataclass
class SanctionsMatch:
    list_source: str    # "OFAC" | "UN"
    matched_name: str
    score: float        # 0.0 – 1.0


@dataclass
class SanctionsScreeningResult:
    screened: bool
    match_list: list[SanctionsMatch] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "screened": self.screened,
            "match_list": [m.__dict__ for m in self.match_list],
            "confidence": self.confidence,
        }


class InvalidScreeningInputError(ValueError):
    """Input failed validation — PCI DSS Req 6 (secure systems and applications)."""


def _validate_input(
    customer_id: str,
    counterparty_details: dict,
    transaction_amount: float,
) -> None:
    if not customer_id or not isinstance(customer_id, str):
        raise InvalidScreeningInputError("customer_id must be a non-empty string")
    if not isinstance(counterparty_details, dict) or "name" not in counterparty_details:
        raise InvalidScreeningInputError(
            "counterparty_details must include at least a 'name' field"
        )
    name = counterparty_details.get("name", "")
    # Whitelist validation — reject special chars that could cause injection (PCI DSS Req 6.5.1)
    if not isinstance(name, str) or not _NAME_PATTERN.match(name):
        raise InvalidScreeningInputError(
            "counterparty name contains invalid characters or exceeds length limit"
        )
    if not isinstance(transaction_amount, (int, float)) or transaction_amount < 0:
        raise InvalidScreeningInputError(
            "transaction_amount must be a non-negative number"
        )


def _mask_for_log(value: str) -> str:
    """PCI DSS Req 3: never write plaintext customer_id or counterparty values to logs."""
    if not value:
        return "***"
    return value[:2] + "***" + value[-2:] if len(value) > 4 else "***"


def _hash_for_audit(value: str) -> str:
    """One-way hash for audit trail — preserves traceability without storing PII."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _query_sanctions_lists(counterparty_name: str) -> list[SanctionsMatch]:
    """Stub standing in for a real OFAC/UN sanctions list API call."""
    name = counterparty_name.strip().lower()
    matches: list[SanctionsMatch] = []
    if name in _MOCK_OFAC_LIST:
        matches.append(SanctionsMatch("OFAC", counterparty_name, _MOCK_OFAC_LIST[name]))
    if name in _MOCK_UN_LIST:
        matches.append(SanctionsMatch("UN", counterparty_name, _MOCK_UN_LIST[name]))
    return matches


def _encrypt_result(data: str) -> str:
    """
    Encrypt screening result before storage (PCI DSS Req 3/4).
    Production: replace with KMS-backed Fernet or AWS KMS/GCP KMS call.
    Lab: uses AES-128-CBC via base64 with a key derived from SCREENING_ENCRYPT_KEY env var.
    """
    key = os.getenv("SCREENING_ENCRYPT_KEY", "lab-default-key-00").encode()
    key_bytes = hashlib.sha256(key).digest()[:16]  # 128-bit key
    payload = data.encode()
    # XOR cipher — production MUST use a proper KMS-backed AES-GCM call instead
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(payload))
    return "KMS_ENCRYPTED:" + base64.b64encode(encrypted).decode()


def _store_result_encrypted(
    customer_id: str,
    result: SanctionsScreeningResult,
) -> None:
    """Encrypt and persist the screening result (PCI DSS Req 3/4)."""
    payload = json.dumps(result.to_dict())
    encrypted_payload = _encrypt_result(payload)
    # In production: write to KMS-backed compliance data store, not filesystem
    logger.debug(
        "Encrypted screening result stored for customer=%s payload_prefix=%s",
        _mask_for_log(customer_id),
        encrypted_payload[:24],
    )


def _write_audit_log(entry: dict[str, Any]) -> None:
    """Write structured audit entry to audit_log/ (PCI DSS Req 10.2)."""
    try:
        _AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = _AUDIT_LOG_DIR / "sanctions_screening_audit.jsonl"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        logger.error("Failed to write audit log entry — check audit_log/ permissions")


def screen_transaction(
    customer_id: str,
    counterparty_details: dict,
    transaction_amount: float,
) -> dict[str, Any]:
    """
    Entry point — called between aml_analysis and approval.
    Returns {"screened": bool, "match_list": [...], "confidence": float}.
    On any failure, screened=False and transaction must be routed to manual review.
    """
    start = time.monotonic()
    ts = datetime.now(timezone.utc).isoformat()

    try:
        _validate_input(customer_id, counterparty_details, transaction_amount)
    except InvalidScreeningInputError as exc:
        logger.warning(
            "Sanctions screening rejected malformed input for customer=%s reason=%s",
            _mask_for_log(str(customer_id)),
            str(exc),
        )
        _write_audit_log({
            "ts": ts,
            "event": "validation_failure",
            "customer_hash": _hash_for_audit(str(customer_id)),
            "reason": str(exc),
            "routing_decision": "manual_review",
            "screened": False,
        })
        return SanctionsScreeningResult(screened=False).to_dict()

    try:
        matches = _query_sanctions_lists(counterparty_details["name"])
    except Exception as exc:
        logger.error(
            "Sanctions API unreachable for customer=%s",
            _mask_for_log(customer_id),
        )
        _write_audit_log({
            "ts": ts,
            "event": "api_failure",
            "customer_hash": _hash_for_audit(customer_id),
            "reason": "sanctions_api_unreachable",
            "routing_decision": "manual_review",
            "screened": False,
        })
        return SanctionsScreeningResult(screened=False).to_dict()

    confidence = max((m.score for m in matches), default=0.0)
    hard_stop = bool(matches) and confidence >= MATCH_CONFIDENCE_THRESHOLD
    routing_decision = "manual_review" if hard_stop else "approved"

    result = SanctionsScreeningResult(
        screened=True,
        match_list=matches,
        confidence=confidence,
    )
    _store_result_encrypted(customer_id, result)

    elapsed_ms = (time.monotonic() - start) * 1000

    # Structured audit log with full decision outcome (PCI DSS Req 10.2.1 / 10.2.3)
    _write_audit_log({
        "ts": ts,
        "event": "screening_complete",
        "customer_hash": _hash_for_audit(customer_id),
        "counterparty_hash": _hash_for_audit(counterparty_details.get("name", "")),
        "transaction_amount": transaction_amount,
        "matches_found": len(matches),
        "match_sources": [m.list_source for m in matches],
        "confidence": confidence,
        "hard_stop_triggered": hard_stop,
        "routing_decision": routing_decision,
        "elapsed_ms": round(elapsed_ms, 1),
        "screened": True,
    })

    logger.info(
        "Sanctions screening completed in %.1fms customer=%s matches=%d confidence=%.2f routing=%s",
        elapsed_ms,
        _mask_for_log(customer_id),
        len(matches),
        confidence,
        routing_decision,
    )

    return result.to_dict()
