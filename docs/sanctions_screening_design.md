# Sanctions Screening — Insertion Point & Design

**Grounded in:** `banking-api` MCP `get_compliance_pipeline` response (queried live, 2026-10-02)

## 1. Pipeline Position

**MCP response from `get_compliance_pipeline`:**

```json
[
  {"step": 1, "name": "kyc_check",    "description": "Verify customer identity"},
  {"step": 2, "name": "aml_analysis", "description": "Anti-money laundering screening"},
  {"step": 3, "name": "approval",     "description": "Final compliance approval"}
]
```

**Insertion point:** between `aml_analysis` (step 2) and `approval` (step 3).

Updated pipeline: `kyc_check → aml_analysis → [NEW: sanctions_screening] → approval`

**Rationale:** Sanctions screening must occur after AML analysis has already flagged the risk profile of a transaction, but before the compliance approval gate. Running it after AML ensures we have AML context available for combined-risk decisions; running it before approval ensures no sanctioned entity can slip through to the final pass/fail verdict. Inserting it earlier (before AML) would produce false escalations on incomplete data; inserting it after approval would defeat the compliance gate.

## 2. Data Inputs Required

| Field | Type | Source | Notes |
|---|---|---|---|
| `customer_id` | `str` | Banking-api MCP / transaction payload | Used to look up the originating customer record; must not be logged in plaintext (PCI DSS Req 3) |
| `counterparty_details` | `dict` | Transaction payload | `name` (str), `country` (str, ISO-3166), `account_id` (str, optional) — primary match target against OFAC/UN lists |
| `transaction_amount` | `float` | Transaction payload | Used for risk-weighting the confidence score; not used in name-match logic |

## 3. Output Schema

```json
{
  "screened": true,
  "match_list": [
    {
      "list_source": "OFAC_SDN",
      "matched_name": "ACME TRADING LLC",
      "score": 0.92
    }
  ],
  "confidence": 0.92
}
```

| Field | Type | Description |
|-------|------|-------------|
| `screened` | `bool` | `true` if the screening step executed successfully; `false` on API failure (never silently pass) |
| `match_list` | `list[dict]` | Zero or more matches, each with `list_source`, `matched_name`, `score` (0–1) |
| `confidence` | `float` (0–1) | Max score across all matches; `0.0` if `match_list` is empty |

## 4. Integration Contract with the AML Module

- **Input from AML step:** the `aml_result` dict (`status`, `risk_score`) is passed through to the approval step unchanged; sanctions screening runs as a parallel concern, not a downstream calculation.
- **Output to Approval step:** any non-empty `match_list` with `confidence >= 0.75` is a **hard stop** — the transaction is routed to manual compliance review and cannot proceed to automatic approval.
- **Failure mode:** if the sanctions list API is unreachable, `screened` must be `false` and the transaction routed to manual review. Silent pass-through on API failure is explicitly forbidden.
- **No PII in logs:** `customer_id` and `counterparty_details` values must never appear in log lines; use masked references only (PCI DSS Req 3).

## 5. Open Questions / Risks

| # | Question | Risk | Mitigation |
|---|----------|------|------------|
| 1 | False-positive rate on fuzzy name matching | High — common names may match benign parties | Threshold `>= 0.75` for hard-stop; 0.50–0.74 flagged for soft review |
| 2 | OFAC/UN list refresh cadence | Stale list = missed new designations | Lists refreshed daily; `screened = false` if list age > 24 h |
| 3 | Name transliteration / romanisation | "Mohammed" vs "Muhammad" may miss or double-match | Normalise to ASCII, apply Levenshtein distance before scoring |
| 4 | Performance SLA | Screening must not add >200 ms to the pipeline | Stub returns deterministically; production must enforce timeout + circuit breaker |
