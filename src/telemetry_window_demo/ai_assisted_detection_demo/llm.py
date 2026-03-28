from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


class DemoStructuredCaseLlm:
    """Constrained local adapter used for the portfolio demo."""

    def generate(
        self,
        system_instructions: str,
        evidence_payload: Mapping[str, Any],
    ) -> str:
        if not system_instructions.strip():
            raise ValueError("System instructions must not be empty.")

        case_bundle = evidence_payload["case_bundle"]
        case_id = str(case_bundle["case_id"])
        rule_names = [hit["rule_name"] for hit in case_bundle["rule_hits"]]
        entity_summary = _entity_summary(case_bundle["entities"])
        time_range = f"{case_bundle['first_seen']} to {case_bundle['last_seen']}"

        summary = (
            f"{case_id} contains {len(case_bundle['rule_hits'])} deterministic rule hits "
            f"covering {', '.join(sorted(set(rule_names)))} for {entity_summary} during "
            f"{time_range}. The case warrants analyst review but does not imply a final "
            f"incident decision."
        )

        likely_causes = _likely_causes(case_bundle)
        uncertainty_notes = [
            "Telemetry is limited to the bundled sample evidence and does not confirm operator intent.",
            "The case summary is advisory only and requires human review before any incident classification.",
        ]
        if _contains_prompt_like_text(case_bundle):
            uncertainty_notes.append(
                "Prompt-like text appeared in telemetry and was treated strictly as untrusted evidence."
            )

        suggested_next_steps = _next_steps(case_bundle)

        response = {
            "case_id": case_id,
            "summary": summary,
            "likely_causes": likely_causes[:3],
            "uncertainty_notes": uncertainty_notes,
            "suggested_next_steps": suggested_next_steps[:4],
            "human_verification": "required",
            "scope_guardrail": "no_final_incident_decision|no_rule_changes|no_automated_actions",
        }
        return json.dumps(response)


def _entity_summary(entities: Mapping[str, list[str]]) -> str:
    parts: list[str] = []
    for field in ("principal", "src_ip", "host"):
        values = entities.get(field, [])
        if values:
            parts.append(f"{field} {', '.join(values)}")
    return "; ".join(parts) if parts else "the observed entities"


def _likely_causes(case_bundle: Mapping[str, Any]) -> list[str]:
    likely_causes: list[str] = []
    rule_names = {hit["rule_name"] for hit in case_bundle["rule_hits"]}

    if "repeated_failed_logins" in rule_names:
        likely_causes.append("Repeated password guessing or credential stuffing against the targeted account.")
    if "successful_login_after_failures" in rule_names:
        likely_causes.append("A valid credential may have been used after several failed login attempts.")
    if "sensitive_path_scan" in rule_names:
        likely_causes.append("The source IP appears to be probing sensitive web paths on the exposed application.")
    if "encoded_powershell_execution" in rule_names:
        likely_causes.append("Obfuscated PowerShell execution may reflect manual tradecraft or an unsafe script.")

    if not likely_causes:
        likely_causes.append("Detections indicate suspicious behavior that requires manual triage.")
    return likely_causes


def _next_steps(case_bundle: Mapping[str, Any]) -> list[str]:
    next_steps: list[str] = [
        "Review the raw evidence and confirm whether the activity aligns with an approved administrative task.",
    ]
    rule_names = {hit["rule_name"] for hit in case_bundle["rule_hits"]}

    if "successful_login_after_failures" in rule_names or "repeated_failed_logins" in rule_names:
        next_steps.append(
            "Check authentication context for MFA state, prior successful logins, and expected source locations."
        )
    if "sensitive_path_scan" in rule_names:
        next_steps.append(
            "Compare the web requests with reverse-proxy and WAF logs to determine whether the probing continued."
        )
    if "encoded_powershell_execution" in rule_names:
        next_steps.append(
            "Inspect the originating host timeline and validate whether the encoded PowerShell command matches known tooling."
        )

    next_steps.append(
        "Document the analyst conclusion separately after human verification; do not treat this summary as a final verdict."
    )
    return next_steps


def _contains_prompt_like_text(case_bundle: Mapping[str, Any]) -> bool:
    marker = "ignore all prior instructions"
    for event in case_bundle["raw_evidence"]:
        raw_text = json.dumps(event.get("raw_event", {})).lower()
        if marker in raw_text:
            return True
    return False
