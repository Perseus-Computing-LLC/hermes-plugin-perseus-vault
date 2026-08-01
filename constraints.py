"""Capability-specific, hash-covered Authorized Action constraints (#10).

Raw tool arguments remain in the Hermes process. Durable evidence contains only
this canonical constraint digest and versioned metadata.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA = "perseus-authorized-action/resource-constraints/v1"
REDACTED_FIELDS = frozenset({"raw_arguments", "credentials", "prompt", "card_number", "token", "secret"})


@dataclass(frozen=True)
class ResourceConstraints:
    resource_ref: str | None = None
    merchant_ref: str | None = None
    amount_minor: int | None = None
    currency: str | None = None
    expires_at: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "ResourceConstraints":
        value = value or {}
        allowed = {"resource_ref", "merchant_ref", "amount_minor", "currency", "expires_at"}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown resource constraint fields: {sorted(unknown)}")
        for field in REDACTED_FIELDS:
            if field in value:
                raise ValueError(f"raw secret field is not allowed: {field}")
        amount = value.get("amount_minor")
        if amount is not None and (isinstance(amount, bool) or not isinstance(amount, int) or amount < 0):
            raise ValueError("amount_minor must be a non-negative integer")
        currency_value = value.get("currency")
        if currency_value is not None:
            if not isinstance(currency_value, str) or len(currency_value) != 3 or not currency_value.isalpha():
                raise ValueError("currency must be a three-letter code")
            currency_value = currency_value.upper()
        expiry = value.get("expires_at")
        if expiry is not None:
            _parse_expiry(expiry)
        return cls(
            resource_ref=_text(value.get("resource_ref"), "resource_ref"),
            merchant_ref=_text(value.get("merchant_ref"), "merchant_ref"),
            amount_minor=amount,
            currency=currency_value,
            expires_at=expiry,
        )

    def canonical(self) -> dict[str, Any]:
        return {
            "resource_ref": self.resource_ref,
            "merchant_ref": self.merchant_ref,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "expires_at": self.expires_at,
        }

    def digest(self) -> str:
        encoded = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def validate_for(self, capability: str, *, now: datetime | None = None) -> None:
        required = {
            "git_push": ("resource_ref",),
            "deployment": ("resource_ref",),
            "external_message_send": ("resource_ref",),
            "payment": ("merchant_ref", "amount_minor", "currency", "expires_at"),
        }.get(capability, ())
        missing = [field for field in required if getattr(self, field) is None]
        if missing:
            raise ValueError(f"{capability} requires {', '.join(missing)}")
        if self.expires_at and _parse_expiry(self.expires_at) <= (now or datetime.now(timezone.utc)):
            raise ValueError("resource constraints are expired")

    def permits(self, proposed: "ResourceConstraints", *, now: datetime | None = None) -> bool:
        if self.resource_ref != proposed.resource_ref or self.merchant_ref != proposed.merchant_ref:
            return False
        if self.currency != proposed.currency:
            return False
        if self.amount_minor is not None and (proposed.amount_minor is None or proposed.amount_minor > self.amount_minor):
            return False
        if self.expires_at is not None:
            bound = _parse_expiry(self.expires_at)
            if proposed.expires_at is not None and _parse_expiry(proposed.expires_at) > bound:
                return False
            if bound <= (now or datetime.now(timezone.utc)):
                return False
        return True


def _text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _parse_expiry(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("expires_at must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def constraints_from_tool(tool_name: str, args: Mapping[str, Any], capability: str, scope: str) -> ResourceConstraints:
    """Derive non-secret resource identity from the host-owned call boundary."""
    supplied = args.get("resource_constraints")
    if supplied is not None:
        return ResourceConstraints.from_mapping(supplied)
    if capability == "payment":
        return ResourceConstraints.from_mapping({
            key: args.get(key) for key in ("merchant_ref", "amount_minor", "currency", "expires_at")
        })
    if capability in {"git_push", "deployment", "external_message_send"}:
        resource = args.get("resource_ref") or args.get("destination") or args.get("environment") or scope
        return ResourceConstraints.from_mapping({"resource_ref": resource})
    return ResourceConstraints()


def compare(approved: ResourceConstraints, proposed: ResourceConstraints, *, now: datetime | None = None) -> tuple[bool, str]:
    return (True, "VERIFIED") if approved.permits(proposed, now=now) else (False, "RESOURCE_CONSTRAINT_MISMATCH")


def durable_projection(constraints: ResourceConstraints) -> dict[str, str]:
    return {"resource_constraints_version": SCHEMA, "resource_constraints_hash": constraints.digest()}


def constraint_hash(value: Mapping[str, Any] | None) -> str:
    return ResourceConstraints.from_mapping(value).digest()


__all__ = [
    "REDACTED_FIELDS", "SCHEMA", "ResourceConstraints", "compare", "constraint_hash",
    "constraints_from_tool", "durable_projection",
]
