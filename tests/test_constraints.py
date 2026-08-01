from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("constraints_under_test", _ROOT / "constraints.py")
assert _SPEC and _SPEC.loader
constraints = importlib.util.module_from_spec(_SPEC)
sys.modules["constraints_under_test"] = constraints
_SPEC.loader.exec_module(constraints)


def test_canonical_digest_is_stable_and_durable_projection_is_hash_only():
    value = {"currency": "usd", "amount_minor": 1800, "merchant_ref": "merchant:a", "expires_at": "2030-01-01T00:00:00Z"}
    parsed = constraints.ResourceConstraints.from_mapping(value)
    assert parsed.canonical()["currency"] == "USD"
    assert parsed.digest() == hashlib.sha256(
        b'{"amount_minor":1800,"currency":"USD","expires_at":"2030-01-01T00:00:00Z","merchant_ref":"merchant:a","resource_ref":null}'
    ).hexdigest()
    projection = constraints.durable_projection(parsed)
    assert set(projection) == {"resource_constraints_version", "resource_constraints_hash"}
    assert "merchant:a" not in str(projection)


def test_capability_specific_requirements_fail_closed():
    for capability, value in (
        ("git_push", {}),
        ("deployment", {}),
        ("external_message_send", {}),
        ("payment", {"merchant_ref": "m", "amount_minor": 100, "currency": "USD"}),
    ):
        try:
            constraints.ResourceConstraints.from_mapping(value).validate_for(capability)
        except ValueError:
            pass
        else:
            raise AssertionError(capability)


def test_resource_retarget_amount_currency_and_expiry_extension_are_rejected():
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    approved = constraints.ResourceConstraints.from_mapping({
        "resource_ref": "github:Org/repo",
        "merchant_ref": "merchant:a",
        "amount_minor": 2000,
        "currency": "USD",
        "expires_at": "2026-08-02T00:00:00Z",
    })
    assert not approved.permits(constraints.ResourceConstraints.from_mapping({"resource_ref": "github:Org/other"}), now=now)
    assert not approved.permits(constraints.ResourceConstraints.from_mapping({
        "resource_ref": "github:Org/repo", "merchant_ref": "merchant:a", "amount_minor": 2001,
        "currency": "USD", "expires_at": "2026-08-02T00:00:00Z",
    }), now=now)
    assert not approved.permits(constraints.ResourceConstraints.from_mapping({
        "resource_ref": "github:Org/repo", "merchant_ref": "merchant:a", "amount_minor": 2000,
        "currency": "CAD", "expires_at": "2026-08-02T00:00:00Z",
    }), now=now)
    assert not approved.permits(constraints.ResourceConstraints.from_mapping({
        "resource_ref": "github:Org/repo", "merchant_ref": "merchant:a", "amount_minor": 2000,
        "currency": "USD", "expires_at": "2026-08-03T00:00:00Z",
    }), now=now)


def test_narrower_execution_is_allowed_and_expired_approval_is_not():
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    approved = constraints.ResourceConstraints.from_mapping({
        "merchant_ref": "merchant:a", "amount_minor": 2000, "currency": "USD", "expires_at": "2026-08-02T00:00:00Z",
    })
    narrower = constraints.ResourceConstraints.from_mapping({
        "merchant_ref": "merchant:a", "amount_minor": 1500, "currency": "USD", "expires_at": "2026-08-01T12:00:00Z",
    })
    assert approved.permits(narrower, now=now)
    expired = constraints.ResourceConstraints.from_mapping({
        "merchant_ref": "merchant:a", "amount_minor": 2000, "currency": "USD", "expires_at": "2026-07-31T00:00:00Z",
    })
    assert not expired.permits(narrower, now=now)


def test_raw_secret_fields_are_rejected():
    try:
        constraints.ResourceConstraints.from_mapping({"resource_ref": "repo", "token": "secret"})
    except ValueError as exc:
        assert "token" in str(exc)
    else:
        raise AssertionError("secret field accepted")


def test_constraints_from_tool_derives_host_owned_resource():
    value = constraints.constraints_from_tool(
        "terminal", {"command": "git push", "resource_ref": "github:Org/repo"}, "git_push", "github:Org/fallback"
    )
    assert value.resource_ref == "github:Org/repo"
    payment = constraints.constraints_from_tool(
        "payment", {"merchant_ref": "m", "amount_minor": 100, "currency": "USD", "expires_at": "2030-01-01T00:00:00Z"}, "payment", "scope"
    )
    assert payment.amount_minor == 100
    assert payment.currency == "USD"


def test_compare_returns_structured_rejection_reason():
    a = constraints.ResourceConstraints.from_mapping({"resource_ref": "a"})
    b = constraints.ResourceConstraints.from_mapping({"resource_ref": "b"})
    assert constraints.compare(a, b)[0] is False
    assert constraints.compare(a, b)[1] == "RESOURCE_CONSTRAINT_MISMATCH"


def test_constraints_module_is_small_and_public_contract_is_explicit():
    assert constraints.SCHEMA.endswith("/v1")
    assert set(constraints.__all__) == {
        "REDACTED_FIELDS", "SCHEMA", "ResourceConstraints", "compare", "constraint_hash",
        "constraints_from_tool", "durable_projection",
    }
