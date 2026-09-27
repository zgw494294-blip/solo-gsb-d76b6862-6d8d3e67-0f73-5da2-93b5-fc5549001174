"""Offline ACME DNS-01 challenge verification for POST /v1/issuance/check-dns01.

Verifies ACME ``dns-01`` challenges (RFC 8555 section 8.4) against a
caller-supplied, offline DNS view of TXT and CNAME records — no real DNS
queries are performed:

* the account key is an RSA JWK (``kty``/``n``/``e``); its RFC 7638
  thumbprint is the SHA-256 of the canonical required-member JSON
  (``e``/``kty``/``n`` in lexicographic order, no whitespace), encoded
  as unpadded base64url; any other JWK members are ignored;
* each challenge carries a unique caller id, a base ``domain`` (never a
  ``*.`` wildcard name), a ``wildcard`` flag and an unpadded base64url
  ``token``; wildcard and plain challenges alike are looked up at
  ``_acme-challenge.<domain>``;
* the expected TXT value is ``base64url(SHA-256(token + "." +
  thumbprint))`` (no padding) — the digest of the ACME key
  authorization;
* CNAME records are followed by exact owner match only — the search
  never climbs to parent names — with at most 8 hops and loop detection
  across the whole chain;
* a TXT record's ``chunks`` are ordered character-strings, concatenated
  per record before comparison; any TXT record at the resolved name
  whose joined value equals the expected digest satisfies the challenge.

A missing TXT record or a value mismatch fails only that challenge;
illegal JWKs/tokens/names, owners mixing TXT and CNAME records, multiple
CNAMEs at one owner, CNAME loops and chains over 8 hops are 422-grade
failures for the whole request.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional

from .engine import (
    CAAError,
    CNAMELimitError,
    CNAMELoopError,
    InvalidNameError,
    MixedRecordsError,
    MultipleCNAMEError,
    normalize_name,
)

MAX_CNAME_HOPS = 8
MAX_RECORDS = 100
MAX_CHALLENGES = 20

_B64URL_CHARS = re.compile(r"[A-Za-z0-9_-]+")


class DNS01Error(CAAError):
    """JWK/token/DNS-01 input failure; maps to HTTP 422."""


@dataclass(frozen=True)
class PreparedTXTRecords:
    """Immutable index of a validated TXT/CNAME record set.

    ``txt_map`` maps each owner name to its joined TXT values in input
    order; ``cname_map`` maps each owner name to its normalized CNAME
    target. Both mappings and their contents share no mutable state with
    the original record dicts.
    """

    txt_map: Mapping[str, tuple[str, ...]]
    cname_map: Mapping[str, str]


def normalize_owner_name(raw: str, *, field: str = "owner") -> str:
    """Normalize a DNS owner/target name, allowing underscore labels.

    Same rules as :func:`app.engine.normalize_name` — case-insensitive,
    a single trailing dot stripped, empty/root names, empty labels,
    overlong labels/names and wildcards rejected — except that labels
    may also contain ``_`` (as in ``_acme-challenge.example.com``),
    which certificate hostnames may not use but DNS owner names do.
    """
    if not isinstance(raw, str):
        raise InvalidNameError(f"{field} must be a string")
    name = raw.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise InvalidNameError(f"{field} must not be empty or root")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise InvalidNameError(f"invalid {field} {raw!r}: empty label")
        if label.startswith("*"):
            raise InvalidNameError(f"invalid {field} {raw!r}: wildcard not allowed")
        if len(label) > 63:
            raise InvalidNameError(
                f"invalid {field} {raw!r}: label longer than 63 characters"
            )
        if label.startswith("-") or label.endswith("-"):
            raise InvalidNameError(
                f"invalid {field} {raw!r}: label must not start/end with '-'"
            )
        if not all(c.isascii() and (c.isalnum() or c in "-_") for c in label):
            raise InvalidNameError(
                f"invalid {field} {raw!r}: illegal character in label"
            )
    if len(name) > 253:
        raise InvalidNameError(f"invalid {field} {raw!r}: name too long")
    return name


def _b64url_decode(value: str, *, field: str) -> bytes:
    """Decode an unpadded base64url string or raise :class:`DNS01Error`."""
    if not isinstance(value, str) or not value:
        raise DNS01Error(f"{field} must be a non-empty unpadded base64url string")
    if not _B64URL_CHARS.fullmatch(value):
        raise DNS01Error(
            f"{field} must use the unpadded base64url alphabet "
            "(A-Z a-z 0-9 - _)"
        )
    if len(value) % 4 == 1:
        raise DNS01Error(f"{field} is not decodable base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - guarded
        raise DNS01Error(f"{field} is not decodable base64url: {exc}") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint of an RSA JWK, unpadded base64url.

    Only the required members ``e``/``kty``/``n`` take part, serialized
    in lexicographic order with no whitespace and with their values used
    exactly as supplied. ``kty`` must be ``"RSA"`` and ``n``/``e`` must
    be unpadded base64url encodings of positive integers.
    """
    kty = jwk.get("kty")
    if kty != "RSA":
        raise DNS01Error(f"jwk.kty must be 'RSA', got {kty!r}")
    n = jwk.get("n")
    e = jwk.get("e")
    if int.from_bytes(_b64url_decode(n, field="jwk.n"), "big") == 0:
        raise DNS01Error("jwk.n must decode to a positive integer")
    if int.from_bytes(_b64url_decode(e, field="jwk.e"), "big") == 0:
        raise DNS01Error("jwk.e must decode to a positive integer")
    members = json.dumps(
        {"e": e, "kty": kty, "n": n},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )
    return _b64url_encode(hashlib.sha256(members.encode("utf-8")).digest())


def validate_token(token: str) -> str:
    """Return an ACME token unchanged, or raise :class:`DNS01Error`."""
    _b64url_decode(token, field="token")
    return token


def expected_txt_value(token: str, thumbprint: str) -> str:
    """Expected TXT value: unpadded base64url of SHA-256(token + "." + thumbprint)."""
    key_authorization = f"{token}.{thumbprint}".encode("ascii")
    return _b64url_encode(hashlib.sha256(key_authorization).digest())


def prepare_txt_records(records: list[dict]) -> PreparedTXTRecords:
    """Validate raw TXT/CNAME record dicts into an immutable index.

    One pass performs every record-set-level check: owner/target name
    normalization (underscore labels allowed), rejection of owners
    mixing TXT and CNAME records and of owners with multiple CNAME
    records. CNAME loops and the hop limit depend on the chain a lookup
    actually follows and are enforced during the lookup itself.
    """
    txt_map: dict[str, list[str]] = {}
    cname_map: dict[str, str] = {}
    for rec in records:
        kind = rec.get("type")
        owner = normalize_owner_name(rec.get("owner", ""), field="owner")
        if kind == "TXT":
            if owner in cname_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and TXT records"
                )
            txt_map.setdefault(owner, []).append("".join(rec["chunks"]))
        elif kind == "CNAME":
            if owner in txt_map:
                raise MixedRecordsError(
                    f"owner {owner!r} mixes CNAME and TXT records"
                )
            if owner in cname_map:
                raise MultipleCNAMEError(
                    f"owner {owner!r} has multiple CNAME records"
                )
            cname_map[owner] = normalize_owner_name(
                rec.get("target", ""), field="target"
            )
        else:  # pragma: no cover - rejected by the schema layer
            raise DNS01Error(f"unknown record type {kind!r}")
    return PreparedTXTRecords(
        txt_map=MappingProxyType(
            {owner: tuple(values) for owner, values in txt_map.items()}
        ),
        cname_map=MappingProxyType(cname_map),
    )


def _resolve_txt(
    name: str, snapshot: PreparedTXTRecords
) -> tuple[Optional[tuple[str, ...]], str]:
    """Follow exact-match CNAMEs from ``name`` to the TXT lookup point.

    Returns the joined TXT values at the terminal name (``None`` when no
    TXT record exists there) and the terminal name itself. The search
    never climbs to parent names; any revisited name is a loop and a
    chain needing more than 8 hops raises — both 422-grade errors.
    """
    current = name
    hops = 0
    seen: set[str] = set()
    path: list[str] = []
    while True:
        if current in seen:
            raise CNAMELoopError(
                f"CNAME loop detected at {current!r} "
                f"(path: {' -> '.join(path + [current])})"
            )
        seen.add(current)
        path.append(current)
        target = snapshot.cname_map.get(current)
        if target is None:
            return snapshot.txt_map.get(current), current
        if hops >= MAX_CNAME_HOPS:
            raise CNAMELimitError(
                f"CNAME chain exceeds {MAX_CNAME_HOPS} hops from {name!r}"
            )
        hops += 1
        current = target


def check_dns01(jwk: dict, challenges: list[dict], records: list[dict]) -> dict:
    """Verify every DNS-01 challenge against one offline TXT/CNAME view.

    The JWK thumbprint and the record set are each prepared once and
    shared by all challenges. Every challenge is looked up at
    ``_acme-challenge.<domain>`` — wildcard challenges use the same base
    name — and passes when some TXT record at the resolved name joins to
    exactly the expected key-authorization digest. Challenges are
    reported in input order; the request is valid only when every
    challenge is valid.
    """
    thumbprint = jwk_thumbprint(jwk)
    for challenge in challenges:
        validate_token(challenge["token"])
    snapshot = prepare_txt_records(records)

    results: list[dict] = []
    for challenge in challenges:
        domain = normalize_name(challenge["domain"], field="domain")
        lookup = f"_acme-challenge.{domain}"
        expected = expected_txt_value(challenge["token"], thumbprint)
        values, terminal = _resolve_txt(lookup, snapshot)
        if values is None:
            valid = False
            reason = f"no TXT record found at {terminal}"
        elif expected in values:
            valid = True
            reason = (
                f"TXT record at {terminal} matches the expected "
                "key-authorization digest"
            )
        else:
            valid = False
            reason = (
                f"no TXT record at {terminal} matches the expected "
                "key-authorization digest"
            )
        results.append(
            {
                "id": challenge["id"],
                "domain": domain,
                "wildcard": bool(challenge.get("wildcard", False)),
                "lookup": lookup,
                "expected_value": expected,
                "valid": valid,
                "reason": reason,
            }
        )

    valid = all(item["valid"] for item in results)
    if valid:
        reason = f"all {len(results)} challenge(s) valid"
    else:
        failed = [item["id"] for item in results if not item["valid"]]
        reason = f"{len(failed)} of {len(results)} challenge(s) invalid: {failed}"
    return {
        "valid": valid,
        "thumbprint": thumbprint,
        "reason": reason,
        "challenges": results,
    }
