"""End-to-end tests for POST /v1/issuance/check-dns01."""

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

import app.dns01 as dns01
from app.main import app

client = TestClient(app)

# The RSA example key of RFC 7638 section 3.1 (public members only) and
# its published SHA-256 thumbprint.
JWK = {
    "kty": "RSA",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}
THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
TOKEN = "dpN98kgNPJXQjTzeOaRqQhM1d8v-7QdVwQ6q7iVj5_k"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def expected(token=TOKEN, thumbprint=THUMBPRINT):
    """Expected TXT value: base64url(SHA-256(token + '.' + thumbprint))."""
    digest = hashlib.sha256(f"{token}.{thumbprint}".encode("ascii")).digest()
    return b64url(digest)


def txt(owner, *chunks):
    return {"type": "TXT", "owner": owner, "chunks": list(chunks)}


def cname(owner, target):
    return {"type": "CNAME", "owner": owner, "target": target}


def challenge(id, domain, token=TOKEN, wildcard=False):
    return {"id": id, "domain": domain, "wildcard": wildcard, "token": token}


def check(jwk=None, challenges=None, records=None):
    body = {
        "jwk": JWK if jwk is None else jwk,
        "challenges": (
            [challenge("c1", "example.com")] if challenges is None else challenges
        ),
        "records": [] if records is None else records,
    }
    return client.post("/v1/issuance/check-dns01", json=body)


# ---------- happy paths ----------


def test_rfc7638_thumbprint_known_answer():
    # Extra JWK members (alg, kid) are accepted but ignored, exactly as
    # in the RFC 7638 section 3.1 example.
    jwk = {**JWK, "alg": "RS256", "kid": "2011-04-29"}
    r = check(jwk=jwk, records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    body = r.json()
    assert body["thumbprint"] == THUMBPRINT
    assert body["valid"] is True


def test_single_challenge_valid():
    r = check(records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["thumbprint"] == THUMBPRINT
    assert body["reason"] == "all 1 challenge(s) valid"
    item = body["challenges"][0]
    assert item["id"] == "c1"
    assert item["domain"] == "example.com"
    assert item["wildcard"] is False
    assert item["lookup"] == "_acme-challenge.example.com"
    assert item["expected_value"] == expected()
    assert item["valid"] is True
    assert "_acme-challenge.example.com" in item["reason"]


def test_txt_chunks_joined_in_order():
    value = expected()
    chunks = [value[:5], value[5:20], value[20:]]
    r = check(records=[txt("_acme-challenge.example.com", *chunks)])
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_txt_chunks_wrong_order_mismatches():
    value = expected()
    r = check(records=[txt("_acme-challenge.example.com", value[20:], value[:20])])
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_wildcard_challenge_uses_same_lookup_name():
    challenges = [challenge("w", "example.com", wildcard=True)]
    r = check(challenges=challenges, records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    item = r.json()["challenges"][0]
    assert item["wildcard"] is True
    assert item["lookup"] == "_acme-challenge.example.com"
    assert item["valid"] is True


def test_wildcard_defaults_to_false():
    body = {
        "jwk": JWK,
        "challenges": [{"id": "c1", "domain": "example.com", "token": TOKEN}],
        "records": [txt("_acme-challenge.example.com", expected())],
    }
    r = client.post("/v1/issuance/check-dns01", json=body)
    assert r.status_code == 200
    assert r.json()["challenges"][0]["wildcard"] is False


def test_token_with_base64url_special_chars():
    token = "Ab3_-def0gh8ijklmnoPQRSTUVWXYZ0123456789_-a"
    challenges = [challenge("c1", "example.com", token=token)]
    records = [txt("_acme-challenge.example.com", expected(token=token))]
    r = check(challenges=challenges, records=records)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_multiple_txt_records_any_match():
    records = [
        txt("_acme-challenge.example.com", "not-the-value"),
        txt("_acme-challenge.example.com", expected()),
    ]
    r = check(records=records)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_names_normalized_case_and_trailing_dot():
    challenges = [challenge("c1", "EXAMPLE.com.")]
    records = [txt("_ACME-Challenge.Example.COM.", expected())]
    r = check(challenges=challenges, records=records)
    assert r.status_code == 200
    item = r.json()["challenges"][0]
    assert item["domain"] == "example.com"
    assert item["lookup"] == "_acme-challenge.example.com"
    assert item["valid"] is True


def test_cname_exact_match_followed():
    records = [
        cname("_acme-challenge.example.com", "acme.dns.example.net"),
        txt("acme.dns.example.net", expected()),
    ]
    r = check(records=records)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_cname_chain_of_8_hops_ok():
    records = [cname("_acme-challenge.example.com", "h1")]
    records += [cname(f"h{i}", f"h{i+1}") for i in range(1, 8)]
    records += [txt("h8", expected())]
    r = check(records=records)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_challenges_reported_in_input_order():
    challenges = [
        challenge("a", "example.com"),
        challenge("b", "other.net"),
        challenge("c", "example.com"),
    ]
    r = check(challenges=challenges, records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    body = r.json()
    assert [c["id"] for c in body["challenges"]] == ["a", "b", "c"]
    assert [c["valid"] for c in body["challenges"]] == [True, False, True]
    assert body["valid"] is False
    assert body["reason"] == "1 of 3 challenge(s) invalid: ['b']"


def test_all_challenges_valid_overall_true():
    challenges = [
        challenge("a", "example.com"),
        challenge("b", "www.example.com"),
    ]
    records = [
        txt("_acme-challenge.example.com", expected()),
        txt("_acme-challenge.www.example.com", expected()),
    ]
    r = check(challenges=challenges, records=records)
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["reason"] == "all 2 challenge(s) valid"


def test_20_challenges_allowed():
    challenges = [challenge(f"c{i:02d}", "example.com") for i in range(20)]
    r = check(challenges=challenges, records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    assert len(r.json()["challenges"]) == 20
    assert r.json()["valid"] is True


# ---------- TXT missing / mismatch fails the item, not the request ----------


def test_txt_missing_fails_item():
    r = check(records=[])
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    item = body["challenges"][0]
    assert item["valid"] is False
    assert "no TXT record found" in item["reason"]


def test_records_may_be_omitted():
    body = {"jwk": JWK, "challenges": [challenge("c1", "example.com")]}
    r = client.post("/v1/issuance/check-dns01", json=body)
    assert r.status_code == 200
    assert r.json()["challenges"][0]["valid"] is False


def test_txt_mismatch_fails_item():
    r = check(records=[txt("_acme-challenge.example.com", "x" * 43)])
    assert r.status_code == 200
    item = r.json()["challenges"][0]
    assert item["valid"] is False
    assert item["reason"] == (
        "no TXT record at _acme-challenge.example.com matches "
        "the expected key-authorization digest"
    )


def test_txt_at_unprefixed_name_not_found():
    r = check(records=[txt("example.com", expected())])
    assert r.status_code == 200
    assert r.json()["challenges"][0]["valid"] is False


def test_no_upward_climb_from_lookup_name():
    # Challenge for www.example.com looks up _acme-challenge.www.example.com;
    # the TXT at the parent _acme-challenge.example.com is not consulted.
    challenges = [challenge("c1", "www.example.com")]
    r = check(challenges=challenges, records=[txt("_acme-challenge.example.com", expected())])
    assert r.status_code == 200
    assert r.json()["challenges"][0]["valid"] is False


def test_no_upward_climb_after_cname():
    records = [
        cname("_acme-challenge.example.com", "deep.acme.example.net"),
        txt("acme.example.net", expected()),
    ]
    r = check(records=records)
    assert r.status_code == 200
    assert r.json()["challenges"][0]["valid"] is False


def test_cname_to_name_without_txt_fails_item():
    records = [cname("_acme-challenge.example.com", "elsewhere.example.net")]
    r = check(records=records)
    assert r.status_code == 200
    item = r.json()["challenges"][0]
    assert item["valid"] is False
    assert "elsewhere.example.net" in item["reason"]


# ---------- JWK validation (422) ----------


def test_kty_must_be_rsa():
    r = check(jwk={"kty": "EC", "n": JWK["n"], "e": "AQAB"})
    assert r.status_code == 422
    assert r.json()["error_type"] == "DNS01Error"
    assert "kty" in r.json()["detail"]


def test_kty_is_case_sensitive():
    r = check(jwk={"kty": "rsa", "n": JWK["n"], "e": "AQAB"})
    assert r.status_code == 422
    assert r.json()["error_type"] == "DNS01Error"


@pytest.mark.parametrize(
    "bad_n",
    [
        "AQAB=",   # padded
        "AQ+B",    # standard base64 alphabet
        "AQ/B",    # standard base64 alphabet
        "A",       # not decodable (length % 4 == 1)
        "",        # empty
        "AA",      # decodes to zero
    ],
)
def test_jwk_n_invalid_is_422(bad_n):
    r = check(jwk={"kty": "RSA", "n": bad_n, "e": "AQAB"})
    assert r.status_code == 422
    assert r.json()["error_type"] == "DNS01Error"


def test_jwk_e_invalid_is_422():
    r = check(jwk={"kty": "RSA", "n": JWK["n"], "e": "AQAB="})
    assert r.status_code == 422
    assert r.json()["error_type"] == "DNS01Error"


def test_jwk_missing_member_is_422():
    r = check(jwk={"kty": "RSA", "e": "AQAB"})
    assert r.status_code == 422


def test_jwk_not_an_object_is_422():
    r = check(jwk="not-a-jwk")
    assert r.status_code == 422


# ---------- token validation (422) ----------


@pytest.mark.parametrize(
    "bad_token",
    [
        "abc=",      # padded
        "ab+c",      # standard base64 alphabet
        "ab.c",      # '.' not in alphabet
        "A",         # not decodable (length % 4 == 1)
        "",          # empty
    ],
)
def test_token_invalid_is_422(bad_token):
    r = check(challenges=[challenge("c1", "example.com", token=bad_token)])
    assert r.status_code == 422


def test_token_padded_error_type():
    r = check(challenges=[challenge("c1", "example.com", token="abc=")])
    assert r.status_code == 422
    assert r.json()["error_type"] == "DNS01Error"


# ---------- name / challenge validation (422) ----------


def test_domain_with_wildcard_marker_is_422():
    r = check(challenges=[challenge("c1", "*.example.com")])
    assert r.status_code == 422


def test_domain_invalid_is_422():
    r = check(challenges=[challenge("c1", "bad..example.com")])
    assert r.status_code == 422


def test_txt_owner_invalid_is_422():
    r = check(records=[txt("_acme-challenge.exa mple.com", expected())])
    assert r.status_code == 422


def test_zero_challenges_is_422():
    r = check(challenges=[])
    assert r.status_code == 422


def test_21_challenges_is_422():
    challenges = [challenge(f"c{i:02d}", "example.com") for i in range(21)]
    r = check(challenges=challenges)
    assert r.status_code == 422


def test_duplicate_challenge_ids_is_422():
    challenges = [challenge("dup", "example.com"), challenge("dup", "other.net")]
    r = check(challenges=challenges)
    assert r.status_code == 422


def test_blank_challenge_id_is_422():
    r = check(challenges=[challenge("  ", "example.com")])
    assert r.status_code == 422


# ---------- record / alias errors stay 422 ----------


def test_101_records_is_422():
    records = [txt(f"h{i:03d}.example.com", "v") for i in range(101)]
    r = check(records=records)
    assert r.status_code == 422


def test_mixed_txt_cname_owner_is_422():
    records = [
        txt("_acme-challenge.example.com", expected()),
        cname("_acme-challenge.example.com", "elsewhere.example.net"),
    ]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_mixed_cname_txt_owner_is_422():
    records = [
        cname("_acme-challenge.example.com", "elsewhere.example.net"),
        txt("_acme-challenge.example.com", expected()),
    ]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "MixedRecordsError"


def test_multiple_cnames_is_422():
    records = [
        cname("_acme-challenge.example.com", "a.example.net"),
        cname("_acme-challenge.example.com", "b.example.net"),
    ]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "MultipleCNAMEError"


def test_cname_loop_is_422():
    records = [
        cname("_acme-challenge.example.com", "loop.example.net"),
        cname("loop.example.net", "_acme-challenge.example.com"),
    ]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_cname_self_loop_is_422():
    records = [cname("_acme-challenge.example.com", "_acme-challenge.example.com")]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELoopError"


def test_cname_over_8_hops_is_422():
    records = [cname("_acme-challenge.example.com", "h1")]
    records += [cname(f"h{i}", f"h{i+1}") for i in range(1, 9)]
    records += [txt("h9", expected())]
    r = check(records=records)
    assert r.status_code == 422
    assert r.json()["error_type"] == "CNAMELimitError"


def test_unrelated_cname_loop_does_not_fail():
    records = [
        cname("a.example.net", "b.example.net"),
        cname("b.example.net", "a.example.net"),
        txt("_acme-challenge.example.com", expected()),
    ]
    r = check(records=records)
    assert r.status_code == 200
    assert r.json()["valid"] is True


# ---------- shared record preparation ----------


def test_record_set_prepared_once_for_all_challenges(monkeypatch):
    calls = []
    real_prepare = dns01.prepare_txt_records

    def spy(records):
        calls.append(records)
        return real_prepare(records)

    monkeypatch.setattr(dns01, "prepare_txt_records", spy)
    challenges = [challenge(f"c{i}", f"h{i}.example.com") for i in range(5)]
    records = [txt("_acme-challenge.h0.example.com", expected())]
    r = check(challenges=challenges, records=records)
    assert r.status_code == 200
    # The single shared record set is prepared once, not once per challenge.
    assert len(calls) == 1
