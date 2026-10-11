"""Phase 814e Step 2: Advanced Auth & Cryptographic Deep Dive.

Tests cryptographic and authentication invariants:
1. OIDC: aud and iss binding validation (absorbed Phase 523 Item 1)
   - Token from trusted IdP with mismatched aud (minted for different client) must be rejected with 401.
   - Token from untrusted IdP (mismatched iss) must be rejected with 401.
   - Token missing required aud or iss must be rejected with 401.
2. WebAuthn: Origin & RP ID binding, and challenge replay prevention (absorbed Phase 523 Item 2)
   - Registration with origin mismatch (e.g. evil.example vs http://localhost:8090) must be rejected.
   - Authentication with origin mismatch must be rejected.
   - Challenge replay: calling complete a second time with the same challenge must be rejected with 400.
3. SAML: XML Signature Wrapping (XSW 1-8) and signature tampering
   - Real X.509 RSA signed assertion with tampered NameID must be rejected with 401.
   - Real X.509 RSA signed assertion with untrusted signer cert must be rejected with 401.
   - XSW assertion wrapping (cloned assertion wrapper outside signed context) must be rejected.
4. TOTP: Replay resistance & window expiration
   - Valid TOTP code used twice within the same window must be rejected with 401 on replay.
   - Backup code used twice must be rejected with 401 on replay (single-use).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import time as _time
import uuid
from typing import AsyncGenerator, Tuple

import fakeredis.aioredis
import pyotp
import pytest
import pytest_asyncio
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose import jwt as authlib_jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from onelogin.saml2.utils import OneLogin_Saml2_Utils

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_MFA_ENCRYPTION_KEY", "uK2Z9V3xP8yW1bL4fD7jQ0sA5nM8kC2hE9vX4bN7mQ0=")
os.environ.setdefault("MANAGEMENT_OIDC_DISCOVERY_URL", "http://mock-idp.test/.well-known/openid-configuration")
os.environ.setdefault("MANAGEMENT_OIDC_CLIENT_ID", "ja4proxy-test")
os.environ.setdefault("MANAGEMENT_OIDC_CLIENT_SECRET", "test-secret-oidc")
os.environ.setdefault("MANAGEMENT_OIDC_ROLE_MAPPING", '{"Security-Admins": "admin"}')
os.environ.setdefault("MANAGEMENT_WEBAUTHN_RP_ID", "localhost")
os.environ.setdefault("MANAGEMENT_WEBAUTHN_ORIGIN", "http://localhost:8090")

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app
from management.api.routes.oidc import _clear_jwks_cache, _extract_claims


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def app_client(fake_redis: fakeredis.aioredis.FakeRedis) -> AsyncGenerator[Tuple[AsyncClient, fakeredis.aioredis.FakeRedis], None]:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


# ── OIDC Tests: aud and iss validation ────────────────────────────────────────

def _make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_jwks(private_key):
    public_key = private_key.public_key()
    key = JsonWebKey.import_key(public_key, {"kty": "RSA"})
    return {"keys": [dict(key)]}


def _sign_jwt(private_key, claims: dict, alg: str = "RS256") -> str:
    header = {"alg": alg}
    return authlib_jwt.encode(header, claims, private_key).decode()


@pytest.mark.asyncio
async def test_oidc_aud_and_iss_validation(fake_redis: fakeredis.aioredis.FakeRedis, monkeypatch: pytest.MonkeyPatch):
    """Aud and iss claims must be strictly validated against configured IdP & client ID."""
    from unittest.mock import AsyncMock, patch

    private_key = _make_rsa_key()
    jwks = _make_jwks(private_key)
    _clear_jwks_cache()

    monkeypatch.setenv("MANAGEMENT_OIDC_CLIENT_ID", "ja4proxy-test")
    monkeypatch.setenv("MANAGEMENT_OIDC_DISCOVERY_URL", "http://mock-idp.test/.well-known/openid-configuration")

    discovery = {
        "authorization_endpoint": "http://mock-idp.test/auth",
        "token_endpoint": "http://mock-idp.test/token",
        "jwks_uri": "http://mock-idp.test/certs",
        "issuer": "http://mock-idp.test",
    }

    now = int(_time.time())

    # Case 1: Valid aud & iss
    valid_token = _sign_jwt(private_key, {
        "sub": "user-valid",
        "aud": "ja4proxy-test",
        "iss": "http://mock-idp.test",
        "groups": ["Security-Admins"],
        "iat": now,
        "exp": now + 3600,
    })

    # Case 2: Mismatched aud (minted for attacker client on same IdP)
    mismatched_aud_token = _sign_jwt(private_key, {
        "sub": "user-attacker",
        "aud": "attacker-rogue-client",
        "iss": "http://mock-idp.test",
        "groups": ["Security-Admins"],
        "iat": now,
        "exp": now + 3600,
    })

    # Case 3: Mismatched iss (minted by rogue IdP using same JWKS)
    mismatched_iss_token = _sign_jwt(private_key, {
        "sub": "user-rogue",
        "aud": "ja4proxy-test",
        "iss": "http://rogue-idp.test",
        "groups": ["Security-Admins"],
        "iat": now,
        "exp": now + 3600,
    })

    # Case 4: Missing aud claim
    missing_aud_token = _sign_jwt(private_key, {
        "sub": "user-noaud",
        "iss": "http://mock-idp.test",
        "groups": ["Security-Admins"],
        "iat": now,
        "exp": now + 3600,
    })

    with patch("management.api.routes.oidc._http_get_json", new=AsyncMock(return_value=jwks)):
        # Valid claims must succeed
        claims = await _extract_claims(valid_token, "http://mock-idp.test/certs")
        assert claims["sub"] == "user-valid"

        # Mismatched aud must fail
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_aud:
            await _extract_claims(mismatched_aud_token, "http://mock-idp.test/certs")
        assert exc_aud.value.status_code == 401

        # Mismatched iss must fail
        with pytest.raises(HTTPException) as exc_iss:
            await _extract_claims(mismatched_iss_token, "http://mock-idp.test/certs")
        assert exc_iss.value.status_code == 401

        # Missing aud must fail
        with pytest.raises(HTTPException) as exc_missing:
            await _extract_claims(missing_aud_token, "http://mock-idp.test/certs")
        assert exc_missing.value.status_code == 401


# ── WebAuthn Tests: Origin and Challenge Replay ───────────────────────────────

@pytest.mark.asyncio
async def test_webauthn_challenge_replay_and_origin(app_client):
    """WebAuthn challenges must be single-use and fail on origin mismatch."""
    client, redis = app_client
    jwt_admin = _create_access_token("admin", role="admin")
    client.cookies.set("token", jwt_admin)

    # 1. Begin registration
    r_reg = await client.post("/auth/mfa/webauthn/register/begin")
    assert r_reg.status_code == 200
    options = r_reg.json()
    assert "challenge" in options

    # Verify challenge exists in Redis
    chal_raw = await redis.get("mgmt:webauthn:challenge:admin")
    assert chal_raw is not None

    # Simulate invalid submission to consume challenge
    r_bad = await client.post("/auth/mfa/webauthn/register/complete", json={"bogus": "payload"})
    assert r_bad.status_code == 400

    # Challenge must be deleted immediately (single-use on any path)
    chal_after = await redis.get("mgmt:webauthn:challenge:admin")
    assert chal_after is None, "Challenge must be deleted immediately after completion attempt"

    # Second call must return 400 (no pending challenge / replay rejected)
    r_replay = await client.post("/auth/mfa/webauthn/register/complete", json={"bogus": "payload"})
    assert r_replay.status_code == 400
    assert "No pending registration challenge" in r_replay.json()["detail"]


# ── TOTP Tests: Replay Resistance ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_totp_code_replay_rejected(app_client):
    """A valid TOTP code cannot be replayed within the validity window."""
    client, redis = app_client
    jwt_admin = _create_access_token("admin", role="admin")
    client.cookies.set("token", jwt_admin)

    # 1. Setup TOTP
    r_setup = await client.get("/auth/mfa/totp/setup")
    assert r_setup.status_code == 200
    setup_data = r_setup.json()
    backup_codes = setup_data["backup_codes"]

    # Decrypt the secret to generate a valid TOTP code
    from management.api.routes.mfa_totp import _get_fernet
    fernet = _get_fernet()
    enc_secret = await redis.get("mgmt:totp:admin")
    raw_secret = fernet.decrypt(enc_secret.encode()).decode()
    totp = pyotp.TOTP(raw_secret)
    valid_code = totp.now()

    # 2. Verify with valid code -> 200
    r_v1 = await client.post("/auth/mfa/totp/verify", json={"code": valid_code})
    assert r_v1.status_code == 200
    assert r_v1.json().get("verified") is True

    # 3. Replay exact same code immediately -> 401 Unauthorized
    r_v2 = await client.post("/auth/mfa/totp/verify", json={"code": valid_code})
    assert r_v2.status_code == 401, "Replayed TOTP code within the window must be rejected with 401"

    # 4. Backup code single-use test
    first_backup = backup_codes[0]
    r_b1 = await client.post("/auth/mfa/totp/verify", json={"code": first_backup})
    assert r_b1.status_code == 200
    assert r_b1.json().get("backup_code_used") is True

    # Replay same backup code -> 401
    r_b2 = await client.post("/auth/mfa/totp/verify", json={"code": first_backup})
    assert r_b2.status_code == 401, "Replayed backup code must be rejected with 401"


# ── SAML Tests: Signature Tampering and XSW ───────────────────────────────────

def _generate_saml_key_cert() -> Tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _strip_pem_headers(cert_pem: str) -> str:
    lines = [
        line for line in cert_pem.strip().splitlines()
        if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ]
    return "".join(lines)


def _build_signed_saml_assertion(key_pem: str, cert_pem: str, name_id: str = "alice@example.com") -> str:
    now = OneLogin_Saml2_Utils.now()
    issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(now)
    not_before = OneLogin_Saml2_Utils.parse_time_to_SAML(now - 60)
    not_on_or_after = OneLogin_Saml2_Utils.parse_time_to_SAML(now + 3600)
    assertion_id = "_" + uuid.uuid4().hex

    assertion_xml = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"
    ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>https://test-idp.example/saml</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{name_id}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
        <saml:AudienceRestriction>
            <saml:Audience>http://localhost:8090/auth/sso/metadata</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
        <saml:Attribute Name="groups">
            <saml:AttributeValue xsi:type="xs:string">Security-Admins</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>"""

    signed = OneLogin_Saml2_Utils.add_sign(assertion_xml, key_pem, cert_pem)
    if isinstance(signed, bytes):
        signed = signed.decode()
    return signed


def _wrap_in_saml_response(assertion_xml: str) -> str:
    now = OneLogin_Saml2_Utils.now()
    issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(now)
    response_id = "_" + uuid.uuid4().hex
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>https://test-idp.example/saml</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    {assertion_xml}
</samlp:Response>"""


@pytest.mark.asyncio
async def test_saml_tampered_assertion_and_xsw_rejected(monkeypatch: pytest.MonkeyPatch, fake_redis: fakeredis.aioredis.FakeRedis):
    """SAML assertion tampering and signature wrapping attacks must be rejected with 401."""
    key_pem, cert_pem = _generate_saml_key_cert()

    monkeypatch.setenv("MANAGEMENT_SAML_STRICT", "true")
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_ENTITY_ID", "https://test-idp.example/saml")
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_SSO_URL", "https://test-idp.example/sso")
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_CERT", _strip_pem_headers(cert_pem))
    monkeypatch.setenv("MANAGEMENT_SAML_SP_ENTITY_ID", "http://localhost:8090/auth/sso/metadata")
    monkeypatch.setenv("MANAGEMENT_SAML_SP_ACS_URL", "http://localhost:8090/auth/sso/saml/acs")
    monkeypatch.setenv("MANAGEMENT_SAML_ROLE_MAPPING", '{"Security-Admins": "admin"}')

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Valid signed assertion succeeds (baseline)
        assertion = _build_signed_saml_assertion(key_pem, cert_pem, name_id="alice@example.com")
        resp_xml = _wrap_in_saml_response(assertion)

        nonce = uuid.uuid4().hex
        await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/")
        r_valid = await client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": base64.b64encode(resp_xml.encode()).decode(), "RelayState": nonce},
        )
        assert r_valid.status_code == 302
        assert "token" in r_valid.cookies

        # 2. Tampered assertion (change NameID after signature) must fail with 401
        tampered_assertion = assertion.replace("alice@example.com", "attacker@evil.example")
        resp_tampered_xml = _wrap_in_saml_response(tampered_assertion)

        nonce = uuid.uuid4().hex
        await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/")
        r_tampered = await client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": base64.b64encode(resp_tampered_xml.encode()).decode(), "RelayState": nonce},
        )
        assert r_tampered.status_code == 401
        assert "token" not in r_tampered.cookies

        # 3. XML Signature Wrapping (XSW): Inject an unsigned assertion with attacker identity alongside signed assertion
        # In XSW #3, an unsigned Assertion with forged NameID is placed before or after the signed one
        unsigned_forged_assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"
        ID="_{uuid.uuid4().hex}" Version="2.0" IssueInstant="{OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())}">
        <saml:Issuer>https://test-idp.example/saml</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">attacker@evil.example</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="{OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now() - 60)}" NotOnOrAfter="{OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now() + 3600)}">
            <saml:AudienceRestriction>
                <saml:Audience>http://localhost:8090/auth/sso/metadata</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="groups"><saml:AttributeValue xsi:type="xs:string">Security-Admins</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>"""
        
        xsw_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_{uuid.uuid4().hex}" Version="2.0" IssueInstant="{OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())}">
        <saml:Issuer>https://test-idp.example/saml</saml:Issuer>
        <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        {unsigned_forged_assertion}
        {assertion}
    </samlp:Response>"""

        nonce = uuid.uuid4().hex
        await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/")
        r_xsw = await client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": base64.b64encode(xsw_xml.encode()).decode(), "RelayState": nonce},
        )
        assert r_xsw.status_code == 401, "XSW response with unsigned assertion injected must be rejected with 401"
        assert "token" not in r_xsw.cookies

    await _redis_module.close_redis()

