"""Phase 801 D2 — real (non-mocked) SAML assertion signature verification.

`test_saml.py` mocks `OneLogin_Saml2_Auth` for every ACS test — none of it
ever exercises the real xmlsec/libxmlsec1 signature-verification code path
python3-saml uses under the hood. That's exactly the code whose musl/Alpine
build behaviour Phase 801's rebase needed to prove safe (see PHASE_801.md
D2): "the real risk here is silent auth breakage, not a loud build failure."

This file builds and self-signs a real minimal SAML 2.0 Response — no
mocking of the SAML library at any layer — and posts it through the actual
ACS endpoint with MANAGEMENT_SAML_STRICT=true. Three cases:

1. A validly-signed assertion is accepted (positive control — proves the
   happy path still works, not just that tampering is caught).
2. The same assertion, signed, then tampered with post-signature (NameID
   changed without re-signing) is rejected with 401.
3. An assertion signed by a key/cert the SP does NOT trust is rejected
   with 401 (proves cert-pinning, not just "a signature is present").
"""

from __future__ import annotations

import base64
import datetime
import os
import uuid
from typing import AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

_IDP_ENTITY_ID = "https://test-idp.example/saml"
_SP_ENTITY_ID = "http://localhost:8090/auth/sso/metadata"
_ACS_URL = "http://localhost:8090/auth/sso/saml/acs"


def _generate_key_and_cert() -> Tuple[str, str]:
    """Generate a fresh self-signed RSA key + X.509 cert PEM pair."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-idp.example")]
    )
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
    """MANAGEMENT_SAML_IDP_CERT is documented as 'PEM without header'."""
    lines = [
        line
        for line in cert_pem.strip().splitlines()
        if line and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ]
    return "".join(lines)


def _build_signed_assertion(
    key_pem: str,
    cert_pem: str,
    name_id: str = "alice@example.com",
    groups: list[str] | None = None,
) -> str:
    """Build a minimal, spec-valid SAML 2.0 Assertion and sign it."""
    groups = groups if groups is not None else ["Security-Admins"]
    now = OneLogin_Saml2_Utils.now()
    issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(now)
    not_before = OneLogin_Saml2_Utils.parse_time_to_SAML(now - 60)
    not_on_or_after = OneLogin_Saml2_Utils.parse_time_to_SAML(now + 3600)
    sc_not_on_or_after = not_on_or_after
    assertion_id = "_" + uuid.uuid4().hex
    group_attrs = "".join(
        f'<saml:AttributeValue xsi:type="xs:string">{g}</saml:AttributeValue>'
        for g in groups
    )

    assertion_xml = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"
    ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{_IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{name_id}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="{sc_not_on_or_after}"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
        <saml:AudienceRestriction>
            <saml:Audience>{_SP_ENTITY_ID}</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
        <saml:Attribute Name="groups">{group_attrs}</saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>"""

    signed_assertion = OneLogin_Saml2_Utils.add_sign(assertion_xml, key_pem, cert_pem)
    if isinstance(signed_assertion, bytes):
        signed_assertion = signed_assertion.decode()
    return signed_assertion


def _wrap_in_response(signed_assertion_xml: str) -> str:
    """Wrap a (possibly already-signed) Assertion in an unsigned Response envelope."""
    now = OneLogin_Saml2_Utils.now()
    issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(now)
    response_id = "_" + uuid.uuid4().hex
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{_IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    {signed_assertion_xml}
</samlp:Response>"""


def _encode(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


@pytest_asyncio.fixture()
async def saml_client(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[Tuple["AsyncClient", fakeredis.aioredis.FakeRedis, str, str], None]:  # noqa: F821
    """Unauthenticated client with real (non-mocked, strict) SAML settings.

    Yields (client, fake_redis, key_pem, trusted_cert_pem).
    """
    from httpx import ASGITransport, AsyncClient

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    key_pem, cert_pem = _generate_key_and_cert()

    monkeypatch.setenv("MANAGEMENT_SAML_STRICT", "true")
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_ENTITY_ID", _IDP_ENTITY_ID)
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_SSO_URL", "https://test-idp.example/sso")
    monkeypatch.setenv("MANAGEMENT_SAML_IDP_CERT", _strip_pem_headers(cert_pem))
    monkeypatch.setenv("MANAGEMENT_SAML_SP_ENTITY_ID", _SP_ENTITY_ID)
    monkeypatch.setenv("MANAGEMENT_SAML_SP_ACS_URL", _ACS_URL)
    monkeypatch.setenv(
        "MANAGEMENT_SAML_ROLE_MAPPING", '{"Security-Admins": "admin"}'
    )

    server = fakeredis.FakeServer()
    fake_redis = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client, fake_redis, key_pem, cert_pem

    await _redis_module.close_redis()
    await fake_redis.aclose()


async def _post_saml_response(client, fake_redis, xml: str):
    nonce = uuid.uuid4().hex
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/")
    return await client.post(
        "/auth/sso/saml/acs",
        data={"SAMLResponse": _encode(xml), "RelayState": nonce},
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_validly_signed_assertion_is_accepted(saml_client) -> None:
    """Positive control: a correctly-signed assertion from the trusted cert succeeds.

    Proves the happy path works end to end through the real xmlsec-backed
    signature verification — not just that we can detect tampering. If this
    fails, the adversarial test below would be trivially "passing" for the
    wrong reason (everything rejected, tampered or not).
    """
    client, fake_redis, key_pem, cert_pem = saml_client
    assertion = _build_signed_assertion(key_pem, cert_pem, groups=["Security-Admins"])
    response_xml = _wrap_in_response(assertion)

    r = await _post_saml_response(client, fake_redis, response_xml)

    assert r.status_code == 302, (
        f"expected 302 (successful SAML login), got {r.status_code}: {r.text}"
    )
    assert "token" in r.cookies


@pytest.mark.asyncio
async def test_tampered_assertion_is_rejected(saml_client) -> None:
    """Acceptance-critical (Phase 801 D2): a tampered signed assertion is rejected.

    Signs a real assertion, then modifies the NameID *after* signing without
    re-signing — the classic signature-wrapping/tampering attack. xmlsec must
    detect the digest mismatch and reject it. This is the actual proof the
    python3-saml/xmlsec/libxmlsec1 binding still works correctly on the
    Alpine/musl rebase; nothing else in this repo tests it end to end.
    """
    client, fake_redis, key_pem, cert_pem = saml_client
    assertion = _build_signed_assertion(key_pem, cert_pem, name_id="alice@example.com")

    tampered = assertion.replace("alice@example.com", "attacker@evil.example")
    assert tampered != assertion, "tamper substitution had no effect — test is broken"

    response_xml = _wrap_in_response(tampered)
    r = await _post_saml_response(client, fake_redis, response_xml)

    assert r.status_code == 401, (
        f"tampered assertion must be rejected with 401, got {r.status_code}: {r.text}"
    )
    assert "token" not in r.cookies


@pytest.mark.asyncio
async def test_assertion_signed_by_untrusted_key_is_rejected(saml_client) -> None:
    """An assertion signed by a key the SP never configured is rejected.

    Proves cert-pinning (idp.x509cert) is actually enforced, not just "some
    signature is present, structurally valid, and unmodified."
    """
    client, fake_redis, _key_pem, _cert_pem = saml_client
    attacker_key_pem, attacker_cert_pem = _generate_key_and_cert()

    assertion = _build_signed_assertion(attacker_key_pem, attacker_cert_pem)
    response_xml = _wrap_in_response(assertion)

    r = await _post_saml_response(client, fake_redis, response_xml)

    assert r.status_code == 401, (
        f"assertion signed by an untrusted key must be rejected with 401, "
        f"got {r.status_code}: {r.text}"
    )
    assert "token" not in r.cookies
