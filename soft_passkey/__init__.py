"""Software WebAuthn authenticator (passkey as a protocol, not as a device).

Gives a bot or a machine its own credential, registered and revoked on its own,
so a human never hands their real passkey to automation.

Adapted from bodik/soft-webauthn (MIT, CESNET) to python-fido2 2.x, with user
verification, key export/import (file or environment variable) and a fixed
signature counter for stateless use.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.utils import sha256, websafe_decode, websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)

__all__ = ["SoftPasskey", "PasskeyError", "DEFAULT_ENV"]
__version__ = "0.1.0"

DEFAULT_ENV = "SOFT_PASSKEY"
ES256_ALG = -7
EXPORT_VERSION = 1


class PasskeyError(ValueError):
    """Raised when options are not supported or do not match the credential."""


def _b64url(value: bytes) -> str:
    return websafe_encode(value)


def _bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else websafe_decode(value)


def _public_key(options: Mapping[str, Any]) -> Mapping[str, Any]:
    return options.get("publicKey", options)


def _flags(uv: bool, attested: bool = False) -> AuthenticatorData.FLAG:
    flags = AuthenticatorData.FLAG.UP
    if uv:
        flags |= AuthenticatorData.FLAG.UV
    if attested:
        flags |= AuthenticatorData.FLAG.AT
    return flags


@dataclass
class SoftPasskey:
    """One credential bound to one RP ID and one user handle."""

    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    rp_id: str
    user_handle: bytes
    sign_count: int = 0
    counter_increments: bool = False
    user_verified: bool = True

    @classmethod
    def create(
        cls, options: Mapping[str, Any], origin: str, *, counter_increments: bool = False
    ) -> tuple["SoftPasskey", dict]:
        """Run navigator.credentials.create(). Returns the passkey and the
        registration response in WebAuthn JSON form (base64url fields)."""
        pk = _public_key(options)
        algs = [p.get("alg") for p in pk.get("pubKeyCredParams", [])]
        if algs and ES256_ALG not in algs:
            raise PasskeyError("RP does not accept ES256 (alg -7)")
        if pk.get("attestation") not in (None, "none", "indirect"):
            raise PasskeyError("only 'none' attestation is supported")
        rp_id = pk["rp"].get("id") or _origin_host(origin)
        passkey = cls(
            credential_id=os.urandom(32),
            private_key=ec.generate_private_key(ec.SECP256R1()),
            rp_id=rp_id,
            user_handle=_bytes(pk["user"]["id"]),
            counter_increments=counter_increments,
        )
        client_data = CollectedClientData.create(
            type=CollectedClientData.TYPE.CREATE, challenge=_bytes(pk["challenge"]), origin=origin
        )
        cose_key = ES256.from_cryptography_key(passkey.private_key.public_key())
        auth_data = AuthenticatorData.create(
            sha256(rp_id.encode()),
            _flags(passkey.user_verified, attested=True),
            passkey.sign_count,
            AttestedCredentialData.create(Aaguid.NONE, passkey.credential_id, cose_key),
        )
        attestation = AttestationObject.create("none", auth_data, {})
        response = {
            "id": _b64url(passkey.credential_id),
            "rawId": _b64url(passkey.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": _b64url(bytes(client_data)),
                "attestationObject": _b64url(bytes(attestation)),
                "transports": ["internal"],
            },
        }
        return passkey, response

    def get(self, options: Mapping[str, Any], origin: str) -> dict:
        """Run navigator.credentials.get(). Returns the authentication response
        in WebAuthn JSON form (base64url fields)."""
        pk = _public_key(options)
        rp_id = pk.get("rpId") or _origin_host(origin)
        if rp_id != self.rp_id:
            raise PasskeyError(f"RP ID {rp_id!r} does not match credential RP ID {self.rp_id!r}")
        allowed = [_bytes(c["id"]) for c in pk.get("allowCredentials") or []]
        if allowed and self.credential_id not in allowed:
            raise PasskeyError("credential is not in allowCredentials")
        if self.counter_increments:
            self.sign_count += 1
        client_data = CollectedClientData.create(
            type=CollectedClientData.TYPE.GET, challenge=_bytes(pk["challenge"]), origin=origin
        )
        auth_data = AuthenticatorData.create(
            sha256(self.rp_id.encode()), _flags(self.user_verified), self.sign_count
        )
        signature = self.private_key.sign(
            bytes(auth_data) + sha256(bytes(client_data)), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": _b64url(bytes(client_data)),
                "authenticatorData": _b64url(bytes(auth_data)),
                "signature": _b64url(signature),
                "userHandle": _b64url(self.user_handle),
            },
        }

    def export(self) -> str:
        """Serialize to one base64 string (fits an environment variable).
        This string IS the secret: whoever holds it can sign in."""
        pkcs8 = self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        doc = {
            "v": EXPORT_VERSION,
            "credentialId": _b64url(self.credential_id),
            "privateKey": _b64url(pkcs8),
            "rpId": self.rp_id,
            "userHandle": _b64url(self.user_handle),
            "signCount": self.sign_count,
            "counterIncrements": self.counter_increments,
        }
        return base64.urlsafe_b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()

    @classmethod
    def load(cls, exported: str) -> "SoftPasskey":
        doc = json.loads(base64.urlsafe_b64decode(exported.strip().encode()))
        if doc.get("v") != EXPORT_VERSION:
            raise PasskeyError("unsupported export version")
        key = serialization.load_der_private_key(_bytes(doc["privateKey"]), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise PasskeyError("private key must be P-256")
        return cls(
            credential_id=_bytes(doc["credentialId"]),
            private_key=key,
            rp_id=doc["rpId"],
            user_handle=_bytes(doc["userHandle"]),
            sign_count=int(doc.get("signCount", 0)),
            counter_increments=bool(doc.get("counterIncrements", False)),
        )

    @classmethod
    def from_env(cls, name: str = DEFAULT_ENV, *, pop: bool = True) -> "SoftPasskey":
        """Load from an environment variable. By default the variable is removed
        from this process so child processes do not inherit it."""
        value = os.environ.pop(name, None) if pop else os.environ.get(name)
        if not value:
            raise PasskeyError(f"environment variable {name} is not set")
        return cls.load(value)

    def __repr__(self) -> str:
        return f"SoftPasskey(rp_id={self.rp_id!r}, credential_id={_b64url(self.credential_id)[:12]}…)"


def _origin_host(origin: str) -> str:
    host = origin.split("://", 1)[-1].split("/", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
