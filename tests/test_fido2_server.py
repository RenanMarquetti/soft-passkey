import json
import os

import pytest
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

from soft_passkey import PasskeyError, SoftPasskey
from soft_passkey.cli import main

ORIGIN = "https://login.example.com"
RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")


def _server():
    return Fido2Server(RP, verify_origin=lambda o: o == ORIGIN)


def _json(options):
    return json.loads(json.dumps(dict(options)))


def _register(server, **kw):
    options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b"bot-user-1", name="bot"), user_verification="required")
    passkey, response = SoftPasskey.create(_json(options), ORIGIN, **kw)
    auth_data = server.register_complete(state, response)
    return passkey, [auth_data.credential_data]


def _login(server, passkey, creds, origin=ORIGIN):
    options, state = server.authenticate_begin(creds, user_verification="required")
    return server.authenticate_complete(state, creds, passkey.get(_json(options), origin))


def it_registers_and_signs_in_with_user_verification():
    server = _server()
    passkey, creds = _register(server)
    assert _login(server, passkey, creds).credential_id == passkey.credential_id


def it_survives_export_and_load():
    server = _server()
    passkey, creds = _register(server)
    assert _login(server, SoftPasskey.load(passkey.export()), creds)


def it_loads_from_env_and_removes_the_variable(monkeypatch):
    server = _server()
    passkey, creds = _register(server)
    monkeypatch.setenv("SOFT_PASSKEY", passkey.export())
    loaded = SoftPasskey.from_env()
    assert "SOFT_PASSKEY" not in os.environ
    assert _login(server, loaded, creds)


def it_is_rejected_by_the_server_when_origin_is_wrong():
    server = _server()
    passkey, creds = _register(server)
    with pytest.raises(ValueError):
        _login(server, passkey, creds, origin="https://evil.example.net")


def it_refuses_a_different_rp_id():
    server = _server()
    passkey, creds = _register(server)
    other = Fido2Server(PublicKeyCredentialRpEntity(id="other.com", name="Other"), verify_origin=lambda o: True)
    options, _ = other.authenticate_begin(creds)
    with pytest.raises(PasskeyError):
        passkey.get(_json(options), "https://other.com")


def it_increments_the_counter_only_when_asked():
    server = _server()
    passkey, creds = _register(server, counter_increments=True)
    _login(server, passkey, creds)
    _login(server, passkey, creds)
    assert passkey.sign_count == 2


def it_cli_writes_key_with_mode_600_and_signs(tmp_path, capsys):
    server = _server()
    options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b"bot-user-2", name="bot2"), user_verification="required")
    (tmp_path / "reg.json").write_text(json.dumps(_json(options)))
    key = tmp_path / "bot.passkey"
    main(["register", "--origin", ORIGIN, "--options", str(tmp_path / "reg.json"), "--out", str(key)])
    creds = [server.register_complete(state, json.loads(capsys.readouterr().out)).credential_data]
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    options, state = server.authenticate_begin(creds, user_verification="required")
    (tmp_path / "auth.json").write_text(json.dumps(_json(options)))
    main(["sign", "--origin", ORIGIN, "--options", str(tmp_path / "auth.json"), "--key", str(key)])
    assert server.authenticate_complete(state, creds, json.loads(capsys.readouterr().out))
