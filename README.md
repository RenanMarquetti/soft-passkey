# soft-passkey

A software WebAuthn authenticator: **passkey as a protocol, not as a device**.

Give a bot, CI job or machine **its own** passkey, registered on its own (test/service) user and revocable on its own,
instead of sharing a human's real passkey. The server sees a distinct credential ID, so it can tell the bot from the person
and scope what the bot may do.

Built on [python-fido2](https://github.com/Yubico/python-fido2) 2.x. Adapted from
[bodik/soft-webauthn](https://github.com/bodik/soft-webauthn) (MIT) with:

- user verification flag (servers with `requireUserVerification: true` accept it)
- export/import as one base64 string — a file (mode 600) or an environment variable
- fixed signature counter by default (stateless; counter `0` means "no counter" in WebAuthn), opt-in increment
- WebAuthn JSON in and out (base64url), the format `@simplewebauthn/server` and `python-fido2` expect

## Usage

```python
from soft_passkey import SoftPasskey

passkey, registration = SoftPasskey.create(creation_options_json, origin="https://login.example.com")
secret = passkey.export()          # store it: this string IS the credential

bot = SoftPasskey.from_env()       # reads SOFT_PASSKEY and removes it from os.environ
assertion = bot.get(request_options_json, origin="https://login.example.com")
```

CLI:

```sh
soft-passkey register --origin https://login.example.com --options reg-options.json --out bot.passkey
SOFT_PASSKEY="$(cat bot.passkey)" soft-passkey sign --origin https://login.example.com --options auth-options.json
```

## Security notes

- **The exported string is the secret.** Anyone holding it signs in as that credential. Use a dedicated user with the
  minimum role, short sessions, and revoke the credential if the machine is compromised.
- **Environment variables leak to child processes** and are readable in `/proc/<pid>/environ`. Inject the variable only
  into the process that signs in (`from_env` pops it by default) and hand the resulting session to the rest.
- **The client declares the origin.** In a browser, the browser writes `clientDataJSON.origin`; here, this program does.
  The server still checks it, but phishing resistance relies on the bot only talking to the real RP.
- User verification is self-asserted: there is no human gesture. Servers that need proof of a human should not accept
  software credentials (no attestation is provided; `fmt` is `none`).

## Tests

```sh
uv venv && uv pip install -e '.[test]' && .venv/bin/pytest
# against @simplewebauthn/server (Node):
cd tests/simplewebauthn && npm install && node verify.mjs
```

License: MIT.
