"""Auth unit tests: hashing, tokens, expiry, tampering, lockout."""
from aegis.auth import Auth, allowed


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def test_password_hashing_and_login(tmp_path):
    a = Auth(tmp_path / "u.json", secret="s")
    a.add("alice", "correct horse", "operator")
    assert "correct horse" not in (tmp_path / "u.json").read_text()        # never stored in plain text
    tok, msg = a.login("alice", "correct horse")
    assert tok and a.verify(tok) == {"user": "alice", "role": "operator"}
    assert a.login("alice", "wrong")[0] is None and a.login("mallory", "x")[0] is None


def test_token_tamper_and_expiry(tmp_path):
    clk = Clock()
    a = Auth(tmp_path / "u.json", secret="s", clock=clk)
    a.add("bob", "password1", "viewer")
    tok = a.issue("bob", "viewer")
    forged = a.issue("bob", "engineer")                       # role not what's on file -> rejected
    assert a.verify(forged) is None
    other = Auth(tmp_path / "u.json", secret="different")
    assert other.verify(tok) is None                          # wrong signing key
    p, sig = tok.split(".")
    assert a.verify(p[:-2] + "AA." + sig) is None             # edited payload
    clk.t += 9 * 3600
    assert a.verify(tok) is None                              # expired after a shift


def test_roles_order():
    assert allowed({"role": "engineer"}, "operator") and not allowed({"role": "viewer"}, "operator")
    assert not allowed(None, "viewer")


def test_short_passwords_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        Auth(tmp_path / "u.json").add("carol", "short", "operator")
