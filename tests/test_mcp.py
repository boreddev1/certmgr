#!/usr/bin/env python3
"""Test des MCP-Servers: Werkzeug-Registrierung und API-Aufrufe.

Prueft auch das Sicherheitsmodell - ohne ALLOW_WRITE gibt es kein
create_client_cert, mit ALLOW_REVOKE gibt es revoke_client_cert.
"""
import importlib
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from certmgr import ca  # noqa: E402
from certmgr.app import AdminAuth, serve  # noqa: E402
from certmgr.manager import CertManager  # noqa: E402
from certmgr.store import Store  # noqa: E402
from test_e2e import MockCF  # noqa: E402

FAILURES = []
PORT = 18204
TOKEN = "test-api-token"


def check(name, cond, detail=""):
    if cond:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        print(f"  \033[31mFAIL\033[0m {name} {detail}")
        FAILURES.append(name)


def load_mcp(allow_write="0", allow_revoke="0"):
    """MCP-Server mit gesetzten Env-Variablen neu laden."""
    tmpdir = tempfile.mkdtemp()
    tokenfile = os.path.join(tmpdir, "token")
    with open(tokenfile, "w") as fh:
        fh.write(TOKEN)
    os.environ["CERTMGR_BASE_URL"] = f"http://127.0.0.1:{PORT}"
    os.environ["CERTMGR_API_TOKEN_FILE"] = tokenfile
    os.environ["CERTMGR_MCP_ALLOW_WRITE"] = allow_write
    os.environ["CERTMGR_MCP_ALLOW_REVOKE"] = allow_revoke
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp")
    sys.path.insert(0, path)
    for mod in list(sys.modules):
        if mod == "certmgr_admin":
            del sys.modules[mod]
    return importlib.import_module("certmgr_admin")


def tool_names(mod):
    """Namen der registrierten Werkzeuge."""
    tools = getattr(mod.mcp, "_tool_manager", None)
    if tools is None:
        return set()
    try:
        return set(tools._tools.keys())
    except AttributeError:
        return set()


def main():
    # Cert-Manager laufen lassen
    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "registry.sqlite"))
    mgr = CertManager(
        store=store, cf=MockCF(), master_key=b"Y" * 32,
        base_url="https://access.boreddev1.cc", api_token=TOKEN,
    )
    threading.Thread(
        target=serve,
        args=(mgr, AdminAuth("pw")),
        kwargs={"public_port": 18203, "admin_port": PORT},
        daemon=True,
    ).start()
    time.sleep(1.2)

    print("\n[1] Standardmodus: nur lesende Werkzeuge")
    mod = load_mcp("0", "0")
    names = tool_names(mod)
    check("list_client_certs vorhanden", "list_client_certs" in names, names)
    check("certmgr_status vorhanden", "certmgr_status" in names, names)
    check("create_client_certs NICHT vorhanden", "create_client_cert" not in names, names)
    check("revoke_client_cert NICHT vorhanden", "revoke_client_cert" not in names, names)

    print("\n[2] Schreiben erlaubt")
    mod = load_mcp("1", "0")
    names = tool_names(mod)
    check("create_client_cert vorhanden", "create_client_cert" in names, names)
    check("revoke_client_cert weiterhin gesperrt", "revoke_client_cert" not in names, names)

    print("\n[3] Widerruf erlaubt")
    mod = load_mcp("1", "1")
    names = tool_names(mod)
    check("revoke_client_cert vorhanden", "revoke_client_cert" in names, names)
    check("reactivate_client_cert vorhanden", "reactivate_client_cert" in names, names)

    print("\n[4] Werkzeuge funktionieren")
    mod = load_mcp("1", "1")
    res = mod.list_client_certs()
    check("list_client_certs liefert certs", "certs" in res, res)
    check("certmgr_status liefert Modus", mod.certmgr_status().get("cf_mode") is not None)

    res = mod.create_client_cert(device="mcp-test", validity_days=90)
    check("create_client_cert liefert Passwort", "password" in res, res)
    check("create_client_cert liefert Link", "link" in res, res)
    cert_id = res.get("id", "")

    res = mod.revoke_client_cert(cert_id, reason="Test")
    check("revoke_client_cert antwortet", "cert" in res or "error" in res, res)

    print("\n[5] Fehlende Token-Datei")
    os.environ["CERTMGR_API_TOKEN_FILE"] = "/tmp/gibtsnicht-token"
    for mod_name in list(sys.modules):
        if mod_name == "certmgr_admin":
            del sys.modules[mod_name]
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp"))
    mod2 = importlib.import_module("certmgr_admin")
    res = mod2.list_client_certs()
    check("Fehlermeldung statt Absturz", "error" in res, res)

    print()
    if FAILURES:
        print(f"\033[1;31m{len(FAILURES)} Test(s) fehlgeschlagen:\033[0m")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\033[1;32mAlle MCP-Tests bestanden.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
