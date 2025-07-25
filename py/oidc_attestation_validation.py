import logging
from pathlib import Path
from typing import Any

import requests

from utils import AttestationToken, get_unverified_token

# ——— Configuration ———
OIDC_ISSUER = "https://confidentialcomputing.googleapis.com"
WELL_KNOWN = "/.well-known/openid-configuration"
TIMEOUT = 10

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

# ——— HTTP Helpers ———
session = requests.Session()
session.headers.update({"Accept": "application/json"})


def fetch_json(url: str) -> dict[str, Any]:
    resp = session.get(url, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def get_jwks() -> dict[str, Any]:
    cfg = fetch_json(f"{OIDC_ISSUER}{WELL_KNOWN}")
    return fetch_json(cfg["jwks_uri"])


# ——— Main ———
def main(token_file: Path) -> None:
    raw = token_file.read_text().splitlines()[0].strip()
    token: AttestationToken = get_unverified_token(raw)

    log.info("=== Decoded Token ===")
    log.info("===== Header =====")
    print(token.header.model_dump_json(indent=2))
    log.info("===== Payload =====")
    print(token.payload.model_dump_json(indent=2))
    log.info("===== Signature =====")
    print(token.signature)


if __name__ == "__main__":
    import sys

    main(Path(sys.argv[1] if len(sys.argv) > 1 else "data/oidc.txt"))
