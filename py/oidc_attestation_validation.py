import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, TypedDict

import requests
from web3 import Web3


# ——— TypedDicts ———
class Container(TypedDict):
    image_digest: str


class _Submods(TypedDict):
    container: Container


class PayloadJson(TypedDict, total=False):
    hwmodel: str
    swname: str
    submods: _Submods
    iss: str
    secboot: str
    exp: int
    iat: int


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


# ——— JWT Utilities ———
def read_first_line(path: Path) -> str:
    return path.read_text().splitlines()[0].strip()


def base64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def split_token(tok: str) -> list[str]:
    parts = tok.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly 3 parts")
    return parts


def decode_part(b64: str) -> PayloadJson:
    return json.loads(base64url_decode(b64))


# ——— Printing ———
def show_inputs(h_hex: str, p_hex: str, s_hex: str) -> None:
    log.info("== verifyAndAttest INPUTS ==")
    log.info(h_hex)
    log.info(p_hex)
    log.info(s_hex)
    log.info("============================\n")


def show_vtpm_inputs(p: PayloadJson) -> None:
    md = p.get("submods", {}).get("container", {}).get("image_digest", "N/A")
    log.info("== setBaseVtpmConfig ==")
    log.info(f"hwmodel:   {p.get('hwmodel', 'N/A')}")
    log.info(f"swname:    {p.get('swname', 'N/A')}")
    log.info(f"img_digest:{md}")
    log.info(f"iss:       {p.get('iss', 'N/A')}")
    log.info(f"secboot:   {p.get('secboot', 'N/A')}")
    log.info("=========================\n")


def show_vtpm_config(p: PayloadJson, dg: bytes) -> None:
    log.info("===== VtpmConfig =====")
    log.info(f"exp:    {p.get('exp', 'N/A')}")
    log.info(f"iat:    {p.get('iat', 'N/A')}")
    log.info(f"digest: {Web3.to_hex(dg)}")
    log.info("======================\n")


# ——— Main ———
def main(path: Path) -> None:
    raw = read_first_line(path)
    h_b64, p_b64, s_b64 = split_token(raw)

    pld: PayloadJson = decode_part(p_b64)

    h_hex, p_hex, s_hex = (base64url_decode(x).hex() for x in (h_b64, p_b64, s_b64))

    show_inputs(h_hex, p_hex, s_hex)
    show_vtpm_inputs(pld)

    dg = hashlib.sha256(f"{h_b64}.{p_b64}".encode()).digest()
    show_vtpm_config(pld, dg)


if __name__ == "__main__":
    import sys

    main(Path(sys.argv[1] if len(sys.argv) > 1 else "data/oidc.txt"))
