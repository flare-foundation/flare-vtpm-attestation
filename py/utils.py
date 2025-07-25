import base64
import json
from typing import Literal

from pydantic import BaseModel


class MonitoringEnabled(BaseModel):
    memory: bool


class ConfidentialSpaceSubmod(BaseModel):
    monitoring_enabled: MonitoringEnabled
    support_attributes: list[str] | None = None


class ContainerSubmod(BaseModel):
    image_reference: str
    image_digest: str
    restart_policy: str
    image_id: str
    env_override: dict[str, str] | None = None
    env: dict[str, str] | None = None
    args: list[str] | None = None


class GceSubmod(BaseModel):
    zone: str
    project_id: str
    project_number: str
    instance_name: str
    instance_id: str


class NvidiaGpuSubmod(BaseModel):
    cc_mode: Literal["ON", "OFF"]


class Submods(BaseModel):
    confidential_space: ConfidentialSpaceSubmod
    container: ContainerSubmod
    gce: GceSubmod
    nvidia_gpu: NvidiaGpuSubmod | None = None


class Tdx(BaseModel):
    gcp_attester_tcb_status: str
    gcp_attester_tcb_date: str


class AttestationTokenPayload(BaseModel):
    aud: str
    exp: int
    iat: int
    iss: str
    nbf: int
    sub: str
    eat_profile: str
    secboot: bool
    oemid: int
    hwmodel: str
    swname: str
    swversion: list[str]
    dbgstat: str
    google_service_accounts: list[str]
    eat_nonce: str | None = None
    attester_tcb: list[str] | None = None
    tdx: Tdx | None = None
    submods: Submods


class AttestationTokenHeader(BaseModel):
    alg: Literal["RS256"]
    kid: str
    typ: str
    x5c: list[str] | None = None


class AttestationToken(BaseModel):
    header: AttestationTokenHeader
    payload: AttestationTokenPayload
    signature: str


def base64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def get_unverified_token(raw_token: str) -> AttestationToken:
    raw_token_parts = raw_token.split(".")
    if len(raw_token_parts) != 3:
        raise ValueError("JWT must have exactly 3 parts")

    header_json = json.loads(base64url_decode(raw_token_parts[0]))
    payload_json = json.loads(base64url_decode(raw_token_parts[1]))
    signature = raw_token_parts[2]
    return AttestationToken(
        header=AttestationTokenHeader.model_validate(header_json),
        payload=AttestationTokenPayload.model_validate(payload_json),
        signature=signature,
    )
