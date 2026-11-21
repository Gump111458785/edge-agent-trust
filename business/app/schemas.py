from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Identifier = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]{1,80}$')]
BookingId = Annotated[str, StringConstraints(pattern=r'^BK-[0-9]{4}$')]
Digest = Annotated[str, StringConstraints(pattern=r'^[0-9a-f]{64}$')]
Signature = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]{86}$')]
Timestamp = Annotated[int, Field(ge=0, le=253402300799)]
Revision = Annotated[int, Field(ge=1, le=2**31 - 1)]
Area = Literal['visitor_area', 'server_room']
Action = Literal['grant_access', 'grant_restricted_access']


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class GrantArgs(StrictModel):
    booking_id: BookingId
    area: Area
    valid_minutes: Annotated[int, Field(ge=1, le=120)]


class GrantProposal(StrictModel):
    action: Action
    args: GrantArgs


class Evidence(StrictModel):
    session_id: Identifier
    booking_id: BookingId
    booking_version: Revision
    policy_version: Identifier
    tool_manifest_version: Identifier


class TokenClaims(StrictModel):
    version: Literal[1]
    issuer: Identifier
    audience: Identifier
    key_id: Identifier
    token_id: Identifier
    operation_id: Identifier
    subject: Identifier
    action: Action
    args_hash: Digest
    issued_at: Timestamp
    expires_at: Timestamp
    approval_ref: Identifier | None = None
    evidence: Evidence | None = None


class SignedToken(StrictModel):
    claims: TokenClaims
    signature: Signature


class ExecuteRequest(StrictModel):
    operation_id: Identifier
    action: Action
    args: GrantArgs
    token: SignedToken | None = None


class DemoLogin(StrictModel):
    visitor_id: Identifier
    credential: Annotated[str, Field(min_length=1, max_length=256)]


class BookingToolResult(StrictModel):
    booking_id: BookingId
    status: Literal['confirmed', 'expired', 'revoked']
    building: str
    zone: str
    fixture: str | None = None
