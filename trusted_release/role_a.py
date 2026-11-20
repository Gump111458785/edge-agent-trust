"""C's opt-in release checks at A's existing execution boundary."""

from dataclasses import dataclass, field, replace
import os
from pathlib import Path
from typing import Callable

from business.app.authorization import ApprovalVerifier, Rejected, TokenVerifier
from business.app.executor import Executor
from business.app.main import create_executor_app, database_path
from business.app.schemas import Evidence, ExecuteRequest, GrantArgs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .configuration import VerifiedConfiguration, load_configuration
from .handoff import open_store
from .protocol import TrustError
from .store import ReleaseStore


@dataclass(frozen=True)
class ExecutorReleaseCheck:
    store: ReleaseStore
    policy_id: str
    tool_manifest_id: str

    def __call__(self, action: str, args: GrantArgs, evidence: Evidence | None) -> VerifiedConfiguration:
        try:
            config = load_configuration(
                self.store, policy_id=self.policy_id, tool_manifest_id=self.tool_manifest_id,
                policy_version=evidence.policy_version if evidence else None,
                tool_manifest_version=evidence.tool_manifest_version if evidence else None,
            )
            config.validate_arguments(action, args.model_dump(mode="json"))
            return config
        except TrustError as exc:
            status = 503 if exc.code in {"STATE_UNAVAILABLE", "STATE_INVALID"} else 403
            raise Rejected("TRUST_" + exc.code, status) from exc


@dataclass(frozen=True)
class ReleaseAwareExecutor(Executor):
    """Supply current release tags to the existing A transaction for this request."""

    release_check: Callable[[str, GrantArgs, Evidence | None], VerifiedConfiguration] = field(kw_only=True)

    def _execute(self, request: ExecuteRequest, session_token: str | None) -> dict:
        claims = self.tokens.verify(request, self.clock())
        if not session_token:
            raise Rejected("SESSION_REQUIRED", 401)
        if self.evidence_required and claims.evidence is None:
            raise Rejected("EVIDENCE_REQUIRED")
        config = self.release_check(request.action, request.args, claims.evidence)
        executor = replace(self, **config.evidence_versions())
        # A repeats token/time checks, verifies session and approvals, and owns the write transaction.
        return Executor._execute(executor, request, session_token)


def create_app():
    store = open_store(Path(os.environ["ROLE_C_TRUST_CONFIG"]))
    verifier = ExecutorReleaseCheck(
        store, os.environ.get("ROLE_C_POLICY_ID", "campus-policy"),
        os.environ.get("ROLE_C_TOOLS_ID", "campus-tools"),
    )
    profile = os.environ.get("ROLE_A_PROFILE", "evidence")
    if profile not in {"token", "evidence"}:
        raise ValueError("ROLE_A_PROFILE must be token or evidence")
    public_key = load_pem_public_key(Path(os.environ["ROLE_A_D_PUBLIC_KEY"]).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("ROLE_A_D_PUBLIC_KEY must contain an Ed25519 public key")
    tokens = TokenVerifier(
        os.environ.get("ROLE_A_ISSUER", "role-d"),
        os.environ.get("ROLE_A_AUDIENCE", "role-a-executor"),
        {os.environ.get("ROLE_A_KEY_ID", "role-d-v1"): public_key},
    )
    approvals = ApprovalVerifier()
    if config := os.environ.get("ROLE_B_FABRIC_CONFIG"):
        from role_b.approval import FabricApprovalSource

        approvals = ApprovalVerifier(source=FabricApprovalSource.from_config(Path(config)))
    executor = ReleaseAwareExecutor(database_path(), tokens, approvals=approvals,
                                    evidence_required=profile == "evidence",
                                    release_check=verifier)
    return create_executor_app(executor)
