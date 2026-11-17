"""Point-of-use integration for A's executor and D's gateway."""

from copy import deepcopy
from dataclasses import dataclass

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry
from referencing.exceptions import Unresolvable

from .payloads import parse_tool_manifest
from .protocol import TrustError
from .store import ReleaseStore, VerifiedRelease


@dataclass(frozen=True)
class VerifiedConfiguration:
    policy: VerifiedRelease
    tool_manifest: VerifiedRelease
    _tools: dict[str, dict]

    def evidence_versions(self) -> dict[str, str]:
        return {
            "policy_version": self.policy.ref.tag,
            "tool_manifest_version": self.tool_manifest.ref.tag,
        }

    def tool(self, tool_id: str) -> dict:
        if tool_id not in self._tools:
            raise TrustError("UNKNOWN_TOOL")
        return deepcopy(self._tools[tool_id])

    def validate_arguments(self, tool_id: str, arguments: dict) -> None:
        schema = self.tool(tool_id)["argument_schema"]
        try:
            Draft202012Validator(schema, registry=Registry()).validate(arguments)
        except (ValidationError, Unresolvable, RecursionError) as exc:
            raise TrustError("INVALID_TOOL_ARGUMENTS") from exc


def load_configuration(store: ReleaseStore, *, policy_id: str, tool_manifest_id: str,
                       policy_version: str | None = None, tool_manifest_version: str | None = None
                       ) -> VerifiedConfiguration:
    with store.snapshot() as snapshot:
        policy = snapshot.load("policy", policy_id, expected_version=policy_version)
        tools = snapshot.load("tool_manifest", tool_manifest_id, expected_version=tool_manifest_version)
    return VerifiedConfiguration(policy, tools, parse_tool_manifest(tools.content))
