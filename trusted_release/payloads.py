"""Validate the structured artifacts consumed directly by C's runtime."""

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .crypto import canonical_json
from .protocol import TrustError, decode_json, is_identifier


_SCHEMA_DIR = Path(__file__).with_name("schemas")
_KNOWLEDGE = Draft202012Validator(decode_json((_SCHEMA_DIR / "knowledge.schema.json").read_bytes()))
_TOOLS = Draft202012Validator(decode_json((_SCHEMA_DIR / "tool-manifest.schema.json").read_bytes()))


def _parse(content: bytes, validator: Draft202012Validator) -> dict:
    try:
        value = decode_json(content)
        canonical_json(value)  # Reject non-finite floats and lone surrogate escapes.
        validator.validate(value)
    except (ValueError, TypeError, RecursionError, ValidationError) as exc:
        raise TrustError("INVALID_CONTENT") from exc
    return value


@dataclass(frozen=True)
class KnowledgeDocument:
    source: str
    chunks: Mapping[str, str]


def parse_knowledge(content: bytes) -> KnowledgeDocument:
    value = _parse(content, _KNOWLEDGE)
    chunks = {}
    for chunk in value["chunks"]:
        chunk_id = chunk["chunk_id"]
        if not is_identifier(chunk_id) or chunk_id in chunks:
            raise TrustError("INVALID_CONTENT")
        chunks[chunk_id] = chunk["text"]
    return KnowledgeDocument(value["source"], MappingProxyType(chunks))


def _check_local_references(value: object) -> None:
    # Follow all JSON values because a fragment pointer can point outside ordinary subschemas.
    if isinstance(value, dict):
        for key, item in value.items():
            if (key in ("$ref", "$dynamicRef") and isinstance(item, str)
                    and item and not item.startswith("#")):
                raise ValueError("External schema reference")
            _check_local_references(item)
    elif isinstance(value, list):
        for item in value:
            _check_local_references(item)


def parse_tool_manifest(content: bytes) -> dict[str, dict]:
    tools = {}
    for tool in _parse(content, _TOOLS)["tools"]:
        tool_id = tool["tool_id"]
        if not (is_identifier(tool_id) and is_identifier(tool["service_identity"])) or tool_id in tools:
            raise TrustError("INVALID_CONTENT")
        try:
            target = tool["execution_target"]
            url = urlsplit(target)
            if (not url.hostname or "@" in url.netloc or "#" in target
                    or any(c.isspace() or ord(c) < 32 or c == "\\" for c in target)):
                raise ValueError("Invalid execution target")
            _ = url.port  # Validate port syntax and range.
            schema = tool["argument_schema"]
            Draft202012Validator.check_schema(schema)
            _check_local_references(schema)
        except (ValueError, SchemaError, RecursionError) as exc:
            raise TrustError("INVALID_CONTENT") from exc
        tools[tool_id] = tool
    return tools


def validate_content(kind: str, content: bytes) -> None:
    if kind == "knowledge":
        parse_knowledge(content)
    elif kind == "tool_manifest":
        parse_tool_manifest(content)
