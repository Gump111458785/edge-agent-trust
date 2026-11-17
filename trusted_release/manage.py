"""Initialize local release state and import signed artifacts from an offline publisher."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .handoff import open_store
from .protocol import SignedStatement, TrustError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Deployment trust configuration JSON")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("init", help="Initialize the release state database")
    publish = subparsers.add_parser("publish", help="Import a signed release envelope and its payload")
    publish.add_argument("envelope", type=Path)
    publish.add_argument("content", type=Path)
    revoke = subparsers.add_parser("revoke", help="Import a signed revocation envelope")
    revoke.add_argument("envelope", type=Path)
    index = subparsers.add_parser("index", help="Index a current signed knowledge document")
    index.add_argument("artifact_id")
    index.add_argument("--index-dir", required=True, type=Path)
    index.add_argument("--model-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        store = open_store(args.config, initialize=args.operation == "init")
        if args.operation == "publish":
            signed = SignedStatement.from_json(args.envelope.read_bytes())
            ref = store.publish(signed, args.content.read_bytes())
            print(json.dumps(asdict(ref), ensure_ascii=True))
        elif args.operation == "revoke":
            store.revoke(SignedStatement.from_json(args.envelope.read_bytes()))
        elif args.operation == "index":
            from .embedding import open_onnx_index

            document = store.load("knowledge", args.artifact_id)
            open_onnx_index(args.index_dir, args.model_dir).add_release(document)
            print(document.ref.tag)
    except (TrustError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
