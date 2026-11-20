"""Create fresh, synthetic D/C signing material for local integration only."""
import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption, PrivateFormat,
                                                         PublicFormat)

from trusted_release.crypto import canonical_json
from trusted_release.protocol import sign_release
from trusted_release.store import ReleaseStore, TrustedKey


def initialize(directory: Path):
    # Never replace existing signing keys or release state.
    directory.mkdir(parents=True, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    (directory / 'd-private.pem').write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    (directory / 'd-public.pem').write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    publisher = Ed25519PrivateKey.generate()
    (directory / 'c-public.pem').write_bytes(publisher.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    kinds = frozenset({'policy', 'tool_manifest'})
    store = ReleaseStore.initialize(directory / 'releases.sqlite3', 'campus',
                                    {'c-demo': TrustedKey(publisher.public_key(), kinds, kinds)})
    policy = {'version': 1, 'rules': {
        'grant_access': {'area': 'visitor_area', 'max_valid_minutes': 60},
        'grant_restricted_access': {'area': 'server_room', 'max_valid_minutes': 30}}}
    tools = {'tools': []}
    for action, area, risk in [('grant_access', 'visitor_area', 'normal'),
                               ('grant_restricted_access', 'server_room', 'high')]:
        tools['tools'].append({
            'tool_id': action, 'description': 'Synthetic campus access grant',
            'risk_level': risk, 'service_identity': 'role-a-executor',
            'execution_target': 'http://127.0.0.1:8001/internal/executor/access-grants',
            'argument_schema': {'type': 'object', 'required': ['booking_id', 'area', 'valid_minutes'],
                                'additionalProperties': False, 'properties': {
                                    'booking_id': {'type': 'string', 'pattern': '^BK-[0-9]{4}$'},
                                    'area': {'const': area},
                                    'valid_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 120}}}})
    for kind, name, value in [('policy', 'campus-policy', policy), ('tool_manifest', 'campus-tools', tools)]:
        content = canonical_json(value)
        store.publish(sign_release(publisher, scope='campus', kind=kind, artifact_id=name,
                                   version=1, content=content, key_id='c-demo'), content)
    config = {'scope': 'campus', 'database': 'releases.sqlite3', 'keys': {
        'c-demo': {'public_key': 'c-public.pem', 'publish': sorted(kinds), 'revoke': sorted(kinds)}}}
    (directory / 'trust.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    # Publisher private key is intentionally discarded; this is a one-time demo setup.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('gateway/data/demo'))
    args = parser.parse_args()
    initialize(args.directory)
    print(f'Demo material ready: {args.directory.resolve()}')


if __name__ == '__main__':
    main()
