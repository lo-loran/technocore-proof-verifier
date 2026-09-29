#!/usr/bin/env python3
"""Verify Ed25519 signatures of Technocore JSON receipts without private keys."""
import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
EXPECTED_DID = 'did:key:z6Mkgd3yeRxRPoUL8Q5V6GUjLAsHR7VjzSdBmm1rLcadDcVi'


def b58decode(value):
    number = 0
    for char in value:
        number = number * 58 + ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, 'big')
    return b'\x00' * (len(value) - len(value.lstrip('1'))) + raw


def verify(path, expected_did=None):
    # parse_int=int is important: large nonces must never become floats.
    with path.open('r', encoding='utf-8') as handle:
        receipt = json.load(handle, parse_int=int)
    if not isinstance(receipt, dict):
        raise ValueError('JSON root is not an object')
    room = receipt['room']
    posted = receipt['posted']
    if not isinstance(room, str) or not room or '|' in room:
        raise ValueError('Invalid room')
    if not isinstance(posted, dict):
        raise ValueError('Missing posted object')
    did = posted['from']
    nonce = posted['nonce']
    content = posted['text']
    signature = posted['sig']
    seq = posted['seq']
    if expected_did and did != expected_did:
        raise ValueError('DID differs from expected identity')
    if not isinstance(did, str) or not did.startswith('did:key:z'):
        raise ValueError('Unsupported DID')
    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise ValueError('Nonce must be an integer')
    if not isinstance(content, str) or not isinstance(signature, str):
        raise ValueError('Invalid text or signature')
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise ValueError('Invalid sequence number')
    key = b58decode(did[len('did:key:z'):])
    if len(key) != 34 or key[:2] != bytes.fromhex('ed01'):
        raise ValueError('DID is not an Ed25519 did:key')
    try:
        signature_bytes = base64.b64decode(signature + '=' * (-len(signature) % 4), altchars=b'-_', validate=True)
    except ValueError as exc:
        raise ValueError('Invalid signature encoding') from exc
    if len(signature_bytes) != 64:
        raise ValueError('Invalid Ed25519 signature length')
    payload = f'{room}|{nonce}|{content}'.encode('utf-8')
    Ed25519PublicKey.from_public_bytes(key[2:]).verify(signature_bytes, payload)
    # Check that the same message is present in the server-returned messages, if supplied.
    messages = receipt.get('messages')
    if messages is not None:
        if not isinstance(messages, list):
            raise ValueError('Invalid messages list')
        matches = [m for m in messages if isinstance(m, dict) and m.get('seq') == seq]
        if len(matches) != 1:
            raise ValueError('Posted sequence missing or duplicated in messages')
        for field in ('from', 'nonce', 'text', 'sig'):
            if matches[0].get(field) != posted[field]:
                raise ValueError(f'Posted and messages disagree on {field}')
    return seq, did


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', nargs='?', default='preuves', type=Path)
    parser.add_argument('--any-did', action='store_true', help='Accept other valid Ed25519 DIDs')
    args = parser.parse_args()
    if not args.folder.is_dir():
        print(f'Folder not found: {args.folder}', file=sys.stderr)
        return 2
    paths = sorted(args.folder.glob('*.json'))
    if not paths:
        print(f'No JSON receipts found in {args.folder}', file=sys.stderr)
        return 2
    passed = failed = 0
    for path in paths:
        try:
            seq, did = verify(path, None if args.any_did else EXPECTED_DID)
            print(f'OK   seq={seq}  {path.name}')
            passed += 1
        except (OSError, ValueError, KeyError, TypeError, InvalidSignature) as exc:
            print(f'FAIL {path.name}: {type(exc).__name__}: {exc}')
            failed += 1
    print(f'\nResult: {passed} valid, {failed} failed, {len(paths)} total')
    print('Note: cryptographic verification does not prove continued server availability.')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
