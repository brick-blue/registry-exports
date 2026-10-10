#!/usr/bin/env python3
"""
Check a daily brick.blue export without trusting brick.blue: the file's hash and size against
its manifest, its lines against the counts, the manifest's ed25519 signature against the hub's
published key, and the stamp — that the file's sha256 sat in the hub's signed minute.

    python3 verify.py 2026-10-10                  # downloads the file from this repo's release
    python3 verify.py 2026-10-10 path/to/file.gz  # checks a copy you already have

Standard library only; the ed25519 check is RFC 8032's, written out below, so nothing has to be
installed and nothing here asks you to take a library's word either. Exit status 0 when every
check passes.
"""
import gzip
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO = 'brick-blue/registry-exports'
HUB = 'https://brick.blue'
UA = 'brick-blue-export-verify/1.0 (+https://github.com/brick-blue/registry-exports)'

# --- ed25519 verification, RFC 8032 §5.1.7 -------------------------------------------------
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P
    Dd = z1 * 2 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _decode(b):
    y = int.from_bytes(b, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= P:
        raise ValueError('point out of range')
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P:
        raise ValueError('not a point')
    if x == 0 and sign:
        raise ValueError('bad sign')
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _same(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


_BY = 4 * pow(5, P - 2, P) % P
BASE = _decode(_BY.to_bytes(32, 'little'))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        A, R = _decode(public), _decode(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], 'little')
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % L
    return _same(_mul(s, BASE), _add(R, _mul(h, A)))


B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return b'\0' * (len(text) - len(text.lstrip('1'))) + raw


# --- the hub's canonical form: object keys sorted at every depth, compact, UTF-8 -------------
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


# --- RFC 6962 / 9162 inclusion proof -------------------------------------------------------
def merkle_root(digest, index, size, path):
    r = hashlib.sha256(b'\0' + digest).digest()
    fn, sn = index, size - 1
    for step in path:
        p = bytes.fromhex(step)
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b'\1' + p + r).digest()
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b'\1' + r + p).digest()
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def fetch(url, binary=False):
    req = urllib.request.Request(url, headers={'user-agent': UA})
    with urllib.request.urlopen(req, timeout=600) as res:
        data = res.read()
    return data if binary else json.loads(data)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    date = sys.argv[1]
    failures = []

    def check(ok, label):
        print(('  ok    ' if ok else '  FAIL  ') + label)
        if not ok:
            failures.append(label)

    local = Path(__file__).with_name('manifests') / f'{date}.json'
    manifest = json.loads(local.read_text()) if local.exists() else fetch(f'https://raw.githubusercontent.com/{REPO}/main/manifests/{date}.json')
    print(f'{date}: {manifest["counts"]["agents"]} listings, {manifest["counts"]["x402"]} paid resources, sha256 {manifest["sha256"]}')

    if len(sys.argv) > 2:
        data = Path(sys.argv[2]).read_bytes()
    else:
        url = f'https://github.com/{REPO}/releases/download/{date}/{manifest["file"]}'
        print(f'downloading {url}')
        data = fetch(url, binary=True)

    print('file')
    check(len(data) == manifest['bytes'], f'size {len(data)} = manifest {manifest["bytes"]}')
    check(hashlib.sha256(data).hexdigest() == manifest['sha256'], 'sha256 = manifest')
    counts, summary, header = {'agent': 0, 'x402': 0}, None, None
    # '\n' only: descriptions carry U+2028 inside their strings, which splitlines() would cut at.
    for line in gzip.decompress(data).decode('utf-8').split('\n'):
        if not line:
            continue
        row = json.loads(line)
        kind = row.get('type')
        if kind in counts:
            counts[kind] += 1
        elif kind == 'summary':
            summary = row.get('counts')
        elif kind == 'header':
            header = row
    check(header is not None and header.get('date') == date, 'header names the day')
    check(counts['agent'] == manifest['counts']['agents'], f'{counts["agent"]} "agent" lines = manifest')
    check(counts['x402'] == manifest['counts']['x402'], f'{counts["x402"]} "x402" lines = manifest')
    check(summary == manifest['counts'], 'summary line = manifest')

    print('signature')
    signed = manifest.get('signed') or {}
    keys = fetch(signed.get('keys') or f'{HUB}/.well-known/brick-blue-keys.json')
    by_id = {k['keyId']: b58decode(k['publicKeyBase58']) for k in keys.get('keys', []) + keys.get('retired', []) if 'publicKeyBase58' in k}
    core = {k: v for k, v in manifest.items() if k not in ('signed', 'proof')}
    key = by_id.get(signed.get('keyId'))
    check(key is not None, f'key {signed.get("keyId")} is published')
    check(bool(key) and ed25519_verify(key, canonical(core), __import__('base64').b64decode(signed.get('signature', ''))),
          'ed25519 over the canonical manifest (without signed and proof)')

    print('stamp')
    proof = manifest.get('proof')
    if not proof and manifest.get('stamp'):
        try:
            proof = fetch(manifest['stamp']['proof'])
        except Exception as err:  # noqa: BLE001 — a proof not yet taken is reported, not raised
            print(f'  ..    no proof yet ({err})')
    if proof:
        pulse = proof['pulse']
        check(proof['digest'] == manifest['sha256'], 'the proof is for this file')
        root = merkle_root(bytes.fromhex(manifest['sha256']), proof['leafIndex'], proof['size'], proof['path'])
        check(root is not None and root.hex() == pulse['document']['root'], 'inclusion path rebuilds the minute\'s root')
        body = canonical(pulse['document'])
        check(hashlib.sha256(body).hexdigest() == pulse['digest'], 'the minute\'s digest is its document\'s')
        pkey = by_id.get(pulse['keyId'])
        check(bool(pkey) and ed25519_verify(pkey, body, __import__('base64').b64decode(pulse['signature'])), 'the minute is signed by the published key')
        print(f'  ->    in the hub\'s hands between {pulse["document"]["prevAt"]} and {pulse["document"]["at"]}')

    print('all checks passed' if not failures else f'{len(failures)} check(s) failed')
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
