"""Secure file exchange for ICS 344. Faisal Alsalem, 202245540.

Public keys must be copied through a trusted channel before sending files.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Public parameters from RFC 3526, group 14 (2048 bits, generator 2).
P = int('''FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF'''.replace(' ', '').replace('\n', ''), 16)
PARAMS = dh.DHParameterNumbers(P, 2).parameters()
LABEL = 'ICS344-Northbridge-v1'
FIELDS = {
    'version', 'label', 'student_id', 'mode', 'alice_dh', 'bob_dh',
    'salt', 'iv', 'ciphertext',
}
SIGPAD = apad.PSS(mgf=apad.MGF1(hashes.SHA256()), salt_length=32)


def canonical(obj):
    """Use the same JSON representation when signing and verifying."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(value):
    return base64.b64decode(value, validate=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public_value(key):
    return format(key.public_key().public_numbers().y, 'x')


def peer_key(value):
    y = int(value, 16)
    # Fixed safe-prime group; exclude trivial/small-subgroup values.
    if not 2 <= y <= P - 2 or pow(y, (P - 1)//2, P) != 1:
        raise ValueError('invalid DH public value')
    return dh.DHPublicNumbers(y, dh.DHParameterNumbers(P, 2)).public_key()


def derive(shared, header):
    """Derive one AES key and one HMAC key from the DH result."""
    context = {k: header[k] for k in ('version','label','student_id','mode','alice_dh','bob_dh')}
    material = HKDF(algorithm=hashes.SHA256(), length=64,
                    salt=unb64(header['salt']), info=canonical(context)).derive(shared)
    return material[:32], material[32:]


def encrypt(data, key, mode, iv):
    if mode == 'CBC':
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        spec = modes.CBC(iv)
    elif mode == 'CTR':
        spec = modes.CTR(iv)
    else:
        raise ValueError('unsupported mode')
    ctx = Cipher(algorithms.AES(key), spec).encryptor()
    return ctx.update(data) + ctx.finalize()


def decrypt(data, key, mode, iv):
    if mode == 'CBC':
        spec = modes.CBC(iv)
    elif mode == 'CTR':
        spec = modes.CTR(iv)
    else:
        raise ValueError('unsupported mode')
    ctx = Cipher(algorithms.AES(key), spec).decryptor()
    result = ctx.update(data) + ctx.finalize()
    if mode == 'CBC':
        unpadder = padding.PKCS7(128).unpadder()
        result = unpadder.update(result) + unpadder.finalize()
    return result


def make_tag(body, key):
    ctx = hmac.HMAC(key, hashes.SHA256())
    ctx.update(canonical(body))
    return ctx.finalize()


def seal(data, mode, student_id, alice_signing, bob_public):
    """Encrypt the file, add its MAC, then sign the protected message."""
    alice = PARAMS.generate_private_key()  # Use a new DH key for each file.
    header = dict(version=1, label=LABEL, student_id=student_id, mode=mode,
                  alice_dh=public_value(alice),
                  bob_dh=format(bob_public.public_numbers().y, 'x'),
                  salt=b64(os.urandom(32)))
    enc_key, mac_key = derive(alice.exchange(bob_public), header)
    # Store the IV with the ciphertext; it does not need to be secret.
    iv = os.urandom(16)
    body = dict(header, iv=b64(iv), ciphertext=b64(encrypt(data, enc_key, mode, iv)))
    tagged = dict(body, tag=b64(make_tag(body, mac_key)))
    signature = alice_signing.sign(canonical(tagged), SIGPAD, hashes.SHA256())
    return dict(tagged, signature=b64(signature))


def open_envelope(env, bob_private, alice_public, expected_student_id):
    """Check the sender and MAC before returning any plaintext."""
    if set(env) != FIELDS | {'tag', 'signature'}:
        raise ValueError('invalid schema')
    if env['version'] != 1 or env['label'] != LABEL or env['mode'] not in ('CBC', 'CTR'):
        raise ValueError('invalid protocol header')
    if env['student_id'] != expected_student_id:
        raise ValueError('unexpected application identity')
    if env['bob_dh'] != public_value(bob_private):
        raise ValueError('wrong recipient')
    tagged = {k: v for k, v in env.items() if k != 'signature'}
    alice_public.verify(unb64(env['signature']), canonical(tagged), SIGPAD, hashes.SHA256())
    iv, salt, ct = unb64(env['iv']), unb64(env['salt']), unb64(env['ciphertext'])
    if len(iv) != 16 or len(salt) != 32 or (env['mode'] == 'CBC' and (not ct or len(ct) % 16)):
        raise ValueError('invalid lengths')
    enc_key, mac_key = derive(bob_private.exchange(peer_key(env['alice_dh'])), env)
    body = {k: env[k] for k in FIELDS}
    checker = hmac.HMAC(mac_key, hashes.SHA256())
    checker.update(canonical(body))
    checker.verify(unb64(env['tag']))  # Check the tag before decrypting or removing padding.
    return decrypt(ct, enc_key, env['mode'], iv)


def password():
    value = os.environ.get('ICS344_KEY_PASSWORD') or getpass.getpass('Private-key password: ')
    if len(value) < 12:
        raise ValueError('use a laboratory password of at least 12 characters')
    return value.encode()


def store_private(path, key, pw):
    encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(pw))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded)


def load_private(path, pw):
    return serialization.load_pem_private_key(Path(path).read_bytes(), pw)


def load_public(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def setup(folder, pw):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    # Refuse to replace identities silently.
    if any(folder.iterdir()):
        raise ValueError('setup needs a new empty directory')
    alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob = PARAMS.generate_private_key()
    for name, key in [('alice_sign', alice), ('bob_dh', bob)]:
        store_private(folder / (name + '_private.pem'), key, pw)
        (folder / (name + '_public.pem')).write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return alice, bob


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    setup_command = commands.add_parser("setup")
    setup_command.add_argument("--state", required=True)

    for command in ("send", "receive"):
        command_parser = commands.add_parser(command)
        command_parser.add_argument("--state", required=True)
        command_parser.add_argument("--student-id", required=True)
        command_parser.add_argument("--input", required=True)
        command_parser.add_argument("--output", required=True)
        if command == "send":
            command_parser.add_argument("--mode", choices=["CBC", "CTR"], default="CTR")

    args = parser.parse_args()

    try:
        key_password = password()
        state = Path(args.state)

        if args.command == "setup":
            setup(state, key_password)
            print("Created encrypted private keys and trusted public keys.")
            return

        if args.command == "send":
            plaintext = Path(args.input).read_bytes()
            signing_key = load_private(state / "alice_sign_private.pem", key_password)
            receiving_key = load_public(state / "bob_dh_public.pem")
            envelope = seal(plaintext, args.mode, args.student_id, signing_key, receiving_key)
            output = canonical(envelope) + b"\n"
        else:
            envelope = json.loads(Path(args.input).read_text())
            receiving_key = load_private(state / "bob_dh_private.pem", key_password)
            signing_key = load_public(state / "alice_sign_public.pem")
            output = open_envelope(envelope, receiving_key, signing_key, args.student_id)

        # Opening in exclusive mode avoids replacing an existing file.
        with open(args.output, "xb") as output_file:
            output_file.write(output)
        print(json.dumps({"status": "accepted", "bytes_written": len(output)}))
    except Exception:
        parser.exit(1, "Rejected: operation failed; no new output released.\n")


if __name__ == "__main__":
    main()
