"""Run: python test_suite.py --student-id YOUR_ID. No private keys are exported."""
import argparse
import copy
import csv
import json
import os
import platform
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
import secure_exchange as s


def run(student_id):
    out = Path('evidence'); out.mkdir(exist_ok=True)
    data_dir = Path('test_data'); data_dir.mkdir(exist_ok=True)
    text = (student_id + ': Northbridge results are confidential.\n').encode()
    # Fresh, non-sensitive binary data, deliberately 1031 bytes (1031 mod 16 = 7).
    binary = os.urandom(1031)
    (data_dir/'message.txt').write_bytes(text)
    (data_dir/'random_1031.bin').write_bytes(binary)
    a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    b = s.PARAMS.generate_private_key()
    tests = []
    def check(tid, prop, condition, expected, operation):
        try:
            actual, ok = operation()
        except Exception as exc:
            actual, ok = 'Unexpected '+type(exc).__name__, False
        tests.append(dict(test_id=tid, property=prop, condition=condition,
                          expected=expected, actual=actual, passed=bool(ok)))
    def rejects(fn, exception=Exception):
        try:
            fn()
        except exception as exc:
            return 'Rejected ('+type(exc).__name__+')', True
        return 'Accepted unexpectedly', False
    envelopes = {}
    comparisons = []
    tid = 1
    for name, data in [('text', text), ('binary', binary), ('empty', b''), ('aligned', b'A'*16)]:
        for mode in ('CBC','CTR'):
            env = s.seal(data, mode, student_id, a, b.public_key())
            envelopes[(name, mode)] = env
            check(f'T{tid:02}', 'round trip', f'{name}, {mode}, {len(data)} bytes', 'Exact plaintext recovered',
                  lambda env=env,data=data: ('Exact plaintext recovered', s.open_envelope(env,b,a.public_key(),student_id)==data))
            tid += 1
            if name in ('text','binary'):
                repeat = s.seal(data, mode, student_id, a, b.public_key())
                comparisons.append(dict(input=name, mode=mode, plaintext_bytes=len(data),
                    ciphertext_bytes=len(s.unb64(env['ciphertext'])), iv_bytes=len(s.unb64(env['iv'])),
                    padding_bytes=len(s.unb64(env['ciphertext']))-len(data),
                    iv_hex=s.unb64(env['iv']).hex(),
                    ciphertext_hex=s.unb64(env['ciphertext']).hex(),
                    tag_hex=s.unb64(env['tag']).hex(),
                    repeat_iv_equal=env['iv']==repeat['iv'],
                    repeat_ciphertext_equal=env['ciphertext']==repeat['ciphertext'],
                    repeat_envelope_equal=env==repeat))
    env = envelopes[('binary','CTR')]
    check('T09','repeated-message behaviour','Same plaintext; new DH, salt and IV', 'All four repeats differ',
          lambda: ('All four repeats differ', all(not x['repeat_envelope_equal'] and not x['repeat_ciphertext_equal'] for x in comparisons)))
    bad = copy.deepcopy(env); raw = bytearray(s.unb64(bad['ciphertext'])); raw[0] ^= 1; bad['ciphertext']=s.b64(raw)
    check('T10','envelope tamper','Flip one ciphertext bit; retain tag and signature','Reject',
          lambda: rejects(lambda:s.open_envelope(bad,b,a.public_key(),student_id),InvalidSignature))
    body = {k:env[k] for k in s.FIELDS}; shared = b.exchange(s.peer_key(env['alice_dh'])); ek,mk=s.derive(shared,env)
    bad_body = {k:bad[k] for k in s.FIELDS}
    def verify_mac(message, key=mk):
        ctx = hmac.HMAC(key, hashes.SHA256()); ctx.update(s.canonical(message)); ctx.verify(s.unb64(env['tag']))
    check('T11','isolated HMAC tamper','Same flip; verify MAC independently','Reject',
          lambda: rejects(lambda:verify_mac(bad_body),InvalidSignature))
    check('T12','incorrect recipient key','Different Bob DH private key','Reject',
          lambda: rejects(lambda:s.open_envelope(env,s.PARAMS.generate_private_key(),a.public_key(),student_id),ValueError))
    check('T13','incorrect HMAC key','Different 32-byte MAC key','Reject',
          lambda: rejects(lambda:verify_mac(body,os.urandom(32)),InvalidSignature))
    signed = {k:v for k,v in env.items() if k!='signature'}
    def signature_valid():
        a.public_key().verify(s.unb64(env['signature']),s.canonical(signed),s.SIGPAD,hashes.SHA256())
        return 'Signature accepted',True
    check('T14','valid signature','Unchanged signed envelope','Signature accepted',signature_valid)
    signed_bad = {k:v for k,v in bad.items() if k!='signature'}
    check('T15','modified signature input','Changed ciphertext in signed envelope','Reject',
          lambda: rejects(lambda:a.public_key().verify(s.unb64(env['signature']),s.canonical(signed_bad),s.SIGPAD,hashes.SHA256()),InvalidSignature))
    alice_dh=s.PARAMS.generate_private_key(); bob_dh=s.PARAMS.generate_private_key()
    za=alice_dh.exchange(bob_dh.public_key()); zb=bob_dh.exchange(alice_dh.public_key())
    h=dict(version=1,label=s.LABEL,student_id=student_id,mode='CTR',alice_dh=s.public_value(alice_dh),bob_dh=s.public_value(bob_dh),salt=s.b64(os.urandom(32)))
    ka,kb=s.derive(za,h),s.derive(zb,h)
    check('T16','DH and HKDF','Independent Alice/Bob calculations','Shared bytes and derived keys match',
          lambda: ('Shared bytes and derived keys match',za==zb and ka==kb))
    wrong_a=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    check('T17','untrusted signer','Different trusted RSA public key','Reject',
          lambda: rejects(lambda:s.open_envelope(env,b,wrong_a.public_key(),student_id),InvalidSignature))
    # Deliberately isolated misuse: SAME key, same messages, change ONLY second IV.
    p1=b'Known message: salary=5000; user=ALICE.'
    p2=b'Secret report: salary=9000; user=BOB!!!'
    assert len(p1)==len(p2)
    key=os.urandom(32); iv1=os.urandom(16); iv2=os.urandom(16); iv3=os.urandom(16)
    xor=lambda x,y:bytes(a^b for a,b in zip(x,y))
    c1=s.encrypt(p1,key,'CTR',iv1)
    def trial(second_iv):
        c2=s.encrypt(p2,key,'CTR',second_iv)
        recovered=xor(xor(c1,c2),p1)
        return dict(second_iv_hex=second_iv.hex(),ciphertext_2_hex=c2.hex(),
                    xor_ciphertexts_hex=xor(c1,c2).hex(),
                    xor_matches_plaintexts=xor(c1,c2)==xor(p1,p2),
                    recovered_plaintext_hex=recovered.hex(),recovered_exact=recovered==p2)
    baseline=trial(iv2); misuse=trial(iv1); correction=trial(iv3)
    check('T18','CTR baseline','Same key; distinct counter starts','Known-plaintext recovery fails',
          lambda: ('Recovery failed',not baseline['recovered_exact']))
    check('T19','CTR misuse','Only second counter start changed to first','Full second message recovered',
          lambda: ('Full second message recovered',misuse['recovered_exact'] and misuse['xor_matches_plaintexts']))
    check('T20','CTR correction','Restore fresh second counter start','Known-plaintext recovery fails',
          lambda: ('Recovery failed',not correction['recovered_exact']))
    changed_iv=copy.deepcopy(env); changed_iv['iv']=s.b64(os.urandom(16))
    check('T21','metadata tamper','Replace transmitted IV','Reject',
          lambda: rejects(lambda:s.open_envelope(changed_iv,b,a.public_key(),student_id),InvalidSignature))
    check('T22','DH validation','Public value y=1','Reject',lambda:rejects(lambda:s.peer_key('1'),ValueError))
    check('T23','identity binding','Wrong expected student label','Reject',
          lambda:rejects(lambda:s.open_envelope(env,b,a.public_key(),'WRONG'),ValueError))
    # Real encrypted-key serialization/load integration; temporary secrets deleted.
    def storage():
        with tempfile.TemporaryDirectory() as directory:
            aa,bb=s.setup(Path(directory)/'state',os.urandom(24))
            private=Path(directory)/'state/alice_sign_private.pem'
            encrypted=b'BEGIN ENCRYPTED PRIVATE KEY' in private.read_bytes()
            try:
                s.load_private(private,b'wrong-password-1234')
                return 'Wrong password accepted',False
            except (ValueError,TypeError):
                return 'Encrypted PKCS8; wrong password rejected',encrypted
    check('T24','private-key protection','Encrypted PKCS8; incorrect password','Reject private-key load',storage)
    # Hash-versus-MAC evidence. Public digests are forgeable without a secret.
    original=b'pay=100'; replacement=b'pay=900'
    forged_hash=s.digest(replacement)
    hash_evidence=dict(original=original.decode(),replacement=replacement.decode(),
        original_hash=s.digest(original),replacement_hash=forged_hash,
        unkeyed_hash_accepts_replacement=s.digest(replacement)==forged_hash,
        old_hmac_accepts_replacement=False)
    hashkey=os.urandom(32)
    hm=hmac.HMAC(hashkey,hashes.SHA256()); hm.update(original); old=hm.finalize()
    checkhm=hmac.HMAC(hashkey,hashes.SHA256()); checkhm.update(replacement)
    try:
        checkhm.verify(old); hash_evidence['old_hmac_accepts_replacement']=True
    except InvalidSignature:
        pass
    check('T25','hash versus MAC','Attacker replaces payload and unkeyed digest','Hash accepts; original MAC rejects',
          lambda:('Hash accepts; original MAC rejects',hash_evidence['unkeyed_hash_accepts_replacement'] and not hash_evidence['old_hmac_accepts_replacement']))
    dh_evidence=dict(group='RFC3526 group14',p_hex=format(s.P,'x'),p_bits=s.P.bit_length(),g=2,
        alice_public_hex=s.public_value(alice_dh),bob_public_hex=s.public_value(bob_dh),
        alice_shared_sha256=s.digest(za),bob_shared_sha256=s.digest(zb),shared_equal=za==zb,
        shared_bytes=len(za),encryption_keys_equal=ka[0]==kb[0],mac_keys_equal=ka[1]==kb[1],
        derived_encryption_and_mac_keys_distinct=ka[0]!=ka[1],
        note='Only equality checks and shared-secret hashes logged; no private exponent or derived key.')
    results={
        'E01_environment':dict(python=sys.version,platform=platform.platform(),cryptography=cryptography.__version__,utc=datetime.now(timezone.utc).isoformat(),student_id=student_id,placeholder=student_id=='STUDENT_ID_HERE',random_file_sha256=s.digest(binary),random_file_bytes=len(binary)),
        'E02_modes':comparisons,
        'E03_dh':dh_evidence,
        'E04_signed_envelope':env,
        'E05_tests':tests,
        'E06_ctr_misuse':dict(prediction='Reusing key and counter stream gives C1 XOR C2 = P1 XOR P2, allowing full recovery of equal-length P2 given P1.',controlled_change='Second CTR counter start only; key and plaintexts fixed.',plaintext_1=p1.decode(),plaintext_2=p2.decode(),first_iv_hex=iv1.hex(),ciphertext_1_hex=c1.hex(),xor_plaintexts_hex=xor(p1,p2).hex(),baseline=baseline,misuse=misuse,correction=correction,authenticity_note='Attack is passive. Adding a valid HMAC does not conceal XOR leakage.'),
        'E07_hash_vs_mac':hash_evidence,
        'summary':dict(total=len(tests),passed=sum(t['passed'] for t in tests))}
    (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    (out/'sample_ctr_envelope.json').write_bytes(s.canonical(env)+b'\n')
    (out/'alice_sign_public.pem').write_bytes(a.public_key().public_bytes(s.serialization.Encoding.PEM,s.serialization.PublicFormat.SubjectPublicKeyInfo))
    with (out/'tests.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(tests[0]));writer.writeheader();writer.writerows(tests)
    for t in tests:
        print(t['test_id'], 'PASS' if t['passed'] else 'FAIL',t['property'],':',t['actual'])
    print(json.dumps(results['summary']))
    return 0 if all(t['passed'] for t in tests) else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--student-id',required=True)
    raise SystemExit(run(parser.parse_args().student_id))
