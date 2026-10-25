# ICS344 Applied Cryptography

Faisal Alsalem - 202245540

A Python command-line prototype for the Northbridge Analytics secure exchange
assignment. It includes AES-CBC and AES-CTR, HMAC-SHA256, Diffie-Hellman key
establishment, RSA-PSS signatures and a controlled CTR counter-reuse experiment.

## Quick start

```bash
python -m pip install -r requirements.txt
python run_all.py
```

The complete checks run with student ID 202245540 and save fresh results under
`evidence/`. A successful run reports 25 passing security tests and six passing
CLI checks. No private keys or passwords are included in this folder.

## Files

- `secure_exchange.py`: CLI and core cryptographic functions.
- `test_suite.py`: 25 checks, fresh non-sensitive 1031-byte file, JSON/CSV evidence.
- `cli_smoke.py`: six checks using real setup/send/receive CLI processes.
- `run_all.py`: runs both suites and writes their execution logs.
- `report.pdf`: report covering Tasks 1-6.
- `evidence/results.json`: E01-E07; expected and actual results in E05.
- `evidence/E08_cli.json`: separate command-line integration results.
- `evidence/test_run.log`: execution log, including the FFDH deprecation warning.
- `evidence/alice_sign_public.pem`: public verification key for the example envelope.
- `test_data/`: short text and fresh, randomly generated binary test file.

No private keys, key passwords, DH exponents or symmetric keys are supplied.
The archived sample envelope's temporary receiving key was destroyed after testing;
use the CLI to create a new decryptable envelope. Its signature remains independently
verifiable using `evidence/alice_sign_public.pem`.

## Environment and installation

Python 3.11+ (tested with the exact version in E01). From this directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell: activate with `.venv\Scripts\Activate.ps1` instead.
The dependency is pinned to the version used to generate the evidence.
Finite-field DH is deprecated in cryptography 50.0.2 but still works; its warning
is expected and deliberately retained. Keep this pin for this laboratory.
For future deployment, use a supported authenticated ephemeral ECDH protocol.

## Run all tests and regenerate evidence

```bash
python test_suite.py --student-id 202245540
python cli_smoke.py --student-id 202245540
```

Both commands must exit with status 0. The first reports 25/25 checks; the second
reports six successful CLI checks. A new random file is generated on every test-suite
run. Existing evidence/test data are replaced. Random public values, signatures,
IVs, ciphertexts and file hashes will change. Security properties should not.
The report describes the archived run using ID 202245540. If inputs or code change,
update the report to match the new measurements.

## Exact sender/receiver demonstration

Use a new state directory and new output filenames each time. Each command prompts
for the same strong laboratory key password (at least 12 characters). Use no real
institutional password. The same password is only a local simulation convenience;
Alice and Bob would manage their own private keys on separate computers.

```bash
python secure_exchange.py setup --state demo_state
python secure_exchange.py send --state demo_state --student-id 202245540 --input test_data/random_1031.bin --output transfer_ctr.json --mode CTR
python secure_exchange.py receive --state demo_state --student-id 202245540 --input transfer_ctr.json --output recovered_ctr.bin
python secure_exchange.py send --state demo_state --student-id 202245540 --input test_data/random_1031.bin --output transfer_cbc.json --mode CBC
python secure_exchange.py receive --state demo_state --student-id 202245540 --input transfer_cbc.json --output recovered_cbc.bin
python -c "from pathlib import Path; assert Path('recovered_ctr.bin').read_bytes()==Path('test_data/random_1031.bin').read_bytes(); assert Path('recovered_cbc.bin').read_bytes()==Path('test_data/random_1031.bin').read_bytes(); print('Both round trips match')"
```

For unattended local tests only, `ICS344_KEY_PASSWORD` may supply the password.
Do not put it in committed code or logs. `cli_smoke.py` sets a fresh random value
only in its child-process environment and deletes temporary private-key files.

To simulate two computers, use separately protected directories: Alice needs only
`alice_sign_private.pem` and Bob's trusted `bob_dh_public.pem`; Bob needs only
`bob_dh_private.pem` and Alice's trusted `alice_sign_public.pem`. The single shared
`demo_state` directory is a local teaching convenience. Transfer only the JSON
artifact over the insecure channel. Provision and verify public keys out of band;
copying an attacker-provided public key alongside its message does not establish trust.

## Manual tamper demonstration

```bash
python -c "import json; p=json.load(open('transfer_ctr.json')); p['iv']='AAAAAAAAAAAAAAAAAAAAAA=='; json.dump(p,open('tampered.json','w'))"
python secure_exchange.py receive --state demo_state --student-id 202245540 --input tampered.json --output should_not_exist.bin
```

Expected: exit 1, generic rejection, no new plaintext file. Use `cli_smoke.py` for
a repeatable ciphertext-tampering check without editing anything manually.

## Wire format and ordering

Canonical JSON (sorted keys, compact separators, ASCII); binary fields are Base64.
`version`, `label`, `student_id`, `mode`, `alice_dh`, `bob_dh`, `salt`, `iv`, and
`ciphertext` form the body. HMAC-SHA256 authenticates the entire canonical body.
RSA-PSS signs body plus tag. Signature bytes are excluded from their own input.
The receiver uses pinned local trust, validates the signature, derives keys, verifies
HMAC, and only then decrypts and removes CBC padding. All fields except the final
signature are MACed, and the signature authenticates that MAC as well.

The signature binds the encrypted file/message, including the DH context. A standalone
plaintext signature is not stored. No claim of peer liveness or replay prevention is
made. Bob's static DH key means the prototype does not provide forward secrecy
against later compromise of that key. Large files are processed in memory; this is
an arbitrary-length laboratory prototype within available memory, not a streaming tool.
CTR consumes consecutive counters from a random 128-bit initial counter; each
normal envelope has a freshly derived key. Never reuse a key/counter stream.

## Submission notes

When creating another submission archive, omit `demo_state`, `.venv`, recovered files,
and any newly generated private keys or passwords. Keep a private local working
environment for the assessor's demonstration.
