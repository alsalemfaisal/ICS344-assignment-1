# ICS344 Applied Cryptography - Secure Exchange

Faisal Alsalem - 202245540

This is a command-line Python prototype for the Northbridge Analytics secure exchange
assignment. Alice encrypts and signs a file, the protected file is saved as JSON, and
Bob checks it and recovers the original. It uses:

- AES-256 in CBC and CTR mode
- HMAC-SHA256 for integrity
- Diffie-Hellman (RFC 3526 group 14) with HKDF to derive the keys
- RSA-PSS signatures
- a CTR nonce-reuse experiment for Task 3

## Files

- `secure_exchange.py` - the program (setup, send, receive) and all crypto functions
- `test_suite.py` - 25 security tests, writes results to `evidence/`
- `cli_smoke.py` - 6 checks that run the real setup/send/receive commands
- `run_all.py` - runs both of the above and saves the logs
- `report.pdf` - the report (Tasks 1-6)
- `test_data/` - a short text message and a random 1031-byte file
- `evidence/` - results from the last run:
  - `results.json` - evidence items E01-E07 (E05 is the test table)
  - `tests.csv` - the same test table as CSV
  - `E08_cli.json` - command-line check results
  - `test_run.log`, `cli_run.log` - console output
  - `sample_ctr_envelope.json` and `alice_sign_public.pem` - an example protected
    message and the public key that verifies its signature

No private keys, passwords or symmetric keys are included. The private key for the
sample envelope was deleted after the run, so it can only be signature-checked, not
decrypted. Use the commands below to make a new one.

## Setup

Needs Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`cryptography` is pinned to 50.0.2, the version used for the evidence. This version
prints a deprecation warning for finite-field Diffie-Hellman. It still works and the
warning is expected.

## Running the tests

```bash
python run_all.py
```

or run each part on its own:

```bash
python test_suite.py --student-id 202245540
python cli_smoke.py --student-id 202245540
```

You should see 25/25 tests passing and 6 CLI checks passing. Each run generates a new
random test file and replaces the files in `evidence/`. Random values (keys, IVs,
ciphertexts, signatures) change on every run, but the pass/fail results should not.

## Sender and receiver

Each command asks for a password for the private keys (at least 12 characters).
Use the same one for all commands and use a new state folder each time.

```bash
python secure_exchange.py setup --state demo_state

python secure_exchange.py send --state demo_state --student-id 202245540 --input test_data/random_1031.bin --output transfer_ctr.json --mode CTR
python secure_exchange.py receive --state demo_state --student-id 202245540 --input transfer_ctr.json --output recovered_ctr.bin

python secure_exchange.py send --state demo_state --student-id 202245540 --input test_data/random_1031.bin --output transfer_cbc.json --mode CBC
python secure_exchange.py receive --state demo_state --student-id 202245540 --input transfer_cbc.json --output recovered_cbc.bin
```

Check that both recovered files match the original:

```bash
python -c "from pathlib import Path; o=Path('test_data/random_1031.bin').read_bytes(); assert Path('recovered_ctr.bin').read_bytes()==o and Path('recovered_cbc.bin').read_bytes()==o; print('Both round trips match')"
```

For automated runs you can set the password in the `ICS344_KEY_PASSWORD` environment
variable instead of typing it. `cli_smoke.py` does this with a random password.

Note: `demo_state` holds both Alice's and Bob's keys only so the demo runs on one
computer. In a real setup Alice keeps `alice_sign_private.pem` and Bob's public key
`bob_dh_public.pem`; Bob keeps `bob_dh_private.pem` and Alice's public key
`alice_sign_public.pem`. Only the JSON file goes over the insecure channel. Public keys
have to be exchanged and checked beforehand, not sent along with the message.

## Tampering demo

```bash
python -c "import json; p=json.load(open('transfer_ctr.json')); p['iv']='AAAAAAAAAAAAAAAAAAAAAA=='; json.dump(p,open('tampered.json','w'))"
python secure_exchange.py receive --state demo_state --student-id 202245540 --input tampered.json --output should_not_exist.bin
```

This should print `Rejected` and exit with code 1, without creating
`should_not_exist.bin`. `cli_smoke.py` runs a similar check on the ciphertext.

## Message format

The protected file is JSON with sorted keys and no extra spaces, so both sides
compute the MAC and signature over the same bytes. Binary values are Base64.

- The body is `version`, `label`, `student_id`, `mode`, `alice_dh`, `bob_dh`, `salt`,
  `iv` and `ciphertext`.
- `tag` is HMAC-SHA256 over the whole body (encrypt-then-MAC).
- `signature` is RSA-PSS over the body plus the tag.

Bob checks the signature first, then derives the keys, checks the HMAC, and only then
decrypts (and removes the CBC padding).

## Limitations

- Bob's DH key is static, so there is no forward secrecy if it is stolen later.
- There is no replay protection; an old valid message would be accepted again.
- Files are read into memory, so very large files are not supported.

## Submission

Leave out `demo_state`, `.venv`, recovered files and any private keys or passwords
when creating the submission zip.
