# technocore-proof-verifier
Verify Ed25519 signatures of Technocore JSON message receipts.
# Technocore Proof Verifier

A Python tool to independently verify Ed25519 signatures in Technocore JSON message receipts.

## Features

- Verify message signatures using public DID keys
- Check the integrity of signed message content
- Verify multiple JSON receipts automatically
- No private key or passphrase required

## Requirements

- Python 3.10+
- cryptography

## Installation

```bash
git clone https://github.com/lo-loran/technocore-proof-verifier.git
cd technocore-proof-verifier
python -m pip install cryptography
```

## Usage

Create a folder named `preuves` and place your Technocore JSON receipts inside it.

```bash
python verify_technocore.py
```

The script reports valid and invalid signatures and displays a summary.

## Security

Never upload your private key, seed phrase, passphrase or encrypted identity file.

A valid signature proves message authenticity and integrity, not continued server availability.

## License

MIT
