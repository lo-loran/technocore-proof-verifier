# Verifying Signed Technocore Contributions

## Purpose

This guide explains how to independently verify a signed Technocore message and its public contribution receipt without exposing the contributor's private key.

## 1. Understand what a signature proves

An Ed25519 signature can demonstrate that a message was signed by the holder of a particular private key and that the signed content has not been altered.

A valid signature does not, by itself, establish a real-world identity, prove that a contribution is original, or guarantee eligibility for an airdrop.

## 2. Protect the private key

- Never publish or send your private key or passphrase.
- Derive and share only the public DID when needed.
- Perform signature verification with the public key.
- Keep private identity files encrypted and backed up securely.

## 3. Verify the signed message

The signed payload is reconstructed as:

`room|nonce|text`

The verifier checks the Ed25519 signature against the exact room, nonce, and text contained in the receipt. The text must match the content that was originally signed. The verifier does not independently enforce the server's whitespace-normalization rules.

## 4. Check the public receipt

A receipt should identify the room, the posted message sequence, the public DID, the nonce, and the message content or signature.

Where the public message is available, compare its sequence, DID, nonce, text, and signature with the receipt. A mismatch should be treated as a verification failure.

The verifier checks that the posted sequence, DID, nonce, text, and signature match exactly one corresponding message when a `messages` list is included in the receipt.

## 5. Handle uncertainty safely

If a publication request times out, do not immediately send it again. Read the room and look for the same DID and nonce first. This helps avoid accidental duplicate submissions.

A successful local test proves that the verifier behaves as tested; it does not guarantee that a remote server will accept a publication.

## Scope and limitations

This guide describes verification principles and the protocol format used by the project. Before relying on a receipt, check the current official protocol and use a maintained verifier with tests.

A valid receipt is evidence of message integrity and key control, not proof of contribution quality or a promised reward.