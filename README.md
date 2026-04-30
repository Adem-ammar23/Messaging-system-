# Secure Messaging System (X3DH + Symmetric Ratchet)

This project implements a secure end-to-end encrypted messaging protocol inspired by modern systems such as Signal.

##  Features

- Asynchronous key exchange using X3DH
- End-to-end encryption with AEAD
- Forward secrecy via hash-based chain keys
- Password-protected vault for private keys
- Client-server architecture with an untrusted server model

##  Architecture

This project combines multiple technologies:

- **Toit** → client logic (send/receive/update)
- **Python** → server
- **C (DLL)** → cryptographic operations (via libsodium)


##  Cryptographic Design

The protocol is divided into two phases:

### 1. Session Establishment (X3DH)

- Uses Identity Keys, Signed Prekeys, and One-Time Prekeys
- Allows secure communication even if the receiver is offline

### 2. Message Encryption

- Chain keys (CK) derived from shared secret
- Message keys (MK) derived per message
- AEAD encryption with associated data

##  Key Derivation

For each message:
MK_i = H("MK|" || CK_i)
CK_{i+1} = H("CK|" || CK_i)
nonce_i = H("NONCE|" || CK_i || "|" || i)


## Security Properties

- Confidentiality (AEAD encryption)
- Integrity and authenticity (AD binding)
- Forward secrecy (chain key evolution)
- Asynchronous communication (X3DH)



## Report

See the full technical report in `/docs` for a thorough explanation of this project.




