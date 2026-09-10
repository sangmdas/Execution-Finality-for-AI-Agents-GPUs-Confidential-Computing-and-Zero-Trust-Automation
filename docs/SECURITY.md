# Security Guidance

## Production hardening checklist

- Separate authority-signing, presenter-PoP and sink-receipt keys.
- Prefer asymmetric keys backed by HSM/TEE/secure element/device root across trust domains.
- Make the sink's local identity and boundary identity unforgeable from the caller's privilege level.
- Store replay/nonce/epoch state in rollback-resistant durable storage.
- Bound descriptor and payload sizes before canonicalization.
- Reject unsupported encodings and ambiguous numbers rather than normalizing them silently.
- Make policy epoch rollout monotonic and fail closed on unknown epochs.
- Route every externally effective channel through a privileged sink; deny default egress elsewhere.
- Treat logs, telemetry, clipboard, print, debug ports, shared memory and DMA as potential effect channels when they carry protected outputs.
- Keep the Finality Sink TCB small and observable; use measured boot/attestation where available.
- Use transaction/idempotency primitives of the target system rather than inventing weaker generic substitutes.
- Do not reuse a capability after uncertain effect status.

## Key separation

The implementation accepts a distinct `receipt_authenticator` for sink receipts. This prevents an ordinary sink receipt key from automatically becoming an authority-capability minting key. Strict non-bearer mode uses a third presenter key.

## Vulnerability reporting

When publishing this repository, add a project-specific security contact and disclosure policy. Do not publish real production keys, attestation secrets, customer endpoints or infrastructure topology in issues/tests.
