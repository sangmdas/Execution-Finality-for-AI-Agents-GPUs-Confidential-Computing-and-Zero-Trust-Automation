# Deployment Patterns and Non-Bypassability

## The rule that matters

The Finality Sink must control the **last privileged transition** from non-effective state to external effect. Putting `FinalitySink.verify()` in ordinary application code while leaving an unrestricted alternate socket/file/device/API path is not enforcement.

## Deployment patterns

| Environment | Candidate hold point | Suggested Finality Sink | What must be blocked outside sink |
|---|---|---|---|
| API / agent tools | structured tool-call object | privileged gateway / sidecar / RS | direct egress, alternate client, raw sockets |
| Storage | staged mutation / transaction intent | DB writer/proxy | direct DB credentials, alternate writer |
| Payment | unsigned/unsettled instruction | payment terminal/ledger bridge | direct settlement API/key use |
| AI output | sealed output buffer | model-output emitter / renderer | logs, debug stream, alternate UI/export |
| GPU/accelerator | non-released buffer/descriptor | DMA/IOMMU/driver/DPU boundary | alternate DMA mapping, peer-to-peer release |
| Telecom | queued packet/flow action | UPF/N6, SmartNIC/DPU, radio control | secondary egress, management bypass |
| Device/robot | staged command | protected actuator controller | raw bus/GPIO/device command path |
| Message queue | unpublished envelope | broker-side producer gateway | direct broker credentials/secondary broker |

## Hot path / cold path split

To reach sub-millisecond targets, expensive policy discovery, certificate chain validation, remote attestation collection and policy-bundle retrieval should normally occur on a **cold path**. The hot path should operate on bounded, prevalidated inputs:

1. canonical descriptor construction;
2. digest/signature or MAC verification;
3. local epoch/state lookup;
4. single-use claim;
5. effect commit.

The included Python benchmark is a correctness-oriented reference, not the implementation recommended for a 100 µs device boundary. Native code, precomputed descriptor fragments, hardware key operations, lock-free/local state or device-resident verification are appropriate for those profiles.

## Strict non-bearer deployment

Enable presenter proof-of-possession when capability theft/racing is in scope. In multi-trust-domain systems use asymmetric PoP (mTLS exporter/channel binding, DPoP-like key proof, device key, enclave key, workload key, etc.) rather than the HMAC demonstration key.

## Crash consistency

The reference burns a capability before invoking a non-transactional external effector. This prevents duplicate authorization use but can produce `consumed/no-effect` after a crash. For systems requiring recovery:

- use a durable outbox tied to the consumption transaction;
- pass `capability_id` as an idempotency/transaction key to the downstream system;
- or co-locate consumption and effect in the same atomic device/database/ledger primitive.

Never implement automatic same-capability retry after uncertainty unless the downstream effect is provably idempotent for that identifier.
