# noir-ed25519

> [!WARNING]
> This implementation is unaudited and not intended for production use at this time

Implementation of Ed25519 signature verification over variable length messages. Based on [noir-edwards-bignum](https://github.com/willemolding/noir-edwards-bignum/)

The implementation is compatible with the [IRTF RFC-8032](https://www.ietf.org/rfc/rfc8032.txt) instantiation of edDSA over Ed25519. Noir tests cover all test vectors from this specification. 

Compatible with Noir 1.0.0 and later

For example usage see `test.nr`

## Benchmarks

> [!IMPORTANT]
> Ed25519 is not efficient for Barretenberg proving. If you can use another signature algorithm you should.

Circuit cost of a single `ed25519_verify` call by maximum message length. The
SHA-512 hash of the message preimage is the main driver of the growth with
message size.

| Max message length | ACIR opcodes | Circuit size (gates) |
| -----------------: | -----------: | -------------------: |
| 32 bytes           |       66,001 |              228,192 |
| 128 bytes          |       79,633 |              257,588 |

Reproduce with `./scripts/build-gates-report.sh` (requires `nargo`, `bb`, and
`jq`). Benchmark entry points live in `src/benchmarks/`.
