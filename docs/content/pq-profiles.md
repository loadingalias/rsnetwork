# Choose a TLS key-exchange profile

The default profile offers hybrid post-quantum key exchange and works with X25519 peers.
Choose the strict profile when every connection must use hybrid key exchange.
TLS over TCP and QUIC use the same client and server configurations. [Configure TLS](tls.md#configure-each-end)

| `KeyExchangeProfile` | Client offer | Server choice |
| --- | --- | --- |
| `Default` | X25519MLKEM768 first, then X25519. The initial ClientHello includes a key share for each. | Prefer X25519MLKEM768. Request its key share if the client advertised the group without sending its share. Accept X25519 from a classical-only offer. |
| `Strict` | X25519MLKEM768 only. | Require X25519MLKEM768. A classical-only peer cannot complete the handshake. |
| `Classical` | X25519 only. | Require X25519. Select this profile explicitly for connections that require classical key exchange. |

## Require hybrid key exchange

`ClientConfig::new` and `ServerConfig::new` use `Default`. Pass the profile when you create a configuration for another policy.
Keep the same trust roots, identity, and certificate clock that you use for the endpoint.

```rust
use rsnetwork::drive::Error;
use rsnetwork::tls::{ClientConfig, ClientOptions, KeyExchangeProfile};

fn strict_client(options: ClientOptions<'_>) -> Result<ClientConfig, Error> {
    ClientConfig::with_key_exchange(options, KeyExchangeProfile::Strict)
}
```

For a server, use `ServerConfig::with_key_exchange(options, KeyExchangeProfile::Strict)`.
Give the configuration to the TLS stream, HTTP client or server, or QUIC connection.
If the peer offers no common group, the handshake fails with `Kind::Unsupported`. Use a peer that supports the required group.

## Read the result

Read `negotiated()` after the handshake. On a Tokio TLS stream, await `handshake()` to get the same report.
`group` names the actual group. Its display text is `X25519MLKEM768` or `X25519`.
For X25519, `classical_selection` explains the choice.

| `classical_selection` | What this end observed |
| --- | --- |
| `Some(ClassicalSelection::PeerSelected)` | This default client offered both groups. The server selected X25519. The server's other capabilities remain unknown. |
| `Some(ClassicalSelection::NoHybridOffer)` | This default server received an offer without X25519MLKEM768. |
| `Some(ClassicalSelection::ExplicitProfile)` | This end's caller required X25519. |
| `None` | The connection negotiated X25519MLKEM768. |

A HelloRetryRequest asks for a missing key share and costs another round trip. A completed handshake that used it reports `Handshake::Retried`. [TLS 1.3 key shares](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8)

Read `peer.authentication` separately. For example, a strict client can negotiate X25519MLKEM768 with a server authenticated by an ECDSA P-256 certificate.
Its report contains `Group::X25519_MLKEM768` and `Authentication::EcdsaP256`. [Negotiated TLS facts](tls.md#negotiated-facts)
