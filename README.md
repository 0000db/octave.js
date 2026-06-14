# Octave.js

![CI](https://github.com/0000db/octave.js/actions/workflows/ci.yml/badge.svg)

Javascript SDK for the [Octra](https://octra.org) blockchain.
You can find the npm package [here](https://www.npmjs.com/package/octave.js)

## Installation

```sh
npm install octave.js
```

## Modules

| Module | Description |
|---|---|
| `octave.js/wallet` | Key generation, HD derivation, mnemonic, keystore |
| `octave.js/tx` | Transaction builders and signing |
| `octave.js/rpc` | RPC client and all on-chain queries |
| `octave.js/program` | Compile, deploy, and call AML programs |
| `octave.js/token` | OCS-01 token interface |
| `octave.js/circle` | Circle deployment and asset uploads |
| `octave.js/bridge` | Cross-chain bridge client |
| `octave.js/units` | `parseOct` / `formatOct` and token unit helpers |
| `octave.js/crypto` | Low-level hashing, encoding, and Ed25519 primitives |

## Requirements

Node.js 20+, TypeScript 5.x, or any runtime with Web Crypto and `fetch`.

## Development

```sh
npm test       # run test suite
npm run lint   # lint
npm run build  # compile
```

## Contributing

This project is still in early development. Bug reports and feature requests are welcome via [GitHub Issues](https://github.com/0000db/octave.js/issues).

## License

[MIT](LICENSE)
