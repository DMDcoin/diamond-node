# Diamond Node

Node client for the protocol version 4 of the bit.diamonds network.

[![Build and Test][pipeline-badge]][pipeline-url] [![GPL licensed][license-badge]][license-url] [![](https://dcbadge.limes.pink/api/server/WEN5a2hqPu?style=flat)](https://discord.gg/WEN5a2hqPu)

[license-badge]: https://img.shields.io/badge/license-GPL_v3-green.svg
[license-url]: ./LICENSE

[pipeline-badge]: https://github.com/DMDcoin/diamond-node/actions/workflows/build-test.yml/badge.svg
[pipeline-url]: https://github.com/DMDcoin/diamond-node/actions/workflows/build-test.yml

## Table of Contents

1. [Description](#chapter-001)
2. [Technical Overview](#chapter-002)
3. [Building](#chapter-003)<br>
  3.1 [Building Dependencies](#chapter-0031)<br>
  3.2 [Building from Source Code](#chapter-0032)<br>
  3.3 [Starting diamond-node](#chapter-0033)
4. [Testing](#chapter-004)
5. [Documentation](#chapter-005)
6. [Toolchain](#chapter-006)
7. [Contributing](#chapter-007)
8. [License](#chapter-008)


## 1. Description <a id="chapter-001"></a>

diamond-node is the node software powering version 4 of the Diamond network.
It is running on the live network and remains under active development.

## 2. Technical Overview <a id="chapter-002"></a>

diamond-node is based on OpenEthereum and retains many of its core features.
The [upstream OpenEthereum documentation](https://openethereum.github.io/)
describes those inherited features.

By default, diamond-node runs a JSON-RPC HTTP server on port `:8545` and a WebSocket server on port `:8546`. This is fully configurable and supports a number of APIs.

If you run into problems while using diamond-node, feel free to [file an issue in this repository](https://github.com/DMDcoin/diamond-node/issues/new), or hop on our [Discord](https://discord.gg/WEN5a2hqPu) or [Telegram](https://t.me/DMDcoin) to ask a question. We are glad to help!

Tagged binary releases provide Linux amd64 and arm64 archives on
[GitHub Releases](https://github.com/DMDcoin/diamond-node/releases). Each archive
contains the node and setup utilities. See [binary releases](docs/releases.md)
for supported systems, signature verification, and the maintainer release process.

> [!WARNING]
> **ARM64 testing notice:** arm64 binary releases have not been thoroughly tested.
> Validate them in a test environment before production use.

For multi-platform Docker images published to GHCR, see
[container image releases](docs/releases.md#container-image-releases).

## 3. Building <a id="chapter-003"></a>

### 3.1 Build Dependencies <a id="chapter-0031"></a>

diamond-node requires **Rust 1.85 or newer** to build. Binary release CI uses Rust 1.85.1.

We recommend installing Rust through [rustup](https://www.rustup.rs/). If you don't already have `rustup`, you can install it like this:

- Linux:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  diamond-node also requires `clang` (>= 9.0), `clang++`, `pkg-config`, `file`, `make`, and `cmake` packages to be installed.

- OSX:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  `clang` is required. It comes with Xcode command line tools or can be installed with homebrew.

- Windows:
  Make sure you have Visual Studio 2015 with C++ support installed. Next, download and run the `rustup` installer from
  https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe, start "VS2015 x64 Native Tools Command Prompt", and use the following command to install and set up the `msvc` toolchain:
  ```bash
  $ rustup default stable-x86_64-pc-windows-msvc
  ```

Once you have `rustup` installed, then you need to install:
* [Perl](https://www.perl.org)
* [Yasm](https://yasm.tortall.net)

Make sure that these binaries are in your `PATH`. After that, you should be able to build diamond-node from source.

### 3.2 Build from Source Code <a id="chapter-0032"></a>

```bash
# Download diamond-node source code
git clone https://github.com/DMDcoin/diamond-node.git
cd diamond-node

# Build the node in release mode
cargo build --locked --release --features diamond-node/final -p diamond-node
```

This produces the executable at `./target/release/diamond-node`.
To build a specific release, check out its `v<version>` tag before building.
For prerelease builds, omit `--features diamond-node/final`.

### 3.3 Starting diamond-node <a id="chapter-0033"></a>

Prepare the `spec.json` chain specification and `validator.toml` configuration
for the network you want to join. Use your own network files; the container
does not include them.

#### Manually

From the repository root, with your `validator.toml` in that directory, start the
built node:

```bash
./target/release/diamond-node --config ./validator.toml
```

Set `[parity].chain` in `validator.toml` to the path of your `spec.json` and
`[parity].base_path` to a writable data directory. Relative paths resolve from
the current working directory. The node connects to the network defined by
your chain specification and configuration.

#### Using a container

Images for Linux amd64 and arm64 are published to
`ghcr.io/dmdcoin/diamond-node`. The image starts the node with
`--config /dmd/validator.toml --no-persistent-txqueue` by default.

Place your network files at `/srv/diamond-node/validator.toml` and
`/srv/diamond-node/spec.json` on the Docker host. In the existing
`validator.toml`, update these paths while keeping the other network settings:

```toml
[parity]
chain = "/dmd/spec.json"
base_path = "/dmd/data"

[misc]
log_file = "/dmd/data/diamond-node.log"
```

Create the host data directory and start the container. Replace `4.0.3` with
your published image version; the image workflow does not publish a `latest` tag.

```bash
sudo mkdir -p /srv/diamond-node/data

docker run -d \
  --name diamond-node \
  --restart unless-stopped \
  --mount type=bind,src=/srv/diamond-node/validator.toml,dst=/dmd/validator.toml,readonly \
  --mount type=bind,src=/srv/diamond-node/spec.json,dst=/dmd/spec.json,readonly \
  --mount type=bind,src=/srv/diamond-node/data,dst=/dmd/data \
  -p 30303:30303/tcp \
  -p 30303:30303/udp \
  ghcr.io/dmdcoin/diamond-node:4.0.3
```

No startup command is needed after the image name. The port mappings assume
`[network].port = 30303`; adjust them to match your configuration.

Data written under `/dmd/data` is stored in `/srv/diamond-node/data` on the host
and survives container replacement. This mount also persists HBBFT statistics
and default message archives written under relative `data/`. Use a separate host
data directory for each node. Configuration and specification files are mounted
read-only.

Mount any additional files referenced by your configuration, such as passwords
and reserved peers, at their configured container paths. Keep explicit
`db_path`, `keys_path`, and other writable output paths under `/dmd/data`, or
provide separate persistent mounts for them. Relative paths resolve from
`/dmd`.

See [container image releases](docs/releases.md#container-image-releases) for
argument overrides, bundled utilities, and image verification.

#### Using a `systemd` user service

Install the built binary and create directories for the service and network files:

```bash
install -Dm755 ./target/release/diamond-node "$HOME/.local/bin/diamond-node"
mkdir -p "$HOME/.config/systemd/user" "$HOME/diamond-node"
```

Place your `validator.toml` and `spec.json` in `$HOME/diamond-node`. Configure
`[parity].chain = "spec.json"` and `[parity].base_path = "data"` for this native
installation. Paths are relative to the service's working directory.

Create `~/.config/systemd/user/diamond-node.service` with:

```ini
[Unit]
Description=Diamond Node
After=network.target

[Service]
WorkingDirectory=%h/diamond-node
ExecStart=%h/.local/bin/diamond-node --config %h/diamond-node/validator.toml
Restart=on-failure
TimeoutStopSec=300

[Install]
WantedBy=default.target
```

Start the service and enable it for future user sessions:

```bash
systemctl --user daemon-reload
systemctl --user enable --now diamond-node.service
```

## 4. Testing <a id="chapter-004"></a>

Download the required test files: `git submodule update --init --recursive`. You can run tests with the following commands:

* **All** packages
  ```
  cargo test --all
  ```

* Specific package
  ```
  cargo test --package <spec>
  ```

Replace `<spec>` with one of the packages from the [package list](#package-list) (e.g. `cargo test --package evmbin`).

You can show your logs in the test output by passing `--nocapture` (i.e. `cargo test --package evmbin -- --nocapture`)

## 5. Documentation <a id="chapter-005"></a>

See [release and container documentation](docs/releases.md) for downloads,
verification, and container configuration. Run `diamond-node --help` for the
node's command-line options. The
[upstream OpenEthereum configuration reference](https://openethereum.github.io/Configuring-OpenEthereum)
covers inherited options; use the chain specification and configuration for
your Diamond network.

### Viewing documentation for diamond-node packages

Generate Rust documentation with [Cargo](https://doc.rust-lang.org/cargo/commands/cargo-doc.html).

* All workspace packages:

  ```bash
  cargo doc --workspace --document-private-items --open
  ```

* A specific package, for example the node:

  ```bash
  cargo doc --package diamond-node --document-private-items --open
  ```

Use `--document-private-items` to include private items and `--no-deps` to
exclude documentation for dependencies. Use a package name from the list below
with `--package` in `cargo doc` or `cargo test`.

<a id="package-list"></a>
<details>
<summary>Selected packages</summary>

* Node client: `diamond-node`.
* Network setup utilities: `dmd`, `hbbft_config_generator`.
* Account and key management: `ethcore-accounts`, `ethkey`, `ethkey-cli`,
  `ethstore`, `ethstore-cli`.
* Chain specification: `chainspec`.
* EVM tools and libraries: `evmbin`, `evm`, `vm`, `wasm`, `ethash`.
* Blockchain and synchronization: `ethcore`, `ethcore-blockchain`, `ethcore-db`,
  `ethcore-service`, `ethcore-sync`, `common-types`.
* Networking and contract calls: `ethcore-network`, `ethcore-network-devp2p`,
  `node-filter`, `ethcore-call-contract`.
* Consensus and mining: `ethcore-miner`, `parity-local-store`, `price-info`,
  `ethcore-stratum`, `using_queue`.
* JSON-RPC and signing: `parity-rpc`, `oe-rpc-common`, `oe-rpc-servers`,
  `cli-signer`, `parity-rpc-client`.
* Logging and JSON types: `ethcore-logger`, `ethjson`.
* Storage and utilities: `blooms-db`, `dir`, `eip-712`, `fake-fetch`, `fastmap`,
  `fetch`, `ethcore-io`, `journaldb`, `keccak-hasher`, `len-caching-lock`,
  `memory-cache`, `memzero`, `migration-rocksdb`, `panic_hook`,
  `patricia-trie-ethereum`, `rlp_compress`, `stats`, `time-utils`,
  `triehash-ethereum`, `unexpected`, `parity-version`.

</details>

## 6. Toolchain <a id="chapter-006"></a>

In addition to the diamond-node client, this repository includes:

- [dmd](./crates/ethcore/src/engines/hbbft/dmd) - node setup utilities.
- [hbbft_config_generator](./crates/ethcore/src/engines/hbbft/hbbft_config_generator) - HBBFT configuration generator.
- [evmbin](./bin/evmbin) - EVM execution tool; its executable retains the name `openethereum-evm`.
- [ethstore](./crates/accounts/ethstore) - key management library; the CLI package is `ethstore-cli`.
- [ethkey](./crates/accounts/ethkey) - key generation library; the CLI package is `ethkey-cli`.

Related tools maintained in separate upstream repositories:

- [ethabi](https://github.com/openethereum/ethabi) - ABI encoding and decoding. [Documentation](https://crates.io/crates/ethabi).
- [whisper](https://github.com/openethereum/whisper) - upstream Whisper-v2 proof of concept.

## 7. Contributing <a id="chapter-007"></a>

An introduction has been provided in the ["So You Want to be a Core Developer" presentation slides by Hernando Castano](http://tiny.cc/contrib-to-parity-eth). Additional guidelines are provided in [CONTRIBUTING](./.github/CONTRIBUTING.md).

### Contributor Code of Conduct

[CODE_OF_CONDUCT](./.github/CODE_OF_CONDUCT.md)

## 8. License <a id="chapter-008"></a>

[LICENSE](./LICENSE)
