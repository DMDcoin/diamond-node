# Binary releases

The [release workflow](../.github/workflows/release-binaries.yml) builds and
attests Linux amd64 and arm64 archives on manual request, then creates a draft
GitHub Release with all signed files attached. A maintainer edits the release
notes and publishes the draft when ready. Each archive contains diamond-node,
dmd, hbbft_config_generator, LICENSE, BUILD_INFO, and an internal SHA256SUMS file.

Archives use the name `diamond-node-${os}-${arch}-${semver}.tar.gz`, for example
`diamond-node-linux-amd64-4.0.3.tar.gz`. The version has no `v` prefix.

## Supported systems

Archives are built on Ubuntu 24.04, using
Rust 1.85.1. They target glibc 2.39 or newer and the C++/GCC runtime libraries (libstdc++6 and libgcc-s1 on Ubuntu).
Alpine/musl and older glibc systems are not
supported by these archives. Full workspace tests run on amd64 for the exact
tagged commit before publication. The same three programs are built for arm64.

## Download and verify

Choose the intended release tag and source commit independently. Replace REPO,
TAG, and SOURCE_SHA below with the intended repository, tag, and full source
commit. Run the commands in a fresh directory before extracting or executing
any downloaded program.

```bash
set -eou pipefail

REPO=DMDcoin/diamond-node
TAG=v4.0.3
SOURCE_SHA=REPLACE_WITH_EXPECTED_COMMIT_SHA

IDENTITY="https://github.com/$REPO/.github/workflows/release-binaries.yml@refs/tags/$TAG"

gh release download "$TAG" \
  --repo "$REPO" \
  --dir "$TAG" \
  --pattern '*.tar.gz' \
  --pattern SHA256SUMS \
  --pattern provenance.sigstore.jsonl

cd "$TAG"

for file in *.tar.gz SHA256SUMS; do
  gh attestation verify "$file" \
    --bundle provenance.sigstore.jsonl \
    --repo "$REPO" \
    --cert-identity "$IDENTITY" \
    --source-ref "refs/tags/$TAG" \
    --source-digest "$SOURCE_SHA" \
    --deny-self-hosted-runners
done

sha256sum --check --strict SHA256SUMS
```

The verification order is:

1. Download the versioned archives, SHA256SUMS, and provenance.sigstore.jsonl
   from that release.
2. Verify the attestations for both archives and SHA256SUMS with GitHub CLI,
   using the downloaded provenance bundle. Require the expected repository,
   exact workflow certificate identity at the intended tag, source ref, source
   commit SHA, and a policy denying self-hosted runners.
3. Check the downloaded archives against the verified SHA256SUMS file.

The files being checksummed and attested are the same files you downloaded.
Verification never switches from a downloaded mutable alias to a different
artifact reference. Keep the provenance bundle with the archives and checksums.

## Maintainer process

1. Set both [Cargo.toml](../Cargo.toml) and
   [the display-version manifest](../crates/util/version/Cargo.toml) to the same
   intended SemVer, including prerelease/build metadata when present.
2. Commit the change and tag that commit as v followed by the version. The
   tagged commit must contain this workflow and the shared preparation action.
   Push the tag, then explicitly request **Release binaries** for it.
   Pushing a tag or branch does not
   automatically start the workflow. The workflow creates the draft release.

   For example, to request a build after pushing the tag v4.0.3:

   ```bash
   gh workflow run release-binaries.yml --repo DMDcoin/diamond-node --ref v4.0.3
   ```

   Use the intended repository and an existing version tag. GitHub requires
   repository write access to dispatch a workflow. The workflow file must also
   exist on the default branch so GitHub can register manual requests. A request
   targeting a branch fails before checkout or build.
3. CI requires both Cargo package versions to match the v-prefixed tag.
   Checkouts use the workflow run's immutable source SHA. Stable tags enable
   the final feature; prerelease tags produce an unstable executable.
4. Both architectures must finish successfully. CI checksums the complete
   archive set, generates signed provenance for the archives and checksum file,
   and verifies the exact source identity.
5. CI creates a draft release for the existing tag and attaches all four files:
   the amd64 and arm64 .tar.gz archives, SHA256SUMS, and
   provenance.sigstore.jsonl. The draft title is the tag, its initial notes
   record the source commit, and prerelease versions are marked as pre-releases.
6. After the workflow succeeds, open **Releases**, edit the draft's title and
   notes, choose the Latest setting, and click **Publish release** when ready.
   All files are already attached. Publication does not trigger another build.

The workflow stops if a draft or published release already exists for the tag.
If an upload fails, an incomplete draft may remain. Review it and, if it is
incomplete, delete only that draft (keep the tag) before rerunning the failed
job. Wait for a successful workflow before publishing.

GitHub Release assets, including files attached to a draft, have no automatic
expiration. The per-architecture Actions artifacts used to pass archives between
jobs are temporary copies retained for 14 days; their expiry does not remove
files from the release.

## Container image releases

The [image workflow](../.github/workflows/release-image.yml) builds the same
three programs from source and publishes a multi-platform image to
`ghcr.io/<owner>/<repository>:<version>`. Linux amd64 and arm64 builds run
natively on Ubuntu 24.04 runners, using Rust 1.85.1 in a Debian Bookworm builder
and a matching Debian Bookworm runtime. `docker/github-builder` reusable workflow
handles platform distribution, caching, GHCR uploads, and the combined image manifest.
This workflow is independent of the binary release workflow and does not create or
publish a GitHub Release.

The same tag/version rules apply: both Cargo package versions must match the
existing `v<version>` tag, and only stable versions enable the `final` feature.
The image name is lowercase and its version tag omits the `v` prefix. Docker
tags cannot contain `+`, so SemVer build metadata uses `_` instead: for example,
`v4.0.3-rc.1+test.2` produces `:4.0.3-rc.1_test.2`. Only that exact version
tag is published; the workflow does not update `latest` or major/minor aliases.

Commit the Dockerfile, workflow, and shared preparation action before creating
the tag, and ensure the workflow also exists on the default branch. In GitHub,
open **Actions -> Release image -> Run workflow**, select the existing tag, and
run it.

Publication uses the repository's `GITHUB_TOKEN` with `packages: write`; no
personal access token or extra repository secret is needed. If a package with
the same name already exists, ensure this repository has Actions write access
to it. New GHCR packages are private by default.

Both architecture builds must succeed before the version tag is published.
The workflow attests the combined image digest with `actions/attest`, stores
the attestation in GitHub and GHCR, and verifies its source identity. 

### Run with your network configuration

The image starts `/app/diamond-node` with
`--config /dmd/validator.toml --no-persistent-txqueue` by default. Mount your
own configuration and chain specification at those paths; no startup command
is required. Host filenames can differ from the filenames inside the container.

In your existing `validator.toml`, update these paths while keeping the other
settings in each section:

```toml
[parity]
chain = "/dmd/spec.json"
base_path = "/dmd/data"

[misc]
log_file = "/dmd/data/diamond-node.log"
```

Keep the remaining settings for your network and validator. With both files
already present under `/srv/diamond-node` on the Docker host, create the data
directory and start the node:

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

Replace the image version with your published version. The port mappings assume
`[network].port = 30303`; adjust them to match your configuration. The two input
files are read-only, while `/dmd/data` is writable and stored directly in
`/srv/diamond-node/data` on the host. Reuse that host directory when replacing the
container to retain the chain database, default key storage, and HBBFT statistics
and default message archives. HBBFT writes those additional files under relative
`data/`, so mounting `/dmd/data` also persists them. Use a separate host data
directory for each node.

Other files referenced by `validator.toml`, such as validator keys, passwords,
and reserved peers, also need suitable container paths and mounts. Relative
paths resolve from `/dmd`. Explicit `db_path` or `keys_path` settings must
point to persistent mounted storage; they override the corresponding defaults
under `base_path`. Store file logs under `/dmd/data` if they should survive container
replacement, or omit `log_file` to use the container logs.

### Override arguments or run utilities

Arguments after the image replace all default `CMD` arguments. To use a different
configuration, provide the config path and any defaults you want to retain.
This example uses a separate host data directory for the RPC node:

```bash
sudo mkdir -p /srv/diamond-node/rpc-data

docker run --rm \
  --mount type=bind,src=/srv/diamond-node/rpc.toml,dst=/dmd/rpc.toml,readonly \
  --mount type=bind,src=/srv/diamond-node/spec.json,dst=/dmd/spec.json,readonly \
  --mount type=bind,src=/srv/diamond-node/rpc-data,dst=/dmd/data \
  ghcr.io/dmdcoin/diamond-node:4.0.3 \
  --config /dmd/rpc.toml --no-persistent-txqueue
```

Both `rpc.toml` and `spec.json` must already exist on the host. Configure
`rpc.toml` with writable data/log paths under `/dmd/data` and its chain
specification at `/dmd/spec.json`. The default executable
remains the node. To run the bundled utilities, override the entrypoint:

```bash
docker run --rm --entrypoint /app/dmd \
  ghcr.io/dmdcoin/diamond-node:4.0.3 --help

docker run --rm --entrypoint /app/hbbft_config_generator \
  ghcr.io/dmdcoin/diamond-node:4.0.3 --help
```

### Verify the image

The run summary records the published digest. To verify it, substitute the
intended tag, source commit, and digest below:

```bash
REPO=DMDcoin/diamond-node
TAG=v4.0.3
SOURCE_SHA=REPLACE_WITH_EXPECTED_COMMIT_SHA
IMAGE=ghcr.io/dmdcoin/diamond-node
DIGEST=sha256:REPLACE_WITH_PUBLISHED_DIGEST
IDENTITY="https://github.com/$REPO/.github/workflows/release-image.yml@refs/tags/$TAG"

gh attestation verify "oci://$IMAGE@$DIGEST" \
  --repo "$REPO" \
  --cert-identity "$IDENTITY" \
  --source-ref "refs/tags/$TAG" \
  --source-digest "$SOURCE_SHA" \
  --deny-self-hosted-runners
```

Use `docker login ghcr.io` first when verifying a private image. Pulling by
digest also ensures deployments keep using the exact image you verified;
rerunning this workflow for the same version can replace its image tag.
The final image digest passes directly from the reusable builder to the
attestation job; no intermediate digest artifacts are needed. Actions artifact
or cache expiration does not delete published images from GHCR.

For a local build, use `docker build -t diamond-node:local .`. For a prerelease,
pass `--build-arg FEATURES=` to omit the stable-release feature.
