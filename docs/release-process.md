# Release process

The release process separates evidence building from publication. Pull requests build and audit a complete candidate without creating a tag, package, or public release.

## Candidate gate

The `Release Candidate` workflow performs the following checks.

1. It audits Git history for private files and prohibited non-human authorship metadata.
2. It checks that the package, citation, and release versions agree.
3. It audits the locked Python environment for known vulnerabilities.
4. It builds the wheel and source distribution.
5. It regenerates the PCAP evidence through the digest-pinned Zeek container.
6. It verifies the Ed25519 ledger and packages the public evidence.
7. It generates an SPDX JSON software bill of materials and complete SHA-256 checksums.
8. It builds and runs the container as an unprivileged user with no network, capabilities, or writable root filesystem.
9. It verifies both AMD64 and ARM64 container builds.

Manual workflow runs also create and verify GitHub artifact attestations. Pull requests do not request write-capable attestation tokens.

## Publication gate

Publication is tag-only. The repository variable `APACHE_2_RELEASE_AUTHORISED` must equal `true`, and the tag must exactly match the package version as `v0.1.0`.

After both conditions are met, the workflow publishes the AMD64 and ARM64 image to GitHub Container Registry, attaches provenance and SBOM evidence, verifies every checksum, confirms anonymous access to both container architectures, and creates a GitHub pre-release.

GitHub package visibility is configured through the package settings page. The workflow does not attempt to change that account-level setting through the Packages API. For a package's first release, set its visibility to Public after the image is created and rerun the failed publication job. Later releases verify the existing public setting without using stored registry credentials.

No tag should be created until licence authority has been confirmed and the release-candidate issue is complete.

## Independent verification

Download the release assets and run the following command from their directory.

```bash
sha256sum --check SHA256SUMS
```

The wheel provenance can be checked with GitHub CLI.

```bash
gh attestation verify veritas_ai_assurance-0.1.0-py3-none-any.whl \
  --repo csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems
```

The evidence ledger remains independently verifiable with the released public key.

```bash
veritas-ai verify \
  --ledger assurance_events.jsonl \
  --public-key public_key.pem
```
