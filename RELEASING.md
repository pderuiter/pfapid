# Releasing

Releases are automated: merge to `main`, and the pipeline tags, builds,
signs, stores and publishes. GitLab (`wbyc/infra/pfapid`) is the source of
truth; github.com/pderuiter/pfapid is a mirror. The flow is the one the
pderuiter Terraform providers use (see terraform-provider-pf's RELEASING.md),
without the Registry steps.

```
MR merged to main
  └─ main pipeline: tests ─┬─ mirror:github   main → github.com/pderuiter/pfapid
                           └─ release:tag     vX.Y.Z from Conventional Commits (ci-cd-toolkit)
tag pipeline (vX.Y.Z)
  └─ tests ── build:release   GoReleaser (build only): openbsd amd64/arm64 tar.gz, SHA256SUMS
               ├─ sign:gpg     SHA256SUMS.sig (release key, from Vault)
               └─ sign:cosign  *.sigstore.json (estate cosign key, Vault transit)
             publish:nexus     → nexus.bsdserver.nl/repository/software-packages/pfapid/<version>/
             publish:github    fetch from Nexus, verify checksums + signature, mirror tag,
                               draft release + assets → publish, GitLab release
```

## Versions

Semantic Versioning, computed by `release:tag` from the commits since the
last tag: `type!:` or `BREAKING CHANGE:` → major, `feat:` → minor, anything
else → patch. Breaking for pfapid: an API change that breaks the provider or
other clients, a configuration key removed or renamed, a default that changes
what the firewall does. While on 0.x these still get a `!`.

## Published versions are immutable

Never delete and re-push a tag or edit a GitHub release's assets.
`publish:nexus` fails when a stored file differs from a rebuild,
`publish:github` refuses to overwrite a tag GitHub has at another commit and
never edits a published release. A broken release gets fixed by the next
patch version.

## Secrets and access

| What | Where |
|---|---|
| GPG signing key | Vault `secret/wbyc/prd/infra/terraform-registry/gpg` (the key that signs the pderuiter providers; public half in `scripts/release-signing-key.asc`, `sign:gpg` refuses any other key) |
| GitHub token | Vault `secret/wbyc/prd/infra/github/pderuiter` `token` (shared fine-grained PAT; pfapid is in its repository list) |
| Nexus upload | Vault `secret/prod/nexus/ci-publish` |
| cosign | Vault transit key `cosign-estate` |
| Vault login | JWT role `gitlab-ci-terraform-registry` (`RELEASE_VAULT_ROLE`), bound to this project's protected refs |

## One-time setup

1. GitHub: public, empty repo `pderuiter/pfapid`.
2. GitHub token: add `pfapid` to the shared PAT's repository list.
3. Vault: project 316 in the `bound_claims` of JWT role
   `gitlab-ci-terraform-registry` (terragrunt-live prd/security/vault-jwt-auth).
4. GitLab: 316 in `projects` and `signing_project_ids` of terraform-gitlab-config
   (Maintainer-only merge, `v*` tags protected).
