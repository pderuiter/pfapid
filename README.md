# pfapid

REST API for OpenBSD pf. It manages pf **anchors** (`api/*`), the
contents of a fixed set of **tables**, and the firewall's **QoS** (HFSC
queues plus the `match` rules that classify into them). Everything else
stays in the base ruleset, which pfapid only reads. The Terraform provider
is [terraform-provider-pf](https://github.com/pderuiter/terraform-provider-pf)
(registry address `pderuiter/pf`).

Design and the pf behaviour it relies on: [docs/DESIGN.md](docs/DESIGN.md).

## Safety model

* **Privilege-separated.** The root process does every pfctl call. The
  HTTPS process runs as `_pfapid` under `pledge("stdio inet")` and cannot
  open files.
* **Typed objects only.** There is no raw pf.conf passthrough. Rules are
  validated, rendered, guarded (one line per rule, no `include`/`anchor`/
  macros) and checked with `pfctl -n` before they are loaded.
* **Management interface untouchable.** `mgmt` can never appear in the
  interface policy.
* **Commit-confirm.** Every change is reverted unless confirmed within
  `confirm_timeout`; a restart also reverts an unconfirmed change.
* **mTLS** (TLS 1.3) with per-client anchor and table scopes. A client is
  identified by certificate CN or SPIFFE ID, bound to its CA bundle. QoS is
  a separate `qos` grant. A `read_only` client can read and validate
  (`terraform plan`), never write.
* **QoS can only classify.** Its rules are `match` rules (no pass, block or
  NAT), and `set queue` is refused in normal anchors.

## Install

Releases ship OpenBSD binaries (amd64, arm64), built without cgo. Each
release has a `pfapid_<version>_SHA256SUMS` file with a detached GPG signature by key
`10A2F1058821D55C61E45C7EE97C02FEE2F51B23`
([scripts/release-signing-key.asc](scripts/release-signing-key.asc)).

```sh
# on a workstation with gpg; v = the latest release
v=$(curl -s https://api.github.com/repos/pderuiter/pfapid/releases/latest |
	sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
base=https://github.com/pderuiter/pfapid/releases/download/v$v
curl -sSLO $base/pfapid_${v}_openbsd_amd64.tar.gz
curl -sSLO $base/pfapid_${v}_SHA256SUMS -O $base/pfapid_${v}_SHA256SUMS.sig
curl -sSL https://raw.githubusercontent.com/pderuiter/pfapid/main/scripts/release-signing-key.asc | gpg --import
gpg --verify pfapid_${v}_SHA256SUMS.sig pfapid_${v}_SHA256SUMS
shasum -a 256 --ignore-missing -c pfapid_${v}_SHA256SUMS
```

On the firewall, as root, from the unpacked archive:

```sh
useradd -s /sbin/nologin -d /var/empty -L daemon -c "pfapid network process" _pfapid
install -o root -g wheel -m 0555 pfapid /usr/local/sbin/pfapid
install -o root -g wheel -m 0555 deploy/rc.d/pfapid /etc/rc.d/pfapid
install -d -o root -g wheel -m 0700 /etc/pfapid /var/db/pfapid
install -d -o root -g wheel -m 0755 /etc/pf.anchors/api
for f in api.conf api-queues.conf api-qos.conf; do
	[ -f /etc/pf.anchors/$f ] || install -o root -g wheel -m 0600 /dev/null /etc/pf.anchors/$f
done
pfapid pki init -dns fw.example.net -ip 192.0.2.1   # or bring your own certificates
install -o root -g wheel -m 0600 deploy/pfapid.json.example /etc/pfapid.json   # then edit it
# add the base ruleset hooks below to /etc/pf.conf, then:
pfctl -nf /etc/pf.conf && pfctl -f /etc/pf.conf
pfapid -f /etc/pfapid.json -n      # check the configuration
rcctl enable pfapid && rcctl start pfapid
```

Keep a way back in before you load a new base ruleset (console access, or
an `at` job that restores the previous file).

## Usage

```sh
# create (If-None-Match: *) -> 202 + change id; the change is live but pending
curl --cert c.crt --key c.key --cacert ca.crt -X PUT -H 'If-None-Match: *' \
  https://fw:8443/v1/anchors/k8s-prod -d @rules.json
# confirm within confirm_timeout, or it is rolled back
curl ... -X POST https://fw:8443/v1/changes/<id>/confirm
# updates and deletes need If-Match: "<etag from GET>"
```

## Certificates

The built-in PKI is the default; a company CA, Vault, SPIRE and similar
issuers also work. Certificates are reloaded without a restart.

```sh
pfapid pki init -dns fw.example.net -ip 192.0.2.1
pfapid pki issue -name tf-prod -out ./tf-prod
```

Everything else (bring your own CA, SPIFFE IDs, rotation, why there is no
TPM): [docs/CERTIFICATES.md](docs/CERTIFICATES.md).

API contract: [api/openapi.yaml](api/openapi.yaml) (a unit test keeps it in step with the router).
Example configuration: [deploy/pfapid.json.example](deploy/pfapid.json.example).

## Base ruleset requirements

```pf
table <k8s_nodes> persist          # managed tables: declared EMPTY + persist
table <rfc1918> const { 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 }
                                   # policy.ref_tables: rules may name it, pfapid never fills it
pass in quick on mgmt ...          # management before the anchors
# QoS (only if policy.queue_interfaces is set): pfapid writes both files
# and applies a QoS change by reloading this file.
include "/etc/pf.anchors/api-queues.conf"
anchor "api-qos"
load anchor "api-qos" from "/etc/pf.anchors/api-qos.conf"
anchor "api/*"
include "/etc/pf.anchors/api.conf" # generated by pfapid: load anchor lines
```

The included files must exist before pf.conf is loaded (an empty file is
fine); the install steps above create them.

## Development

```sh
go test -race ./...
GOOS=openbsd go vet ./...
go test -run='^$' -fuzz=FuzzAnchor -fuzztime=60s ./internal/render
GOOS=openbsd GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/pfapid
```

Integration tests against real pfctl need an OpenBSD machine; CI runs on
Linux and covers everything else (unit tests with a fake pfctl, renderer
fuzzing, `GOOS=openbsd` vet).

## Releases

GitLab is the source of truth; GitHub is a mirror. A merge to `main` tags
`vX.Y.Z` from the Conventional Commits since the last tag, and the tag
pipeline builds, signs (GPG and cosign), stores the release and publishes it
on GitHub. See [RELEASING.md](RELEASING.md).

## License

ISC, see [LICENSE](LICENSE).
