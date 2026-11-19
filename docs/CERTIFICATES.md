# Certificates and client identity

pfapid only speaks mutual TLS 1.3. It needs three things on disk:

| File | What |
|---|---|
| `tls.cert`, `tls.key` | the server certificate (plus any intermediates) and its key |
| `tls.client_cas` | one or more **named CA bundles** that may issue client certificates |

The files are read by the root process. Every `tls.reload_interval` (default
`1m`, `0` = off) they are read again and, if they changed and are valid,
used for new connections. Rotation never needs a restart. If the new files
are broken, for example half-written or with a key that doesn't match, they
are logged and ignored, and the current material stays in use.

pfapid doesn't care where the files come from. Pick one way.

## 1. Built-in PKI (the default)

A self-signed CA that lives in `/etc/pfapid/pki`. Nothing else is needed.

```sh
pfapid pki init -dns fw.example.net -ip 192.0.2.1   # CA (10y) + server cert (397d)
pfapid pki issue -name tf-prod -out ./tf-prod        # client cert (90d), CN tf-prod
pfapid pki issue -name ci -spiffe-id spiffe://example.net/terraform/ci -out ./ci
pfapid pki renew                                     # new server key+cert, same names
```

```json
"tls": {
  "cert": "/etc/pfapid/pki/server.crt",
  "key": "/etc/pfapid/pki/server.key",
  "client_cas": { "pfapid": "/etc/pfapid/pki/ca.crt" }
}
```

Keys are ECDSA P-256 and written 0600. No file is ever overwritten, except
the server pair on `renew`, which is replaced atomically. Clients use
`ca.crt` to verify the server.

The CA key does not have to stay on the firewall. You can run `pfapid pki`
on an admin machine with `-dir`, then copy only `ca.crt`, `server.crt` and
`server.key` to the firewall.

## 2. Bring your own CA (company PKI)

There are two ways, and you can combine them.

**a. Trust your CA.** Recommended: no CA key on the firewall. Your PKI
issues the client certificates, and usually the server certificate as well.
Add your CA as a bundle:

```json
"client_cas": {
  "pfapid": "/etc/pfapid/pki/ca.crt",
  "corp":   "/etc/ssl/corp-root.pem"
}
```

**b. Let pfapid sign with your intermediate.** Issue a dedicated
intermediate CA for the firewall from your PKI, ideally with path length 0
and name constraints:

```sh
pfapid pki init  -dns fw.example.net -ca-cert corp-fw-int.crt -ca-key corp-fw-int.key
pfapid pki issue -name ops -out ./ops -ca-cert corp-fw-int.crt -ca-key corp-fw-int.key
```

The intermediate's key is used and is **not** copied into `/etc/pfapid/pki`.
Issued certificates carry the intermediate, so peers that trust only your
root can still build the chain.

## 3. Short-lived certificates from an issuer you already run

Any tool that writes PEM files and renews them works with the reload:

* **Vault PKI** via Vault Agent templates (`pki/issue/...`, TTLs of hours).
* **SPIRE** via `spiffe-helper`, which writes X509-SVIDs and the trust
  bundle to files. pfapid does not need a SPIRE agent on OpenBSD; the helper
  can run wherever the SVIDs are delivered.
* **step-ca**, **cert-manager** (for clients in Kubernetes) and similar.

## Client identity: CN or SPIFFE ID

Every client in `pfapid.json` is bound to one CA bundle (`ca`; you can leave
it out when there is only one bundle):

```json
"clients": [
  { "name": "tf-prod", "ca": "pfapid", "anchors": ["k8s-prod"] },
  { "name": "ci",      "ca": "corp", "spiffe_id": "spiffe://example.net/terraform/ci", "qos": true }
]
```

* Without `spiffe_id`, the certificate **CN** must equal `name`.
* With `spiffe_id`, **only** that SPIFFE ID matches. It is the certificate's
  single `spiffe://` URI SAN, as in an X509-SVID, and the CN is ignored.
  `name` is then just the label for logs and change history.
* Either way the certificate must chain to the client's own bundle. A
  certificate from `corp` with CN `tf-prod` is **not** the `pfapid` client
  `tf-prod`. This keeps a second CA from impersonating clients of the first.

The audit log records both the client name and what the certificate
presented (`cert=`).

## Key protection and TPMs

OpenBSD's tpm(4) only tells the chip to save its state before suspend.
There is no `/dev/tpm` and no userland TPM interface (checked on
OpenBSD 7.9). A TPM, including the Proxmox software TPM (swtpm, `tpmstate0`,
which works even on hosts without a hardware TPM), therefore **cannot
seal or hold pfapid's keys on OpenBSD**. See docs/DESIGN.md §15 for the
mitigations used instead: root-only key files, a network process that
never touches files, short certificate lifetimes, and keeping CA keys off
the firewall.
