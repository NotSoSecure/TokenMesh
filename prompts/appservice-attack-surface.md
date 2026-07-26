# App Service Attack Surface

> Copy-paste these into Claude Desktop or CLI mode to hunt Web App and
> Function App misconfigurations, backdoors, and code-execution paths.
> App Service is where developers stash secrets in plaintext, where
> Kudu SCM hands out container shells, and where the MicroBurst
> `Get-AzPasswords` playbook harvests publishing profiles.

---

### Kudu SCM / FTP basic-auth exposure (MicroBurst web-shell primitive)

```
Check every App Service site for Kudu SCM basic auth enabled or FTP
basic auth enabled. Either combo is the MicroBurst web-shell primitive:
publishing profile → container shell via /api/zipdeploy or /api/command.
MITRE T1505.003. Include CIS Azure control IDs.
```

---

### App Service managed identity subscription takeover

```
Find every App Service whose managed identity holds Owner, Contributor,
or User Access Administrator at subscription-or-higher scope. Any Kudu
access or malicious deployment inherits the MI's permissions — that's a
subscription takeover path. MITRE T1552.005 → T1098.003.
```

---

### Plaintext secrets in app settings

```
Enumerate app settings across every App Service. Flag any setting whose
name suggests it holds a secret (connection strings, passwords, API keys,
access keys, tokens, client secrets) but is NOT a @Microsoft.KeyVault(...)
reference. These are plaintext secrets that any Kudu-authenticated caller
can read. MITRE T1552.001. CIS Azure 9.13.
```

---

### App Service hardening posture

```
Full App Service hardening audit: HTTPS-only off, min TLS < 1.2, FTP
publishing accepted, publicNetworkAccess=Enabled, remote debugging on,
wildcard CORS. Rank sites by number of issues, include CIS Azure
control IDs for each.
```

---

### Function App host keys / master keys

```
Function Apps expose function-level and master keys that grant HTTP
invocation without any Entra auth. Enumerate every function app in the
subscription. Which ones have host-level (master) keys with no rotation
schedule? Include the site name, function count, and CIS mapping.
```

---

### Persistent SCM access after breach

```
I'm doing post-incident review. Which App Service sites have publishing
credentials — SCM basic auth, FTP basic auth, or long-lived deployment
identities — that survive a full credential rotation? These are the
persistence artifacts I need to purge.
```

---

### App Service + Key Vault reference audit

```
For each App Service, count how many app settings are Key Vault references
(@Microsoft.KeyVault) vs plaintext values. Sites with mostly plaintext
values need a Key Vault migration. Include the target Key Vault name if
detectable and CIS Azure 9.13 mapping.
```

---

[Back to TokenMesh README](../README.md)
