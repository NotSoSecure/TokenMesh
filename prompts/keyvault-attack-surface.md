# Key Vault Attack Surface

> Copy-paste these into Claude Desktop or CLI mode to hunt Key Vault
> misconfigurations, backdoor persistence, and data-plane exfiltration paths.

---

### Soft-delete / purge-protection posture

```
Check every Key Vault in this subscription for hardening gaps: soft-delete
disabled, purge protection missing, legacy access-policy mode, public
network access. Rank by number of issues.
```

---

### Dangling access policies (deleted-principal persistence)

```
Audit Key Vault access policies. Flag any policy whose objectId no longer
resolves in Microsoft Graph — that's the deleted-principal persistence
pattern. Include the vault name, permissions granted, and MITRE technique.
```

---

### Service principals with Key Vault Administrator or Officer

```
Which service principals hold Key Vault Administrator, Key Vault Secrets
Officer, or Key Vault Crypto Officer at any scope? These are data-plane
compromise primitives — one code-exec on the SP owner reads every secret.
```

---

### Legacy Key Vault Contributor self-grant path

```
Find any principal with Key Vault Contributor on a vault where
enableRbacAuthorization=false. That combo is a classic self-service
privilege escalation — the Contributor can rewrite accessPolicies to grant
itself data-plane access. Include the vault and MITRE T1098.003.
```

---

### Secrets / keys without expiry

```
List all Key Vault secrets, keys, and certificates whose expiration is null
or more than two years in the future. Long-lived vault objects are the
persistence primitive attackers exfil first.
```

---

### HSM-key export or sign abuse

```
Which identities can export or sign with HSM-protected keys? I need to see
Key Vault Crypto Officer and Crypto User assignments and the specific
vault + key IDs — treating this as a supply-chain / code-signing risk.
```

---

### Public-network vault + no private endpoint

```
Which vaults have publicNetworkAccess=Enabled and zero private endpoint
connections? These are internet-reachable secret stores. Flag with
KQL detection signals for data-plane access from unexpected IPs.
```

---

### Cross-tenant access policy

```
Are any Key Vault access policies for objectIds in a different tenant
than the vault's tenantId? Cross-tenant vault trust is rare and usually
means a partner-tenant integration — or a planted backdoor.
```

---

[Back to TokenMesh README](../README.md)
