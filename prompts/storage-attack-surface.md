# Storage Attack Surface

> Copy-paste these into Claude Desktop or CLI mode to audit Azure Storage accounts for security misconfigurations.

---

### Public blob access detection

```
Find all storage accounts with public blob access enabled.
Give me the account name, resource group, and region — I want to manually
enumerate the containers for sensitive data exposure.
```

---

### TLS and HTTP downgrade vectors

```
Audit all storage accounts for weak TLS (TLS 1.0 or 1.1) and HTTP access.
These are downgrade attack vectors.
```

---

### Combined storage risk ranking

```
Give me a combined storage risk report: public access + weak TLS + no HTTPS.
Rank by number of issues per account — most vulnerable first.
```

---

### Network-open storage accounts

```
Which storage accounts have their network default action set to "Allow"?
These are accessible from any network and could be exfiltration targets.
```

---

### Full storage inventory

```
List all storage accounts in this subscription with their full security
configuration: TLS version, HTTPS enforcement, public access setting,
network rules, and SKU. I need a complete inventory.
```

---

### Data exfiltration risk assessment

```
Identify all storage accounts that an attacker could use for data
exfiltration — public access enabled OR network rules set to Allow.
For each one, tell me what data could be at risk based on the
resource group and account name.
```

---

[Back to SkyMesh README](../README.md)
