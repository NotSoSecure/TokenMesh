# Backdoor & Persistence Detection

> Copy-paste these into Claude Desktop or CLI mode to hunt planted
> backdoors and persistence mechanisms across identity, RBAC, Key Vault,
> and Compute layers.

Every finding TokenMesh returns includes a MITRE ATT&CK for Cloud
technique ID, a KQL detection signal ready for Microsoft Sentinel or
Defender for Cloud, and a remediation.

---

### Service principals with Owner access (SP-only, no users)

```
List every service principal with Owner access — service principals only,
not users. This is the persistence path after a breach: an SP with
Owner that survives credential rotation and can be reactivated by
recreating credentials.
```

---

### Orphaned role assignments (deleted-principal persistence)

```
Find every high-privilege role assignment whose principal ID no longer
resolves in Microsoft Graph. Deleted service principals that still hold
Owner or Contributor are the classic Azure backdoor — the object can be
re-created with the same ID (or restored from Recycle Bin) to reinstate
access. MITRE T1078.004.
```

---

### Long-lived application credentials

```
Which service principals have client secrets or certificates that don't
expire for more than two years? Long-lived credentials are what MicroBurst
`Get-AzPasswords` hunts. Rotate anything over 90 days.
```

---

### Federated identity credentials with wildcard subject

```
Audit every application's federated identity credentials. Flag any FIC
whose subject is empty, wildcarded, or set to just "sub" — the workload
federation was misconfigured and any token from that issuer will assume
the SP.
```

---

### Guest users with high-privilege RBAC (partner-tenant lateral)

```
Which Entra guest users (userType = Guest) hold Owner, Contributor, or
User Access Administrator? Partner-tenant breach becomes your subscription
breach through these — MITRE T1078.004.
```

---

### Cross-tenant service principals with high role

```
Find service principals where the owning application lives in a
different tenant than ours (appOwnerOrganizationId != our tenant ID)
AND holds Owner/Contributor. Third-party integrations that hold Owner
are documented trusted-relationship risks — MITRE T1199.
```

---

### Dangling Key Vault access policies

```
Audit every Key Vault's access policies. Any policy whose objectId is
Unknown (does not resolve in Graph) is a deleted-principal persistence
artifact. Include the vault, permissions granted, and MITRE.
```

---

### Legacy Key Vault Contributor escalation

```
Find any principal with Key Vault Contributor on a vault where
enableRbacAuthorization=false. That combo is a self-service data-plane
escalation — the Contributor can rewrite accessPolicies to grant itself
Read on every secret. MITRE T1098.003.
```

---

### Managed identity subscription-takeover paths

```
Detect managed identity escalation: every VM whose MI holds Owner,
Contributor, or UAA at subscription-or-higher scope. Code execution on
the VM (runCommand, IMDS, extension) inherits the MI's permissions.
```

---

### Suspicious VM extensions

```
Enumerate every VM extension. Flag CustomScriptExtension,
RunCommandLinux/Windows, DSC, and any extension whose fileUris point
outside our tenant's storage accounts. BloodHound-Azure AZExecuteCommand.
MITRE T1651.
```

---

### Boot-diagnostics on public storage

```
Which VMs write boot diagnostics to a storage account that also allows
public blob access? Serial-console screenshots can leak login prompts
and sensitive process output. MITRE T1580.
```

---

### Full backdoor scan (all detectors)

```
Run every backdoor detector: orphaned assignments, long-lived credentials,
federated wildcards, guest-user privesc, cross-tenant SPs, dangling KV
access policies, legacy KV Contributor escalation, managed identity
escalation, suspicious VM extensions, public boot diagnostics. Give me
findings grouped by detector with counts, MITRE IDs, and KQL.
```

---

### Suspicious service principal audit

```
Enumerate all service principals with high-priv Azure RBAC. Flag any
that look suspicious — generic names ("app", "test"), no owners, disabled
accounts, or cross-tenant apps. Think like an attacker who planted a
backdoor app registration.
```

---

### Multi-role persistence check

```
Find any service principal that has BOTH an Azure RBAC role AND an Entra
directory role. Dual-access SPs are high-value persistence targets —
revoking one doesn't revoke the other.
```

---

[Back to TokenMesh README](../README.md)
