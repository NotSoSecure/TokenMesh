# Backdoor & Persistence Detection

> Copy-paste these into Claude Desktop or CLI mode to detect planted backdoors and persistence mechanisms.

---

### Full backdoor scan

```
Run backdoor detection. I want to know every service principal with Owner
access that could be used for persistent unauthorized access after a breach.
```

---

### Suspicious service principal audit

```
Enumerate all service principals. Flag any that look suspicious —
unusual names, high privilege, or no clear ownership. Think like an attacker
who planted a backdoor app registration.
```

---

### Guest user privilege abuse

```
Are there any Entra ID guest users (userType = Guest) who have been assigned
high-privilege Azure RBAC roles? This is a common lateral movement path from
a compromised partner tenant.
```

---

### Generic-name SP detection

```
List all service principals and cross-reference with RBAC. Which SPs have
Contributor or Owner access but have generic names like "app" or "test"?
These look like leftover dev resources or planted persistence.
```

---

### Orphaned credentials

```
List all service principals with their roles. Flag any that are disabled but
still have active role assignments — these are orphaned credentials that
could be re-enabled by an attacker with the right access.
```

---

### Multi-role persistence check

```
Find any service principal that has BOTH an Azure RBAC role AND an Entra
directory role. Dual-access SPs are high-value persistence targets because
revoking one doesn't revoke the other.
```

---

[Back to SkyMesh README](../README.md)
