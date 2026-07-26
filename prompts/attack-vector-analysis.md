# Attack Vector Analysis

> Copy-paste these into Claude Desktop or CLI mode to map a specific
> identity's blast radius to concrete attack techniques with MITRE ATT&CK
> for Cloud IDs, KQL detection signals, and remediation.

Backed by TokenMesh's role→attack table (BloodHound-Azure edges, MicroBurst,
Socchi's Entra privesc matrix, MITRE ATT&CK for Cloud).

---

### Full blast-radius report for one identity

```
Analyze the attack vectors for principal <object-id>. Show every role it
holds, and for each role, the concrete attack techniques it enables with
MITRE IDs, KQL detection signals, and remediation.
```

---

### What can this role do?

```
Look up the attack vectors for the role "Storage Account Contributor" at
subscription scope. I want to know exactly what an attacker could do,
what to hunt in Sentinel, and how to remediate.
```

---

### Role-attack lookup for review

```
What attack techniques does "Virtual Machine Contributor" enable? Give me
the MITRE ID, the primitive, the KQL to detect it, and the remediation —
I'm reviewing whether to grant this role to a workload SP.
```

---

### Cross-reference every high-priv SP with its attack surface

```
For every service principal with Owner or Contributor: analyze its full
attack surface. Rank SPs by attack-vector count and highest scope tier.
Give me the top 10.
```

---

### Managed identity attack surface

```
For every managed identity attached to a VM in this subscription, analyze
its Azure RBAC blast radius — what techniques it enables via T1552.005
(IMDS) chained into subsequent access.
```

---

### Prep for a Sentinel detection rule

```
I need to write a Sentinel detection for "any principal that just used a
role it never used before". Which of my high-priv identities have the
widest attack surface — those are the priorities to onboard first.
```

---

[Back to TokenMesh README](../README.md)
