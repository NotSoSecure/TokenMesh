# Identity Hygiene & Governance

> Copy-paste these into Claude Desktop or CLI mode for blue team identity auditing and access governance.

---

### Disabled accounts with live permissions

```
List all Entra ID users and flag any with accountEnabled = false who still
have active Azure RBAC role assignments. Disabled accounts with live
permissions are a hygiene risk.
```

---

### Owner access breakdown by type

```
How many unique identities have Owner access in this subscription?
Break it down by principal type: users, groups, and service principals.
I need this for our quarterly access review.
```

---

### Subscription-root scope audit

```
Are there any role assignments scoped directly to the subscription root?
Best practice is resource-group-level scoping — subscription-level is
overly broad and increases blast radius.
```

---

### Service principal credential hygiene

```
List all service principals and their roles. Flag any SPs that have not been
rotated or reviewed recently — we need to enforce credential hygiene.
```

---

### CISO dashboard inventory

```
Give me a complete identity inventory: total users, groups, service principals,
and how many of each have high-privilege roles. I need this for our CISO
dashboard.
```

---

### Least privilege violation count

```
How many identities violate the principle of least privilege? Count everyone
with Owner access who could function with Contributor or Reader.
Give me numbers for the compliance dashboard.
```

---

### Stale access review

```
List all users and service principals with high-privilege roles.
For each, tell me: do they appear to need this level of access based on
their name/type, or is this potentially stale? Flag candidates for
access revocation.
```

---

[Back to SkyMesh README](../README.md)
