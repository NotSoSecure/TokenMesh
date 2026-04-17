# Lateral Movement & Scope Abuse

> Copy-paste these into Claude Desktop or CLI mode to uncover lateral movement opportunities and overly broad scoping.

---

### Cross-scope identity detection

```
Find any identities that have roles at the subscription scope but also appear
in resource-group-level assignments. This cross-scope presence could indicate
lateral movement or overly broad permissions.
```

---

### Group membership escalation

```
List all groups that have high-privilege RBAC roles. Then enumerate the members
of those groups. A compromised group member inherits the group's Azure role —
this is an indirect escalation path.
```

---

### Managed identity risk

```
Are there any managed identities with high-privilege roles? If a VM or App
Service is compromised, the managed identity's role becomes the attacker's
role. Show me which resources are at risk.
```

---

### Subscription-root over-scoping

```
Are there any role assignments scoped directly to the subscription root?
Best practice is resource-group-level scoping — subscription-level is
overly broad and increases blast radius. List every one of them.
```

---

### Service principal cross-tenant risk

```
List all service principals and identify any that are multi-tenant or
have external app IDs. These could be used for cross-tenant lateral
movement if the external tenant is compromised.
```

---

### Identity overlap mapping

```
Show me identities that appear in multiple role assignments with different
roles or scopes. An identity with Contributor on one resource group and
Owner on another has lateral movement potential between scopes.
```

---

[Back to SkyMesh README](../README.md)
