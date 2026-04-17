# Privilege Escalation Hunting

> Copy-paste these into Claude Desktop or CLI mode to hunt for privilege escalation paths in your Azure environment.

---

### Find all high-privilege identities with attack paths

```
Find all identities with Owner or Contributor roles in this Azure subscription.
For each one, show me their name, type (user/SP/group), scope, and what attack
paths are available to them.
```

---

### Service principals with Owner access

```
Show me every service principal that has Owner access. These are my highest
priority backdoor candidates — include their app ID and whether they are
enabled or disabled.
```

---

### Crown jewel targets (dual Azure + Entra admin)

```
Which identities have both an Azure RBAC high-privilege role AND a Microsoft
Entra directory role like Global Admin or Privileged Role Administrator?
These are crown jewel targets.
```

---

### Ghost identities with active permissions

```
List all role assignments where the principal type is unknown or unresolved.
Ghost identities with active permissions are a classic persistence indicator.
```

---

### User Access Administrator escalation

```
Find all User Access Administrator assignments. These identities can grant
themselves Owner — that's a one-step privilege escalation path.
```

---

### Contributor-to-Owner escalation mapping

```
If an attacker compromised a Contributor-level service principal,
what resources could they access and how could they escalate to Owner?
Map this from the current subscription data.
```

---

### Shortest path to full Owner

```
What is the minimum number of identities an attacker needs to compromise
to get full subscription Owner access? Show me the shortest path.
```

---

[Back to SkyMesh README](../README.md)
