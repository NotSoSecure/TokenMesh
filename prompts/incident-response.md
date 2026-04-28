# Incident Response

> Copy-paste these into Claude Desktop or CLI mode when you're actively triaging a security incident.

---

### Compromised service principal triage

```
I think a service principal may have been compromised. List all service
principals with Owner or Contributor roles, their app IDs, and enabled
status. I need to triage which ones to rotate credentials for first.
```

---

### Compromised user account lockdown

```
A user account may have been taken over. List all users with high-privilege
RBAC roles. Cross-reference with Entra directory roles to find anyone
with both Azure and Entra admin access — those are my highest priority
accounts to lock down.
```

---

### PDF incident report

```
Generate a PDF incident report of all high-privileged identities with
their attack paths, risk levels, and evidence. I need this for the
security team review within the hour.
```

---

### Suspicious activity triage

```
We detected suspicious activity from an IP. List all service principals
and check if any have Owner or Contributor roles that could have been
used for the unauthorized actions we're seeing. I need names, app IDs,
and scopes.
```

---

### Scope of breach assessment

```
We have a confirmed breach on one identity. Run the full intelligence
engine and backdoor detection. I need to understand: what else could
the attacker have accessed from this identity's role and scope?
Show me the full blast radius.
```

---

### Emergency access review

```
We're in incident response mode. Give me EVERY identity with Owner,
Contributor, or User Access Administrator roles — users, SPs, and groups.
For each one, tell me the risk if it's compromised and whether we should
rotate/revoke immediately. This is urgent triage.
```

---

### Post-incident cleanup

```
The incident is contained. Now I need a cleanup report: list all
high-privilege identities that should be reviewed, any ghost/unresolved
identities that might be attacker persistence, and storage accounts
that were potentially exposed. Generate a PDF for the post-mortem.
```

---

[Back to TokenMesh README](../README.md)
