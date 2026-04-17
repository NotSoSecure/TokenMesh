# Threat Detection & Hardening

> Copy-paste these into Claude Desktop or CLI mode for threat detection and hardening recommendations.

---

### Backdoor + remediation scan

```
Detect any backdoors or anomalous service principals in this environment.
Give me a severity-ranked list with remediation steps for each finding.
```

---

### Storage misconfiguration with MITRE mapping

```
Check all storage accounts for security misconfigurations.
For each issue found, tell me the risk level, MITRE ATT&CK mapping,
and what an attacker could do if it were exploited.
```

---

### Full security posture report

```
Generate a full security posture report of this Azure subscription:
high-privilege identities, storage risks, backdoor service principals,
and Entra role exposure. I need this for an executive briefing.
```

---

### Least privilege recommendations

```
Compare our current RBAC setup against the principle of least privilege.
Which assignments are overly broad and should be scoped down? Give me
specific recommendations for each one.
```

---

### Top 10 risks

```
Run all checks — identity, RBAC, storage, backdoor detection.
Then give me the top 10 security risks ranked by severity, with one-line
remediation for each.
```

---

### Hardening checklist

```
Based on the current state of this Azure subscription, generate a hardening
checklist: what should we fix first, second, third? Prioritize by risk and
effort. I want actionable items, not generic advice.
```

---

[Back to SkyMesh README](../README.md)
