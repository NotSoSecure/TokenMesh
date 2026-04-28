# Compliance & Reporting

> Copy-paste these into Claude Desktop or CLI mode to generate audit-ready compliance reports.

---

### Full compliance audit report

```
Generate a full PDF security assessment report. Include all high-privilege
identities, storage findings, and backdoor detection results. This is for
our annual compliance audit.
```

---

### Least privilege violation metrics

```
How many identities violate the principle of least privilege? Count everyone
with Owner access who could function with Contributor or Reader.
Give me numbers for the compliance dashboard.
```

---

### Complete scan + PDF export

```
Run all available checks: identities, RBAC, storage, backdoors.
Then generate a PDF report. I need a comprehensive security posture
document for the client handoff.
```

---

### Executive summary

```
Give me a one-page executive summary of this Azure subscription's security
posture: total identities, high-privilege count, critical risks found,
storage exposure, and top 3 recommendations. Keep it non-technical —
this is for leadership.
```

---

### Quarterly access review

```
Generate a quarterly access review report: list every identity with
high-privilege access, their role, scope, and whether this access appears
justified based on their identity type. Flag candidates for revocation.
```

---

### Risk score summary

```
Assign a risk score (Critical/High/Medium/Low) to every finding across
identity, RBAC, storage, and backdoor checks. Give me a summary table
and the overall subscription risk rating. Then generate a PDF.
```

---

[Back to TokenMesh README](../README.md)
