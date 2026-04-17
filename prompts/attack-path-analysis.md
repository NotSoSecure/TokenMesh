# Attack Path Analysis

> Copy-paste these into Claude Desktop or CLI mode to map full attack chains from your Azure environment's real data.

---

### Full attack path intelligence

```
Run the high-privileged identity intelligence engine. For each finding,
show me the full attack path — what can this identity actually DO if
compromised? Include Entra role escalation paths.
```

---

### Contributor SP escalation chain

```
If an attacker compromised a Contributor-level service principal,
what resources could they access and how could they escalate to Owner?
Map this from the current subscription data.
```

---

### Owner SP full kill chain

```
Map the full kill chain for a compromised Owner-level service principal:
initial access via credential theft → persistence → lateral movement →
data exfiltration. Use the actual identities from this environment.
```

---

### Shortest path to subscription takeover

```
What is the minimum number of identities an attacker needs to compromise
to get full subscription Owner access? Show me the shortest path from
each identity type (user, SP, group).
```

---

### Blast radius analysis

```
For each Owner-level identity, calculate the blast radius:
what resources are in scope, what Entra roles do they also hold,
and what could an attacker destroy or exfiltrate with that access?
```

---

### Defender disable path

```
Which identities have enough privilege to disable Azure Defender,
delete diagnostic logs, or turn off security monitoring? These are
the first identities an attacker would target to go dark.
```

---

[Back to SkyMesh README](../README.md)
