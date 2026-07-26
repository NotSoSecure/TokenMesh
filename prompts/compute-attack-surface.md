# Compute Attack Surface

> Copy-paste these into Claude Desktop or CLI mode to hunt VM, VMSS, and
> Azure Arc persistence + escalation paths.

---

### Managed identity subscription-takeover paths

```
Find every VM whose managed identity holds Owner, Contributor, or
User Access Administrator at subscription-or-higher scope. Any code
execution on those VMs (runCommand, IMDS, extension abuse) equals
subscription takeover. MITRE T1552.005 chaining into T1098.003.
```

---

### runCommand / CustomScriptExtension persistence

```
List every VM extension in the subscription. Flag CustomScriptExtension,
CustomScriptForLinux, RunCommandLinux, RunCommandWindows, DSC extensions,
and anything whose settings.fileUris point outside our tenant's storage
accounts. This is BloodHound-Azure AZExecuteCommand and the MicroBurst
Invoke-AzureRmVMRunCommand technique. MITRE T1651.
```

---

### VMs with public RDP/SSH exposure

```
Which VMs have a public IP with RDP (3389) or SSH (22) open, and no
Just-in-Time access policy? Give me VM name, IP, and network security
group rule that permits it.
```

---

### Azure Arc-connected persistence

```
List Azure Arc-connected machines. Flag any with status=Connected but
last-status-change older than 30 days — attacker-abandoned Arc
registrations are a known persistence artifact. Also flag any Arc machine
whose managed identity has Azure RBAC assignments beyond its own resource.
```

---

### Boot-diagnostics screenshot exposure

```
Which VMs write boot diagnostics to a storage account that also has
public blob access enabled? Serial-console screenshots can leak login
prompts, kernel panics, or sensitive process output. MITRE T1580.
```

---

### Unmanaged disks / no encryption at host

```
Compute hardening audit: VMs without encryption-at-host, without
TrustedLaunch (securityType), with unmanaged OS disks, or using
platform-managed keys instead of a customer-managed disk encryption set.
Rank by risk.
```

---

### VM Contributor role scoped subscription-wide

```
Find every principal with Virtual Machine Contributor at subscription or
management-group scope. VM Contributor = runCommand = SYSTEM shell on
every VM. This role should be RG-scoped at most, not subscription-wide.
```

---

### VMSS extension inventory

```
Enumerate every virtual machine scale set and its extension profile.
Flag CustomScript / RunCommand / DSC extensions and anything pulling
from foreign storage URIs. VMSS extensions apply to every new instance
— higher blast radius than single-VM extensions.
```

---

[Back to TokenMesh README](../README.md)
