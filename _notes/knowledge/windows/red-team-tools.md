---
title: Windows red-team tools
---

## Bloodhound & Sharphound
Bloodhound allowed attackers to visualise the AD environment in a graph format with interconnected nodes. It's a tool for visualization of AD organization structure in the form of a graph.
    
Sharphound is the enumeration tool of Bloodhound. It is used to enumerate the AD information that can then be visually displayed in Bloodhound. Bloodhound is the actual GUI used to display the AD attack graphs. Three Sharphound collectors are available:
- Sharphound.exe
- Sharphound.ps1
- AzureHound.ps1 (for Azure enumeration)
When using these collector scripts, these files propably will be detected as malware and raise an alert to the blue team.

After uploading the data grabbed with Sharphound to Bloodhound, it shows possible attack vectors exploiting different privileges of AD objects.