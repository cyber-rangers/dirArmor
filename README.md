# 🛡️ dirArmor: Cyber Rangers AD Hardening PowerShell Module

## Overview
**dirArmor** is a PowerShell module developed by **Cyber Rangers** to enhance the security and maintainability of **Active Directory** environments. It includes various functions to remediate and harden Active Directory schema configurations, specifically targeting the removal of legacy Exchange-related entries.

## Features 🚀
- **Invoke-dirArmorVulnerableSchemaRemediation**: Removes legacy Exchange schema entries.
- **Write-dirArmorCRLog**: Centralized logging function for improved debugging and audit trails.
- **Supports `-WhatIf` and `-Confirm`**: Safe execution with preview capabilities.
- **Verbose logging with timestamps** for troubleshooting.
- **Enterprise-ready and extensible**: Future-proof module design for additional hardening functions.

## Installation 📦
To install the module, copy the `dirArmor` folder to the PowerShell module directory:

```powershell
$ModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\dirArmor"
New-Item -ItemType Directory -Path $ModulePath -Force
Copy-Item -Path "./dirArmor/*" -Destination $ModulePath -Recurse -Force
```

## Usage 🛠️
### Import the module
```powershell
Import-Module dirArmor
```

### View available functions
```powershell
Get-Command -Module dirArmor
```

## Contributing 🤝
Contributions are welcome! Feel free to submit issues or pull requests to improve the module.

## License 📜
This project is licensed under the **MIT License**.

---
🚀 **Cyber Rangers - Keeping Active Directory Secure!**