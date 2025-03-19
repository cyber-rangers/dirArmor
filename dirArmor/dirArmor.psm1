<#
.SYNOPSIS
    dirArmor: PowerShell module for Active Directory Hardening.

.DESCRIPTION
    dirArmor module provides functions to remediate and harden Active Directory environments.

.NOTES
    Author: Jan Marek, Cyber Rangers
    Version: 1.0
    Requires: Active Directory PowerShell module
#>

Export-ModuleMember -Function *

function Write-dirArmorLog {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")
    $formattedMessage = "$timestamp [$Level] $Message"

    if ($Level -eq "ERROR") {
        Write-Error $formattedMessage
    } elseif ($Level -eq "WARNING") {
        Write-Warning $formattedMessage
    } elseif ($Level -eq "DEBUG" -and $PSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
        Write-Verbose $formattedMessage
    } else {
        Write-Host $formattedMessage
    }

    $formattedMessage | Out-File -Append -FilePath "$env:TEMP\CRADHardening.log"
}

function Invoke-dirArmorVulnerableSchemaRemediation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$Force
    )

    try {
        # Validate environment
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "Active Directory module is not available. Please install RSAT: Active Directory tools."
        }

        if (-not (Test-Connection -ComputerName (Get-ADDomainController).HostName -Count 1 -Quiet)) {
            throw "Unable to connect to the domain controller. Check network and permissions."
        }

        if (-not $Force -and -not $PSCmdlet.ShouldProcess("Exchange Schema Modification", "Apply Changes")) {
            Write-dirArmorLog "Execution canceled by user confirmation." "WARNING"
            return
        }

        # Retrieve schema information
        Write-dirArmorLog "🔍 Retrieving schema information..." "DEBUG"
        $directoryRoot = Get-ADRootDSE
        $schemaPath = $directoryRoot.schemaNamingContext

        # Identify Schema Master
        Write-dirArmorLog "🖥️ Identifying Schema Master..." "DEBUG"
        $schemaOwner = Get-ADObject -Identity $schemaPath -Properties fSMORoleOwner |
            Select-Object -ExpandProperty fSMORoleOwner |
            Get-ADDomainController

        # Connect to Schema Master RootDSE
        Write-dirArmorLog "🔗 Connecting to Schema Master RootDSE at $($schemaOwner.HostName)..." "DEBUG"
        $schemaRoot = [ADSI]("LDAP://$($schemaOwner.HostName)/RootDSE")

        # Locate Exchange schema object
        Write-dirArmorLog "📂 Searching for Exchange schema object..." "DEBUG"
        $exchangeSchemaObject = Get-ADObject -LDAPFilter "(&(objectClass=classSchema)(lDAPDisplayName=msExchStorageGroup))" -SearchBase $schemaPath -ErrorAction Stop
        Write-dirArmorLog "📌 Found schema object: $($exchangeSchemaObject.DistinguishedName)" "INFO"

        # Modify schema object properties
        Write-dirArmorLog "✏️ Modifying schema object properties..." "INFO"
        if ($PSCmdlet.ShouldProcess("Schema Object Modification", "Apply Changes")) {
            try {
                Set-ADObject -Identity $exchangeSchemaObject.DistinguishedName -Remove @{possSuperiors = 'computer'} -Server $schemaOwner -ErrorAction Stop
                Write-dirArmorLog "✅ Schema object modified successfully." "INFO"
            } catch {
                Write-dirArmorLog "❌ Failed to modify schema object: $_" "ERROR"
            }
        } else {
            Write-dirArmorLog "🛑 [WhatIf] Would modify schema object: $($exchangeSchemaObject.DistinguishedName)" "WARNING"
        }

        # Apply schema update
        Write-dirArmorLog "🔄 Applying schema update..." "INFO"
        if ($PSCmdlet.ShouldProcess("Schema Update", "Apply Changes")) {
            try {
                $schemaRoot.Put("schemaUpdateNow", 1)
                $schemaRoot.SetInfo()
                Write-dirArmorLog "✅ Schema update initiated." "INFO"
            } catch {
                Write-dirArmorLog "❌ Failed to update schema: $_" "ERROR"
            }
        }

        Write-dirArmorLog "🎉 Schema remediation completed!" "INFO"
    } catch {
        Write-dirArmorLog "❌ A critical error occurred: $_" "ERROR"
    }
}