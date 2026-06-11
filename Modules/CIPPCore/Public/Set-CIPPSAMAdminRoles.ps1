function Set-CIPPSAMAdminRoles {
    <#
    .SYNOPSIS
        Set SAM roles
    .DESCRIPTION
        Set SAM roles on a tenant
    .PARAMETER TenantFilter
        Tenant to apply the SAM roles to
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $ActionLogs = [System.Collections.Generic.List[object]]::new()

    # AGIO FORK PATCH: upstream hardcodes Compliance Administrator as a default role that is
    # force-assigned into every customer tenant (added upstream 2026-05-28, commit aefa69b0,
    # CIPP 10.5.0). Adding directory roles into client environments on the fly breaks client
    # trust, so we assign ONLY the roles explicitly configured in the SAMRoles table.
    # See docs/cipp-fork-patches.md (Patch 2). Re-apply after any upstream merge.
    $DefaultRoles = @()

    $SAMRolesTable = Get-CIPPTable -tablename 'SAMRoles'
    $Roles = Get-CIPPAzDataTableEntity @SAMRolesTable

    try {
        $SAMRoles = @($Roles.Roles | ConvertFrom-Json -ErrorAction Stop)
        $Tenants = $Roles.Tenants | ConvertFrom-Json -ErrorAction Stop
        if ($Tenants.value) {
            $Tenants = $Tenants.value
        }
    } catch {
        $SAMRoles = @()
        $Tenants = @()
    }

    # Merge default roles with user-configured roles, avoiding duplicates
    $ExistingValues = @($SAMRoles | ForEach-Object { $_.value })
    foreach ($DefaultRole in $DefaultRoles) {
        if ($DefaultRole.value -notin $ExistingValues) {
            $SAMRoles = @($SAMRoles) + @($DefaultRole)
        }
    }

    if (($SAMRoles | Measure-Object).Count -gt 0 -and ($Tenants -contains $TenantFilter -or $Tenants -contains 'AllTenants' -or ($Tenants | Measure-Object).Count -eq 0)) {
        $InitialRequests = @(
            [PSCustomObject]@{
                id     = 'memberOf'
                method = 'GET'
                url    = "servicePrincipals(appId='$($env:ApplicationID)')/memberOf/#microsoft.graph.directoryRole"
            }
            [PSCustomObject]@{
                id     = 'sp'
                method = 'GET'
                url    = "servicePrincipals(appId='$($env:ApplicationID)')?`$select=id,displayName"
            }
        )
        $InitialResults = New-GraphBulkRequest -tenantid $TenantFilter -Requests $InitialRequests -AsApp $true -NoAuthCheck $true
        $AppMemberOf = ($InitialResults | Where-Object { $_.id -eq 'memberOf' }).body.value
        $sp = ($InitialResults | Where-Object { $_.id -eq 'sp' }).body
        $id = $sp.id

        $Requests = $SAMRoles | Where-Object { $AppMemberOf.roleTemplateId -notcontains $_.value } | ForEach-Object {
            # Batch add service principal to directoryRole
            [PSCustomObject]@{
                'id'      = $_.label
                'headers' = @{
                    'Content-Type' = 'application/json'
                }
                'url'     = "directoryRoles(roleTemplateId='$($_.value)')/members/`$ref"
                'method'  = 'POST'
                'body'    = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($id)"
                }
            }
        }
        if (($Requests | Measure-Object).count -gt 0) {
            $HasFailures = $false
            try {
                $null = New-ExoRequest -cmdlet 'New-ServicePrincipal' -cmdParams @{AppId = $env:ApplicationID; ObjectId = $id; DisplayName = 'CIPP-SAM' } -Compliance -tenantid $TenantFilter -useSystemMailbox $true -AsApp
                $ActionLogs.Add('Added Service Principal to Compliance Center')
            } catch {
                $ActionLogs.Add('Service Principal already added to Compliance Center')
            }
            try {
                $null = New-ExoRequest -cmdlet 'New-ServicePrincipal' -cmdParams @{AppId = $env:ApplicationID; ObjectId = $id; DisplayName = 'CIPP-SAM' } -tenantid $TenantFilter -useSystemMailbox $true -AsApp
                $ActionLogs.Add('Added Service Principal to Exchange Online')
            } catch {
                $ActionLogs.Add('Service Principal already added to Exchange Online')
            }

            Write-Verbose ($Requests | ConvertTo-Json -Depth 5)
            $Results = New-GraphBulkRequest -tenantid $TenantFilter -Requests @($Requests)
            $Results | ForEach-Object {
                if ($_.status -eq 204) {
                    $ActionLogs.Add("Added service principal to directory role $($_.id)")
                } elseif ($_.status -eq 404) {
                    $ActionLogs.Add("Directory role $($_.id) does not exist in tenant, skipping")
                } else {
                    $ActionLogs.Add("Failed to add service principal to directoryRole $($_.id):  $($_ | ConvertTo-Json -Depth 5)")
                    Write-Verbose ($_ | ConvertTo-Json -Depth 5)
                    $HasFailures = $true
                }
            }
            $LogMessage = @{
                'API'      = 'Set-CIPPSAMAdminRoles'
                'tenant'   = $TenantFilter
                'tenantid' = (Get-Tenants -TenantFilter $TenantFilter -IncludeErrors).custom
                'message'  = ''
                'LogData'  = $ActionLogs
            }
            if ($HasFailures) {
                $LogMessage.message = 'Errors occurred while setting Admin Roles for CIPP-SAM'
                $LogMessage.sev = 'Error'
            } else {
                $LogMessage.message = 'Successfully set Admin Roles for CIPP-SAM'
                $LogMessage.sev = 'Info'
            }
            Write-LogMessage @LogMessage
        } else {
            $ActionLogs.Add('Service principal already exists in all requested Admin Roles')
        }
    } else {
        $ActionLogs.Add('No SAM roles found or tenant not added to CIPP-SAM roles')
    }
    $ActionLogs
}
