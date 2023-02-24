function Get-GUIDTable {
    <#
    .SYNOPSIS
        Builds a Globally Unique Identifier (GUID) table using the local Active Directory (AD) to match GUIDs with friendly name.

    .DESCRIPTION
        Builds a Globally Unique Identifier (GUID) table using the local Active Directory (AD) to match GUIDs with friendly name. Objects include any active directory object with a schemaIDGUID property and all controlAccessRight objects. The table is returned when this function is called.

    .INPUTS
        None

    .OUTPUTS
        Returns GUID table.

    .NOTES
      Author: David Drinkwater
      Change Log:
        v1.0 - 11/25/2020 - Initial script development
        v1.1 - 12/23/2020 - Packaged into function, changed return, and added 'All' entry


    .EXAMPLE
        $guidTable = Get-GUIDTable

    #>
    [PSObject]$guidTable = @()

    # Add objects with 'schemaIDGUID'
    Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
    ForEach-Object {$guidTable += New-Object PSObject -property @{GUID=[System.GUID]$_.schemaIDGUID;Name=$_.name}}

    # Add 'controlAccessRight' objects
    Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
    ForEach-Object {$guidTable += New-Object PSObject -property @{GUID=[System.GUID]$_.rightsGUID;Name=$_.name}}

    # Add 'All' object
    $guidTable += New-Object PSObject -property @{GUID=[System.GUID]'00000000-0000-0000-0000-000000000000';Name='All'}
    Return $guidTable
}

function Get-ADAcl {
    <#
    .SYNOPSIS
        Gets the Access Control List (ACL) for a Active Directory (AD) object. Translates object Globally Unique Identifiers (GUIDs) into friendly names.

    
    .DESCRIPTION
        Gets the Access Control List (ACL) for a Active Directory (AD) object. Translates object Globally Unique Identifiers (GUIDs) into friendly names and outputs all found data on screen.

    .INPUTS
        PARAMETER       DESCRIPTION
        TargetDN        Distinquished Name (DN) of the AD object you're getting the ACL of (typically an OU).
        DelegateDN      Distinguished Name (DN) of user or group (delegate) you want to view from the ACL. This is optional, leaving it out will return all entries.
                 
    .OUTPUTS
        On-screen list of Access Control Entries (ACEs).

    .NOTES
      Author: David Drinkwater
      Change Log:
        v1.1 - 2/18/2021 - Improved output on return to use in analysis tools.
        v1.0 - 12/23/2020 - Initial script development

    .EXAMPLE
        Get-ADAcl `
            -TargetDN ( 'CN=Computers,'+(Get-ADDomain).DistinguishedName ) `
            -DelegateDN ( "CN=Print Operators,CN=Builtin," + (Get-ADDomain).DistinguishedName )

    #>
    param(
        [Parameter(Mandatory=$true)][string]$TargetDN,    
        [Parameter(Mandatory=$false)][string]$DelegateDN=".*"
    )

    Import-Module ActiveDirectory

    $guidTable = Get-GUIDTable
    
    # Resolve delegate name
    if ( $DelegateDN -eq ".*" ) {
        $DelegateName = $DelegateDN
    }
    else {
        $DelegateName = ( Get-AdObject $DelegateDN ).Name
    }
    if ( ! $DelegateName ) { Write-Error "Unable to resolve name for: $DelegateDN"; Return }


    $accessEntries = (Get-Acl "ad:$TargetDN").access | Where-Object {$_.identityreference -match $DelegateName } 

    [PSObject]$outputTable = @()
    #Compare each entry
    foreach ( $entry  in $accessEntries ) {
        $objectName =  ( $guidTable | Where-Object { $_.GUID -eq ($entry.objectType.Guid) } ).Name
        $inheritedObjectName =  ( $guidTable | Where-Object { $_.GUID -eq ($entry.InheritedObjectType.Guid) } ).Name
        
        #Build output table
        $outputTable += New-Object PSObject -property @{
            IdentityReference=$entry.IdentityReference;
            ActiveDirectoryRights=$entry.ActiveDirectoryRights;
            AccessControlType=$entry.AccessControlType;
            ObjectType=$entry.ObjectType;
            ObjectType_Name=$objectName;
            InheritanceType=$entry.InheritanceType;
            InheritedObjectType=$entry.InheritedObjectType;
            InheritedObjectType_Name=$inheritedObjectName           
        }
    }

    Return $outputTable
}

function Set-AdAcl {
    <#
    .SYNOPSIS
        Adds an entry to the Access Control List (ACL) of an Active Directory (AD) object.

    .DESCRIPTION
        Adds an entry to the Access Control List (ACL) of an Active Directory (AD) object. User input supplies the friendly name for ObjectType and InheritiedObjectType and the script will resolve the GUIDs.

    .INPUTS
        PARAMETER               DESCRIPTION
        TargetDN                Distinquished Name of the AD object you're modifying the ACL of (typically an OU).
        DelegateDN              Distinguished Name of user or group (delegate) to add to the ACL of the target.
        ActiveDirectoryRights   Any valid ActiveDirectoryRights field. See full list below:
                                    AccessSystemSecurity,CreateChild,Delete,DeleteChild,DeleteTree,ExtendedRight,GenericAll,GenericExecute,GenericRead,GenericWrite,ListChildren,ListObject,ReadControl,ReadProperty,Self,Synchronize,WriteDacl,WriteOwner,WriteProperty
        AccessControlType       Any valid AccessControlType field. See full list below:
                                    Allow,Deny
        InheritanceType         Any valid InheritanceType field. See full list below:
                                    All,Children,Descendents,None,SelfAndChildren
        ObjectType              The common name of the AD object that the permissions on the targeted object apply to.
                                Example: 'Computer' here would allow 'Create/delete computer objects' in this OU if ActiveDirectoryRights are 'CreateChild,DeleteChild' and the target is an OU.
        InheritedObjectType     The common name of descendent AD objects that the permissions apply to.
                                Example: 'Computer' here would allow 'Full control' of descendent computer objects in this OU if ActiveDirectoryRights are 'GenericAll' and the target is an OU.

    .OUTPUTS

    .NOTES
      Author: David Drinkwater
      Change Log:
        v1.0 - 12/23/2020 - Initial script development


    .EXAMPLE
        Set-ADAcl `
            -TargetDN ( 'CN=Computers,'+(Get-ADDomain).DistinguishedName ) `
            -DelegateDN ( "CN=Print Operators,CN=Builtin," + (Get-ADDomain).DistinguishedName ) `
            -ActiveDirectoryRights 'CreateChild','DeleteChild' `
            -AccessControlType 'Allow' `
            -InheritanceType 'None' `
            -ObjectType 'Print-Queue' `
            -InheritedObjectType 'All'

    #>
    param(
        [Parameter(Mandatory=$true)][string]$TargetDN,    
        [Parameter(Mandatory=$true)][string]$DelegateDN,
        [Parameter(Mandatory=$true)][ValidateSet('GenericAll','GenericExecute','GenericRead','GenericWrite','AccessSystemSecurity','CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')][array]$ActiveDirectoryRights,
        [Parameter(Mandatory=$false)][ValidateSet('Allow','Deny')][string]$AccessControlType = 'Allow',
        [Parameter(Mandatory=$true)][ValidateSet('All','Children','Descendents','None','SelfAndChildren')][string]$InheritanceType,
        [Parameter(Mandatory=$true)][string]$ObjectType,
        [Parameter(Mandatory=$true)][string]$InheritedObjectType
    )

    Import-Module ActiveDirectory

    $guidTable = Get-GUIDTable

    $acl = Get-Acl "ad:$TargetDN"

    # Resolve delegate SID
    $Delegate = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DelegateDN"
    $DelegateSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Delegate.ObjectSID.Value, 0
    if ( ! $DelegateSID ) { Write-Error "Unable to resolve SID for: $DelegateDN"; Return }

    # Create a new access control entry to allow access to the OU
    $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList @(
        [System.Security.Principal.IdentityReference] $DelegateSID,
        [System.DirectoryServices.ActiveDirectoryRights] $ActiveDirectoryRights,
        [System.Security.AccessControl.AccessControlType] $AccessControlType,
        ( $guidTable | Where-Object { $_.Name -eq $ObjectType } ).GUID,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance] $InheritanceType,
        ( $guidTable | Where-Object { $_.Name -eq $InheritedObjectType } ).GUID
    )

    # Add access ruleto the ACL, then set the ACL to save changes
    $acl.AddAccessRule($accessRule)
    Set-Acl -AclObject $acl "ad:$TargetDN"
}

function Get-OUDelegation {
    <#
    .SYNOPSIS
    This function will scan all Organizational Units (OUs) and generate a CSV of any custom delegation applied to them.

    .DESCRIPTION
    This function will scan all Organizational Units (OUs) and generate a CSV of any custom delegation applied to them. This is intended to satisfy VID V-224974 and, as such, 'Account Operators' and 'Print Operators' will flag as custom delegation when the report is generated.  It is recommended you remove these before launching this script.

    .INPUTS
    n/a

    .OUTPUTS
        Path    CSV output location. Defaults to c:\temp\ouDelegation_$timestamp.csv.

    .NOTES
    Author: David Drinkwater
    Prerequisites: ActiveDirectory Module (RSAT)
    Change Log:
        v1.0 - 6/10/2021 - Initial script development


    .EXAMPLE
    Get-OUDelegation -Path c:\temp\delegation.csv
    #>

    param (
        [Parameter(Mandatory=$false)][string]$Path=("c:\temp\ouDelegation_" + (Get-Date -Format "yyyy-MM-dd_HH.mm.ss") + ".csv"),
        [Parameter(Mandatory=$false)][ValidateSet('AllowOnly','DenyOnly','All')][string]$AccessControlType='All',
        [Parameter(Mandatory=$false)][Switch]$IncludeContainers
    )

    # Import Active Directory module
    Import-Module ActiveDirectory -Verbose:$false
    # Get GUID table
    $guidTable = Get-GUIDTable
    # Get OUs, searching entire subtree
    $OUs = (Get-ADOrganizationalUnit -SearchBase (Get-AdDomain).distinguishedname -Filter {(ObjectClass -eq "organizationalUnit") -and (Name -ne "Domain Controllers")} -SearchScope Subtree).DistinguishedName
    if ( $IncludeContainers ) {
        $OUs += ( Get-AdObject -SearchBase (Get-AdDomain).distinguishedname -Filter {(ObjectClass -eq "container")} ).DistinguishedName
    }
    $domain = (Get-AdDomain).NetBIOSName
    [PSObject]$outputTable = @()
    
    foreach ($ou in $OUs) {
        $acl = Get-Acl -Audit -Path ('AD:'+$ou)
        $access = $acl.Access
        foreach ( $entry in $access ) {
            if ( $AccessControlType -eq "AllowOnly" -and $entry.AccessControlType -eq "Deny" ) {
                # Skip DenyOnly entries
                Continue
            } elseif ( $AccessControlType -eq "DenyOnly" -and $entry.AccessControlType -eq "Allow" ) {
                # Skip DenyOnly entries
                Continue
            }
            if (
                $entry.IdentityReference -eq "NT AUTHORITY\SELF" -and
                ($entry.ActiveDirectoryRights -eq "ReadProperty, WriteProperty, ExtendedRight" -or $entry.ActiveDirectoryRights -eq "ReadProperty, WriteProperty" -or $entry.ActiveDirectoryRights -eq "WriteProperty" -or $entry.ActiveDirectoryRights -eq "Self")
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "NT AUTHORITY\Authenticated Users" -and
                ($entry.ActiveDirectoryRights -eq "GenericRead" -or $entry.ActiveDirectoryRights -eq "ReadProperty")
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "NT AUTHORITY\SYSTEM" -and
                $entry.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "$domain\Domain Admins" -and
                $entry.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "$domain\Enterprise Admins" -and
                $entry.ActiveDirectoryRights -eq "GenericAll"
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "BUILTIN\Administrators" -and
                $entry.ActiveDirectoryRights -eq "CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner"
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "BUILTIN\Pre-Windows 2000 Compatible Access" -and
                ($entry.ActiveDirectoryRights -eq "GenericRead" -or $entry.ActiveDirectoryRights -eq "ListChildren" -or $entry.ActiveDirectoryRights -eq "ReadProperty")
            ) {
                #Match default/expected entry
            }`
            elseif (
            $entry.IdentityReference -eq "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" -and
            ($entry.ActiveDirectoryRights -eq "GenericRead" -or $entry.ActiveDirectoryRights -eq "ReadProperty")
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "$domain\Key Admins" -and
                ($entry.ActiveDirectoryRights -eq "ReadProperty, WriteProperty")
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "$domain\Enterprise Key Admins" -and
                ($entry.ActiveDirectoryRights -eq "ReadProperty, WriteProperty")
            ) {
                #Match default/expected entry
            }`
            elseif (
                $entry.IdentityReference -eq "CREATOR OWNER" -and
                $entry.ActiveDirectoryRights -eq "Self"
            ) {
                #Match default/expected entry
            }`
            else{
                # Not an expected entry!
                $objectName =  ( $guidTable | Where-Object { $_.GUID -eq ($entry.objectType.Guid) } ).Name
                $inheritedObjectName =  ( $guidTable | Where-Object { $_.GUID -eq ($entry.InheritedObjectType.Guid) } ).Name
                
                if ( $entry.IsInherited -eq 'True' ) { 
                    $justification = 'Inherited from parent OU.'
                }`
                else {
                    $justification = ''
                }

                #Build output table
                $outputTable += New-Object PSObject -property @{
                    OU = ( $ou | Out-String ) -replace "`r`n",'';
                    IdentityReference=$entry.IdentityReference.Value;
                    ActiveDirectoryRights=$entry.ActiveDirectoryRights;
                    AccessControlType=$entry.AccessControlType;
                    ObjectType=$entry.ObjectType;
                    ObjectType_Name=$objectName;
                    InheritanceType=$entry.InheritanceType;
                    InheritedObjectType=$entry.InheritedObjectType;
                    InheritedObjectType_Name=$inheritedObjectName;
                    IsInherited=$entry.IsInherited;
                    Justification=$justification
                }
            }
        }
    }

    $outputTable | Select-Object OU,IdentityReference,AccessControlType,ActiveDirectoryRights,ObjectType_Name,InheritanceType,InheritedObjectType_Name,IsInherited,Justification | Export-Csv -Path $Path -NoTypeInformation -Force
}
