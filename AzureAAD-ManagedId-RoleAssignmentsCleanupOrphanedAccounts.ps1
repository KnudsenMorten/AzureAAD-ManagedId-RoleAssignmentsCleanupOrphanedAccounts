#Requires -Version 5.0
<#
    .SYNOPSIS
    This script helps with clean-up of orphaned security principals with role assignments.
    Script also add any missing role assignments for managed identity, if missing

    .NOTES
    VERSION: 2301

    .COPYRIGHT
    @mortenknudsendk on Twitter
    Blog: https://mortenknudsen.net
    
    .LICENSE
    Licensed under the MIT license.

    .WARRANTY
    Use at your own risk, no warranty given!
#>


#####################################################################################################################
# Variables
#####################################################################################################################


    $ManagementGroupName             = "mg-xxxx"   # can be a management group - or tenant id, if entire tenant is included

    $TenantId                        = "xxxxx"


#####################################################################################################################
# PS Modules
#####################################################################################################################
<#
    Install-Module -Name Az -Force
#>

#####################################################################################################################
# Connectivity to Azure & Azure AD
#####################################################################################################################

    Connect-AzureAD -TenantId $TenantId
    Connect-AzAccount -TenantId $TenantId


#####################################################################################################################
# Getting Management groups - using Azure Resource Graph - limited to children under $ManagementGroupName
#
# Output: $AzMGs 
# -------------------------------------------------------------------------------------------------------------------
# Search-AzGraph will only include children objects under the specific management group; not the actual root management
# group. But we need array to include root management group, when checking for orphaned security principels (task 1). 
# Therefore we will build a new Array (AzMGsWithRoot)
#
# Output: $AzMGsWithRoot
#####################################################################################################################

    Write-Output "Getting Management Groups from Azure Resource Graph (root: $($ManagementGroupName))"
    $AzMGs = @()
    $pageSize = 1000
    $iteration = 0
    $searchParams = @{
					    Query = "resourcecontainers `
                        | where type == 'microsoft.management/managementgroups' `
                        | extend mgParent = properties.details.managementGroupAncestorsChain `
                        | mv-expand with_itemindex=MGHierarchy mgParent `
                        | project id, name, properties.displayName, mgParent, MGHierarchy, mgParent.name `
                        | sort by MGHierarchy asc "
					    First = $pageSize
 			            }

    $results = do {
	    $iteration += 1
	            $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	    $searchParams.Skip += $pageResults.Count
	    $AzMGs += $pageResults
    } while ($pageResults.Count -eq $pageSize)

    #------------------------------------------------------------------------------------------------------------------------------------
    # Special for Task #1 - remove orphaned security principals
    # Search-AzGraph will only include children objects under the specific management group - but when using data to
    # remove orphaned objects, we also need to have the actual management group as part of the scope
    # Therefore we will build a new Array $AzMGsWithRoot

        $AzMGWithRoot = @()

        # Getting the root variable
        $AzMGWithRoot_Temp = New-Object PSObject
        $AzMGWithRoot_Temp | Add-Member -MemberType NoteProperty -Name Id -Value ((Get-AzManagementGroup -GroupId $ManagementGroupName -WarningAction SilentlyContinue).id)
        $AzMGWithRoot += $AzMGWithRoot_Temp

        # Now we get the children from AzMGs
        ForEach ($Obj in $AzMGs)
            {
                $AzMGWithRoot_Temp = New-Object PSObject
                $AzMGWithRoot_Temp | Add-Member -MemberType NoteProperty -Name Id -Value $Obj.id
                $AzMGWithRoot += $AzMGWithRoot_Temp
            }
    #------------------------------------------------------------------------------------------------------------------------------------


#####################################################################################################################
# Getting Subscriptions - using Azure Resource Graph - limited to children under $ManagementGroupName
#
# Output: $AzSubs
#####################################################################################################################

        Write-Output "Getting Subscriptions from Azure Resource Graph (root: $($ManagementGroupName))"
        $AzSubs = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "resourcecontainers `
                            | where type == 'microsoft.resources/subscriptions' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	        $searchParams.Skip += $pageResults.Count
	        $AzSubs += $pageResults
        } while ($pageResults.Count -eq $pageSize)


#####################################################################################################################
# Getting Resource Groups - using Azure Resource Graph - limited to children under $ManagementGroupName
#
# Output: $AzRGs
#####################################################################################################################

        Write-Output "Getting Resource Groups from Azure Resource Graph (root: $($ManagementGroupName))"
        $AzRGs = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "resourcecontainers `
                            | where type == 'microsoft.resources/subscriptions/resourcegroups' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	        $searchParams.Skip += $pageResults.Count
	        $AzRGs += $pageResults
        } while ($pageResults.Count -eq $pageSize)


#####################################################################################################################
# Get Azure Policy Assignments, PolicyDefinitions & PolicySetDefinitions using Azure Resource Graph
# Includes all tenant-objects
#
# Output: $AzPolicyAssignments
#         $AzPolicyDefinitions
#         $AzPolicySetDefinitions
#####################################################################################################################

    #--------------------------------------------------
    # Get Azure Policy Assignments
    #--------------------------------------------------
        Write-Output "Getting Policy Assignments from Azure Resource Graph using TenantScope"
        $AzPolicyAssignments = @()

        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "policyresources `
                                    | where type == 'microsoft.authorization/policyassignments' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -UseTenantScope
	        $searchParams.Skip += $pageResults.Count
	        $AzPolicyAssignments += $pageResults
        } while ($pageResults.Count -eq $pageSize)


    #--------------------------------------------------
    # Get Azure Policy Definitions
    #--------------------------------------------------
        Write-Output "Getting Policy Definitions from Azure Resource Graph using TenantScope"
        $AzPolicyDefinitions = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "policyresources `
                                    | where type == 'microsoft.authorization/policydefinitions' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -UseTenantScope
	        $searchParams.Skip += $pageResults.Count
	        $AzPolicyDefinitions += $pageResults
        } while ($pageResults.Count -eq $pageSize)

    #--------------------------------------------------
    # Get Azure PolicySet Definitions (Initiatives)
    #--------------------------------------------------
        Write-Output "Getting PolicySet Definitions (Initiatives) from Azure Resource Graph using TenantScope"
        $AzPolicySetDefinitions = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "policyresources `
                                    | where type == 'microsoft.authorization/policysetdefinitions' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -UseTenantScope
	        $searchParams.Skip += $pageResults.Count
	        $AzPolicySetDefinitions += $pageResults
        } while ($pageResults.Count -eq $pageSize)


#####################################################################################################################
# Policy Assignment Filtering
#
# Exclusions: Global policies
#             RegularyCompliance
#####################################################################################################################

    Write-Output "Policy Assignments             : $($AzPolicyAssignments.count)"
    Write-Output " - with inheritance"
    Write-Output " - without filter (all)"

    $AzPolicyAssignments_Scope = @()
        
    # Management Groups - get direct policy assignments - excluding inherited policies from parent level
    foreach ($AzMG in $AzMGs) 
        {
            Write-Output "Getting policy assignments in $($AzMG.id)"

            $Assignm = $AzPolicyAssignments | Where-Object { $_.Properties.Scope -eq $AzMG.id }
            $AzPolicyAssignments_Scope += $Assignm
        }

    # Subscriptions - get direct policy assignments - excluding inherited policies from parent level
    foreach ($AzSub in $AzSubss) 
        {
            Write-Output "Getting policy assignments in $($AzSub.id)"

            $Assignm = $AzPolicyAssignments | Where-Object { $_.Properties.Scope -eq $AzSub.id }

            $AzPolicyAssignments_Scope += $Assignm
        }

    # Resource Group - get direct policy assignments - excluding inherited policies from parent level
    foreach ($AzRg in $AzRGs) 
        {
            Write-Output "Getting policy assignments in $($AzRg.id)"

            $Assignm = $AzPolicyAssignments | Where-Object { $_.Properties.Scope -eq $AzRg.id }

            $AzPolicyAssignments_Scope += $Assignm
        }

    Write-Output ""
    Write-Output "Doing more filtering of Azure Assignments ...."

    $PolicyCategory_RegularyCompliance = $AzPolicySetDefinitions | Where-Object { $_.properties.metadata.category -eq "Regulatory Compliance" }
    $PolicyCategory_SecurityCenter     = $AzPolicySetDefinitions | Where-Object { $_.properties.metadata.category -eq "Security Center" }

    # Remove global policy assignments
    Write-Output "  filter-away all policy with global location"
    $AzPolicyAssignments_Scope = $AzPolicyAssignments_Scope | Where-Object { $_.location -ne "global" }

    # Remove ISO 27001 policy
    Write-Output "  filter-away ISO 27001 policy"
    $AzPolicyAssignments_Scope = $AzPolicyAssignments_Scope | Where-Object { $_.properties.displayName -notlike "ISO 27001*" }

    # Remove RegularyCompliance
    Write-Output "  filter-away RegularyCompliance policies (audit)"
    $AzPolicyAssignments_Scope = $AzPolicyAssignments_Scope | Where-Object { ($_.properties.policyDefinitionId -split "/")[4] -notin $PolicyCategory_RegularyCompliance.properties.PolicyDefinitions.policyDefinitionReferenceId }

    # Remove ASC Compliance policies
    # $AzPolicyAssignments_Scope = $AzPolicyAssignments_Scope | Where-Object { ($_.properties.policyDefinitionId -split "/")[4] -notin $PolicyCategory_SecurityCenter.properties.PolicyDefinitions.policyDefinitionReferenceId }


    Write-Output ""
    Write-Output "Policy Assignments             : $($AzPolicyAssignments.count)"
    Write-Output " - without inheritance"
    Write-Output " - with filter"


#####################################################################################################################
# Task 1: Remove orphaned security principals role assignments
#
#         This is caused by deleting a  security principal (user, group, managed identity, service principal) BEFORE
#         removing any role assignment first.
#####################################################################################################################

        Write-Output ""
        Write-Output "Task 1: Orphaned security principals clean-up in progress ... Please Wait !"

        # Build array of resource tree (mg, subs, rg)

        $AzResourceTree_Scope  = $AzMGWithRoot.id  # using special array which includes root of management group in scope
        $AzResourceTree_Scope += $AzSubs.id
        $AzResourceTree_Scope += $AzRGs.id

        # Build initial array for list of orphaned accounts for deletion
        $Orphaned_Accounts_Array = @()

        $AzResourceTree_Scope_count = $AzResourceTree_Scope.count
        $Iteration = 0

        # Loop - build list of object to remove
        ForEach ($ScopeLocation in $AzResourceTree_Scope)
            {
                $Iteration += 1

                Write-Output "  [$($Iteration) / $($AzResourceTree_Scope_count)] - Checking $($ScopeLocation)"

                # Also checking if object is inherited from a parant location. Should only be object located on actual ScopeLocation
                $OrphanedAccounts = Get-AzRoleAssignment -Scope $ScopeLocation | Where-Object { ( ($_.ObjectType -eq 'Unknown') -and ($_.Scope -eq $ScopeLocation) ) }
                If ($OrphanedAccounts)
                    {
                        Write-Output ""
                        Write-Output "    Found $($OrphanedAccounts.count) orphaned security principals records"
                        Write-Output ""

                        $Orphaned_Accounts_Array += $OrphanedAccounts
                    }
            }

        # Here you can do export to CSV file or send data for approval in ticket

        # Loop - Deletion of orphaned security principals - based on array $Orphaned_Accounts_Array
        ForEach ($Entry in $Orphaned_Accounts_Array)
            {
                    Write-Output "  Removing orphaned security principals role assignment"
                    Write-output ""
                    Write-Output "  $( $Entry | ConvertTo-Json )"
                    $Entry | Remove-AzRoleAssignment
                    Write-output ""
            }


######################################################################################################################################
# Task 2: Adding role assignments for managed identities - if needed by current Azure Policy Assignments
######################################################################################################################################

    Write-output ""
    Write-Output "Task 2: Adding Role Assignments for managed identities - if needed by current Azure Policy Assignments"
    Write-output ""

    $AzPolicyAssignments_Scope_count = $AzPolicyAssignments_Scope.count
    $Iteration = 0

    # loop through all Azure Policy Assignments in scope (with filter)
    ForEach ($PolAssign in $AzPolicyAssignments_Scope)
        {
            $Iteration += 1

            Write-Output ""
            Write-Output "[$($Iteration) / $($AzPolicyAssignments_Scope_count)] - Processing $($PolAssign.name)"
            Write-Output "  Scope $($PolAssign.Properties.Scope)"

            $ActivePolicyDefintionsInAssignments = @()

            $ManagedIdObjId   = $PolAssign.Identity.principalId

            $PolDef           = $AzPolicyDefinitions | where-Object { $_.id -like "*$($PolAssign.Properties.PolicyDefinitionId)*" }

            If ($PolDef)
                {

                    Write-Output "  PolicyDefinition - $($PolDef.name)"
                    Write-output ""

                    # Policy Definition
                    If (!($PolDef.ResourceId -in $ActivePolicyDefintionsInAssignments.ResourceId) )
                        {
                            $ActivePolicyDefintionsInAssignments  += $PolDef 
                        }
                }
            Else
                {

                    # PolicySet Definition
                    $PolDef            = $AzPolicySetDefinitions | where-Object { $_.id -like "*$($PolAssign.Properties.PolicyDefinitionId)" }

                    Write-Output "  PolicySetDefinition - $($PolDef.name)"
                    Write-output ""

                    ForEach ($Entry in $PolDef.Properties.PolicyDefinitions)
                        {
                            $PolicyDefTemp = $AzPolicySetDefinitions | Where-Object { $_.Properties.PolicyDefinitions.PolicyDefinitionId -like "*$($Entry.PolicyDefinitionId)*" }
                            If (!($PolicyDefTemp.ResourceId -in $ActivePolicyDefintionsInAssignments.ResourceId) )
                                {
                                    $ActivePolicyDefintionsInAssignments += $PolicyDefTemp
                                }
                        }
                }


                #--------------------------------------------------------------------------------
                # Getting Required Managed Identity Role Assignments in Policy Definitions
                #--------------------------------------------------------------------------------

                    $ManagedIdRoles = @()

                    foreach ($Policy in $ActivePolicyDefintionsInAssignments) 
                        {
                            foreach ($RoleDefId in $Policy.Properties.PolicyRule.Then.Details.RoleDefinitionIds) 
                                {
                                    $RoleId = ($RoleDefId  -split "/")[4]

                                        if ($ManagedIdRoles -notcontains $RoleId) 
                                            {
                                                $ManagedIdRoles += $RoleId 
                                            }
                                }
                        }

                #-----------------------------------------------------------------------------------------------------------
                # Adding missing role assignments - if found
                #-----------------------------------------------------------------------------------------------------------

                    If ($ManagedIdObjId)
                        {
                            foreach ($RoleDefId in $ManagedIdRoles) 
                                {
                                    $RoleAssignment = Get-AzRoleAssignment -Scope $PolAssign.Properties.Scope -ObjectId $ManagedIdObjId -RoleDefinitionId  $RoleDefId -WarningAction SilentlyContinue

                                    if (!($RoleAssignment)) 
                                        {
                                            $RoleAssignment = New-AzRoleAssignment -Scope $PolAssign.Properties.Scope -ObjectId $ManagedIdObjId -RoleDefinitionId $RoleDefId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                            Write-output "  [$($RoleAssignment.Displayname)] - Adding $($RoleAssignment.RoleDefinitionName) role assignment"
                                        }
                                    Else
                                        {
                                            Write-output "  [$($RoleAssignment.Displayname)] - $($RoleAssignment.RoleDefinitionName) role assignment already found (SUCCESS)"
                                        }
                                }
                        }
        }
