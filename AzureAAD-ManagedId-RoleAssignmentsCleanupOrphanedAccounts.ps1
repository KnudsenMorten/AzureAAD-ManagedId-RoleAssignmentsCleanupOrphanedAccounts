
Write-Output ""

#####################################################################################################################
# Variables
#####################################################################################################################

    $ManagementGroupName             = "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"


#####################################################################################################################
# Connectivity to Azure & Azure AD
#####################################################################################################################

    Connect-AzureAD
    Connect-AzAccount

    $AccessToken = Get-AzAccessToken -ResourceUrl https://management.azure.com/
    $AccessToken = $AccessToken.Token

    $headers = @{
                  'Host'          = 'management.azure.com'
                  'Content-Type'  = 'application/json';
                  'Authorization' = "Bearer $AccessToken";
                }

#####################################################################################################################
# Scope (target)
#####################################################################################################################

    # Get Azure Policy Assignments using Azure Resource Graph
        Write-Output "Getting Management Groups from Azure Resource Graph"
        $AzMg = @()
        $pageSize = 1000
        $iteration = 0
        $searchParams = @{
					        Query = "resourcecontainers `
                            | where type == 'microsoft.management/managementgroups' "
					        First = $pageSize
 			             }

        $results = do {
	        $iteration += 1
	        $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	        $searchParams.Skip += $pageResults.Count
	        $AzMg += $pageResults
        } while ($pageResults.Count -eq $pageSize)


#####################################################################################################################
# Get Azure Policy Informations (Assignments, PolicyDefinitions, PolicySetDefinitions) using Azure Resource Graph
#####################################################################################################################

    #--------------------------------------------------
    # Get Azure Policy Assignments
    #--------------------------------------------------
        Write-Output "Getting Policy Assignments from Azure Resource Graph"
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
	        $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	        $searchParams.Skip += $pageResults.Count
	        $AzPolicyAssignments += $pageResults
        } while ($pageResults.Count -eq $pageSize)


    #--------------------------------------------------
    # Get Azure Policy Definitions
    #--------------------------------------------------
        Write-Output "Getting Policy Definitions from Azure Resource Graph"
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
	        $pageResults = Search-AzGraph  @searchParams -ManagementGroup $ManagementGroupName
	        $searchParams.Skip += $pageResults.Count
	        $AzPolicyDefinitions += $pageResults
        } while ($pageResults.Count -eq $pageSize)

    #--------------------------------------------------
    # Get Azure PolicySet Definitions (Initiatives)
    #--------------------------------------------------
        Write-Output "Getting PolicySet Definitions (Initiatives) from Azure Resource Graph"
        $AzPolicySetDefinitions = Get-AzPolicySetDefinition -Builtin

#####################################################################################################################
# Policy Assignment Filtering
#####################################################################################################################

    $PolicyCategory_RegularyCompliance = $AzPolicySetDefinitions | Where-Object { $_.properties.metadata.category -eq "Regulatory Compliance" }
    $PolicyCategory_SecurityCenter     = $AzPolicySetDefinitions | Where-Object { $_.properties.metadata.category -eq "Security Center" }


    # Remove global policy assignments
    $AzPolicyAssignments = $AzPolicyAssignments | Where-Object { $_.location -ne "global" }

    # Remove Defender policies
    $AzPolicyAssignments = $AzPolicyAssignments | Where-Object { $_.properties.displayName -notlike "IAC:*" }

    # Remove ASC/MDC Compliance policies
    $AzPolicyAssignments = $AzPolicyAssignments | Where-Object { ($_.properties.policyDefinitionId -split "/")[4] -notin $PolicyCategory_SecurityCenter.properties.PolicyDefinitions.policyDefinitionReferenceId }
    $AzPolicyAssignments = $AzPolicyAssignments | Where-Object { ($_.properties.policyDefinitionId -split "/")[4] -notin $PolicyCategory_RegularyCompliance.properties.PolicyDefinitions.policyDefinitionReferenceId }

    # Remove policies from childs, which are inheritant



#####################################################################################################################
# Step 1/3: Checking for Policy Assignments managed identities requiring role assignment permissions
#####################################################################################################################

$assignmentsForRbacFix = @()

    # Step 1.1 - Get Assignments
    foreach ($scope in $scopes) 
        {
            Write-Output -InputObject " Checking assignments requiring permissions in $( $scope.id )"

            #fitler out inherited assignments and Azure Security Center
            $assignments = Get-AzPolicyAssignment -Scope $scope.id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object -FilterScript { 
                $_.Properties.Scope -eq $scope.id -and `
                -not $_.ResourceId.EndsWith('SecurityCenterBuiltIn') -and `
                $_.Identity
            }

            $assignmentsForRbacFix += $assignments
        }


    #####################################################################################################################
    # Step 1.2 - Get Assignments
    #####################################################################################################################
    foreach ($assignmentRbacFix in $assignmentsForRbacFix) 
        {
                $msiObjectId = $assignmentRbacFix.Identity.principalId

                $policyDefinitionsMSIFIX = @()

                $policyDefinition = Get-AzPolicyDefinition -Id $assignmentRbacFix.Properties.PolicyDefinitionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                if ($policyDefinition) 
                    {
                        $policyDefinitionsMSIFIX += $policyDefinition #not tested without initiative!
                    } 
                else 
                    {
                        $policySetDefinitionMSIFIX = Get-AzPolicySetDefinition -Id $assignmentRbacFix.Properties.PolicyDefinitionId
                        $policyDefinitionsMSIFIX += $policySetDefinitionMSIFIX.Properties.PolicyDefinitions | % { Get-AzPolicyDefinition -Id $_.PolicyDefinitionId }
                    }

                $requiredRoles = @()

                foreach ($policy in $policyDefinitionsMSIFIX) 
                    {

                        foreach ($roleDefinitionId in $policy.Properties.PolicyRule.Then.Details.RoleDefinitionIds) 
                            {
                                $roleId = ($roleDefinitionId  -split "/")[4]

                                    if ($requiredRoles -notcontains $roleId) 
                                        {
                                            $requiredRoles += $roleId 
                                        }
                            }
                    }

                #####################################################################################################################
                # Step 1/3: Cleanup 'unknown' role assignments
                #####################################################################################################################
                $Remove = Get-AzRoleAssignment -Scope $assignmentRbacFix.Properties.Scope -WarningAction SilentlyContinue | Where-Object -Property ObjectType -EQ 'Unknown'
                ForEach ($Entry in $Remove)
                    {

                        ##############################################################
                        # Check for resource lock
                        ##############################################################
                        $ResLock = Get-AzResourceLock -scope $Entry.scope

                        If ($ResLock)
                            {
                                Set-AzContext -Subscription ($Entry.Scope.Split("/")[2])

                                Write-Output "  Temporarely removing lock to remove assignments"
                                $Result = Remove-AzResourceLock -LockId $ResLock.LockId -Force

                                Write-Output "  Removing role assigment"
                                $Entry | Remove-AzRoleAssignment -WarningAction SilentlyContinue

                                Write-Output "  Adding lock again"
                                $Result = New-AzResourceLock   -LockName $ResLock.Name `
                                                                -LockLevel "CanNotDelete" `
                                                                -LockNotes "$($ResLock.Properties.notes)" `
                                                                -ResourceName $ResLock.ResourceName `
                                                                -ResourceType $ResLock.ResourceType `
                                                                -ResourceGroupName $ResLock.ResourceGroupName `
                                                                -force

                                Write-Output "  Removed role assignment: $( $Entry | ConvertTo-Json )"
                                Write-output ""
                            }
                        Else
                            {
                                Write-Output "  Removing role assignment"
                                $Entry | Remove-AzRoleAssignment -WarningAction SilentlyContinue

                                Write-Output "  Removed role assignment: $( $Entry | ConvertTo-Json )"
                                Write-output ""
                            }
                    }

            #####################################################################################################################
            # Step 1/3: Add role assignments
            #####################################################################################################################

                foreach ($roleDefinitionId in $requiredRoles) 
                    {
                        $roleAssignment = Get-AzRoleAssignment -Scope $assignmentRbacFix.Properties.Scope -ObjectId $msiObjectId -RoleDefinitionId  $roleDefinitionId -WarningAction SilentlyContinue

                        if (-not $roleAssignment ) 
                            {
                                $roleAssignment = New-AzRoleAssignment -Scope $assignmentRbacFix.Properties.Scope -ObjectId $msiObjectId -RoleDefinitionId $roleDefinitionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                Write-output ""
                                Write-Output -InputObject "  Added role assignment: $( $roleAssignment | ConvertTo-Json )"
                                Write-output ""
                            }            
                    }


        }
