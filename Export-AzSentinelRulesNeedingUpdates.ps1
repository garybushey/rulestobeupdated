#requires -version 6.2
<#
    .SYNOPSIS
        This command will generate a CSV file containing the names of all the Azure Sentinel
        rules that need updating
    .DESCRIPTION
        This command will generate a CSV file containing the names of all the Azure Sentinel
        rules that need updating
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to use.  Defaults to "solutionInformation.csv"  ".csv" will be appended to all filenames
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 19 Feb 2023
    .EXAMPLE
        Export-AzSentinelRulesNeedingUpdates "workspacename" -ResourceGroupName "rgname"
        In this example you will get the file named "rulesNeedingUpdates.csv" generated containing all the solution information
    .EXAMPLE
        Export-AzSentinelRulesNeedingUpdates -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
        In this example you will get the file named "test.csv" generated containing all the solution information
   
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [string]$FileName = "rulesNeedingUpdates.csv"

)
Function Export-AzSentinelRulesNeedingUpdates ($workspaceName, $resourceGroupName, $fileName) {

    #Create the object template that will be used to export the data
    $outputObject = New-Object system.Data.DataTable
    [void]$outputObject.Columns.Add('Name', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('OldVersion', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('NewVersion', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('TemplateId', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('DisplayNameChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('DescriptionChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('TacticsChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('TechniquesChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('SeverityChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('QueryChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('QueryFrequencyChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('QueryPeriodChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('TriggerOperatorChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('TriggerThresholdChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('EntityMappingsChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('AlertDetailNameChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('AlertDetailDescriptionChanged', [string]::empty.GetType() )
    [void]$outputObject.Columns.Add('AlertDetailDynamicPropertiesChanged', [string]::empty.GetType() )


    

    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $instanceProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($instanceProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    $subscriptionId = $context.Subscription.Id

    #Load the rules
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertrules?api-version=2023-02-01-preview"
    $rules = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the MS Sentinel rule templates so that we search for the information we need
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2023-02-01-preview"
    $ruleTemplates = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the rule templates from solutions
    $solutionURL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
    $query = @"
    Resources 
    | where type =~ 'Microsoft.Resources/templateSpecs/versions' 
    | where tags['hidden-sentinelContentType'] =~ 'AnalyticsRule' 
    and tags['hidden-sentinelWorkspaceId'] =~ '/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)' 
    | extend version = name 
    | extend parsed_version = parse_version(version) 
    | extend resources = parse_json(parse_json(parse_json(properties).template).resources) 
    | extend metadata = parse_json(resources[array_length(resources)-1].properties)
    | extend contentId=tostring(metadata.contentId) 
    | summarize arg_max(parsed_version, version, properties) by contentId 
    | project contentId, version, properties
"@
    $body = @{
        "subscriptions" = @($SubscriptionId)
        "query"         = $query
    }
    $solutionTemplates = Invoke-RestMethod -Uri $solutionURL -Method POST -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)

    #Check each rule
    foreach ($rule in $rules) {
        # We only want rules that come from templates.
        if ($null -ne $rule.properties.templateVersion) {
            $name = $rule.properties.displayName
            #Get the name of the template (GUID)
            $templateName = $rule.properties.alertRuleTemplateName
            $ruleVersion = $rule.properties.templateVersion
            $template = ""
            $templateVersion = ""
            #Check to see if the rule template exists in the Sentinel templates
            $foundTemplate = $ruleTemplates | Where-Object -Property "name" -EQ $templateName
            #If not found, check the solution rule templates
            if ($null -eq $foundTemplate) {
                $foundTemplate = ($solutionTemplates.data | Where-Object -Property "contentId" -EQ $templateName)
                if ($null -ne $foundTemplate) {
                    $templateVersion = $foundTemplate.version
                    #Solutions' properties are a bit more down the way.  There are actually two different "properties" 
                    #and we only care about the information in the first one
                    $template = $foundTemplate.properties.template.resources.properties[0]
                }
            }
            else {
                $templateVersion = $foundTemplate.properties.version
                $template = $foundTemplate.properties
            }
            #If a template was found and the version in the template exists  (found a couple of instances where this didn't happen)
            if (($null -ne $template) -and (-not [string]::IsNullOrWhiteSpace($templateVersion))) {
                #check to see if the versions match, if not ouput the data
                if (($null -ne $templateVersion) -and ($ruleVersion -ne $templateVersion)) {

                    #Load the arrays and make sure there is a property that can be used in the Compare-Object call
                    $ruleTactics = LoadArray $rule.properties.tactics
                    $templateTactics = LoadArray $template.tactics
                    $ruleTechniques = LoadArray $rule.properties.techniques
                    $templateTechniques = LoadArray $template.techniques
                    $ruleAlertDetailDynamic = LoadArray $rule.properties.alertDetailsOverride.AlertDynamicProperties
                    $templateAlertDetailDynamic = LoadArray $template.alertDetailsOverride.AlertDynamicProperties
                    $ruleEntities = LoadArray $rule.properties.entityMappings
                    $templateEntities = LoadArray $template.entityMappings
                
                    $newRow = $outputObject.NewRow()
                    $newRow.Name = $name
                    $newRow.OldVersion = $ruleVersion
                    $newRow.NewVersion = $templateVersion
                    $newRow.TemplateId = $templateName
                    $newRow.DisplayNameChanged = ($rule.properties.displayName -ne $template.displayName)
                    $newRow.DescriptionChanged = ($rule.properties.description -ne $template.description)
                    #Compare the two different arrays to see if there was a change
                    $newRow.TacticsChanged = $null -ne (Compare-Object $ruleTactics $templateTactics)
                    $newRow.TechniquesChanged = $null -ne (Compare-Object $ruleTechniques $templateTechniques)
                    $newRow.SeverityChanged = ($rule.properties.severity -ne $template.severity)
                    $newRow.QueryChanged = ($rule.properties.query -ne $template.query)
                    $newRow.QueryFrequencyChanged = ($rule.properties.queryFrequency -ne $template.queryFrequency)
                    $newRow.QueryPeriodChanged = ($rule.properties.queryPeriod -ne $template.queryPeriod)
                    $newRow.TriggerOperatorChanged = ($rule.properties.triggerOperator -ne $template.triggerOperator)
                    $newRow.TriggerThresholdChanged = ($rule.properties.triggerThreshold -ne $template.triggerThreshold)
                    $newRow.EntityMappingsChanged = $null -ne (Compare-Object $ruleEntities $templateEntities)
                    $newRow.AlertDetailNameChanged = ($rule.properties.alertDetailsOverride.alertDisplayNameFormat -ne $template.displayName.alertDetailsOverride.alertDisplayNameFormat)
                    $newRow.AlertDetailDescriptionChanged = ($rule.properties.alertDetailsOverride.alertDescriptionFormat -ne $template.alertDetailsOverride.alertDescriptionFormat)
                    $newRow.AlertDetailDynamicPropertiesChanged = $null -ne (Compare-Object $ruleAlertDetailDynamic $templateAlertDetailDynamic)
                    [void]$outputObject.Rows.Add( $newRow )
                }
            }
        }
    }

    $outputObject |  Export-Csv -QuoteFields "Name" -Path $fileName -Append
}

#Load the array from the value passed in and then make sure the return value has
#a value that can be used in the comparison
Function LoadArray ($arrayToCheck) {
    $returnValue = $arrayToCheck
    if (($null -eq $arrayToCheck) -or ($arrayToCheck.count -eq 0)) { 
        
        $returnValue = "1" 
    }
    return $returnValue
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
Export-AzSentinelRulesNeedingUpdates $WorkSpaceName $ResourceGroupName $FileName 
