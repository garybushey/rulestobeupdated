# rulestobeupdated
Generate a report of the analytic rules that can be updated

### SYNOPSIS
This command will generate a CSV file containing the names of all the Azure Sentinel rules that need updating
        
### DESCRIPTION
This command will generate a CSV file containing the names of all the Azure Sentinel rules that need updating
        
### PARAMETER WorkSpaceName
Enter the Log Analytics workspace name, this is a required parameter
        
### PARAMETER ResourceGroupName
Enter the Log Analytics workspace name, this is a required parameter
        
### PARAMETER FileName
Enter the file name to use.  Defaults to "solutionInformation.csv"  ".csv" will be appended to all filenames

### NOTES
**AUTHOR**: Gary Bushey  **LASTEDIT**: 19 Feb 2023
        
### EXAMPLE
`Export-AzSentinelRulesNeedingUpdates "workspacename" -ResourceGroupName "rgname"`

In this example you will get the file named "rulesNeedingUpdates.csv" generated containing all the solution information
        
### EXAMPLE
`Export-AzSentinelRulesNeedingUpdates -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"`

In this example you will get the file named "test.csv" generated containing all the solution information
