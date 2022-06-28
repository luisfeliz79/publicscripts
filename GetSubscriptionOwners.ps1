
###############################################################
#
# This Sample Code is provided for the purpose of illustration only
# and is not intended to be used in a production environment.  THIS
# SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED AS IS
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
# MERCHANTABILITY ANDOR FITNESS FOR A PARTICULAR PURPOSE.  We
# grant You a nonexclusive, royalty-free right to use and modify
# the Sample Code and to reproduce and distribute the object code
# form of the Sample Code, provided that You agree (i) to not use
# Our name, logo, or trademarks to market Your software product in
# which the Sample Code is embedded; (ii) to include a valid
# copyright notice on Your software product in which the Sample
#
# Code is embedded; and (iii) to indemnify, hold harmless, and
# defend Us and Our suppliers from and against any claims or
# lawsuits, including attorneys’ fees, that arise or result from
# the use or distribution of the Sample Code.
# Please note None of the conditions outlined in the disclaimer
# above will supersede the terms and conditions contained within
# the Premier Customer Services Description.
#
###############################################################


function Invoke-ARMAPIQuery ($Url) {

    $headers=@{

        
        "Content-Type"  = 'application/json'        
        "Authorization" = "Bearer $AccessToken"
    }

    $Uri=$URL

    #Write-Warning $Uri

    Invoke-RestMethod -Method Get -UseBasicParsing -Uri $Uri -Headers $headers -ContentType 'application/json' 

}

Function Get-ResourceByType ($type,$AccessToken,$SubscriptionFilter, $AppendKQLClause){

Write-Warning "Getting list of resource type $type ..."

If ($SubscriptionFilter.count -eq 0) {

$KQL=@"
        resources | where type == '$type'
"@
# the line above is purposedly aligned to the left due to the here string requirement

} else {

Write-warning "Using Subscription Filter: $SubscriptionFilter"

$KQL=@"
        resources | where type == '$type' | where subscriptionId matches regex "$($SubscriptionFilter -join '|')"
"@
# the line above is purposedly aligned to the left due to the here string requirement



}

if ($AppendKQLClause.Lenght -gt 0) {
    $KQL += ' | ' + $AppendKQLClause

}



return (Invoke-ResourceExplorerQuery -AccessToken $AccessToken -KQL $KQL)



}

function GetAccessTokenViaDeviceCode {
    [CmdletBinding()]
    param
    (
        # The tenant ID of the tenant to collect the OAUTH token from
        [Parameter(Mandatory = $true)]
        [System.String]
        $tenantid,

        # The resource ID of resource you want an OAUTH token for
        [Parameter(Mandatory = $true)]
        [System.String]
        $resourceid
    )
    # Known Client ID for PowerShell
    $clientid = '1950a258-227b-4e31-a9cf-717495945fc2'

    # Request device login @ Microsoft
    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
        Body   = @{
            client_id = $ClientId
            resource  = $ResourceID
        }
    }
    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams

    # Show the user a message where he/she should login
    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow

    # Poll the token site to see or the user succesfully autorized
    do {
        try {
            $TokenRequestParams = @{
                Method = 'POST'
                Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
                Body   = @{
                    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                    code       = $DeviceCodeRequest.device_code
                    client_id  = $ClientId
                }
            }
            $TokenRequest = Invoke-RestMethod @TokenRequestParams
            # Add a new line to the ouput, so it lookks better
            write-host ""
            # Return the token information
            return $TokenRequest
        }
        catch {
            if ((convertfrom-json $_.ErrorDetails.Message).error -eq "authorization_pending") {
                write-host "." -NoNewline
                Start-Sleep -Seconds 5
            }
            else {
                throw "Unkown error while requesting token"
            }
        }
    } while ($true)

}


Function GetAccessToken() {

#Get Access token
#Using PowerShell Az Module

    #Check for AZ PowerShell Module first
    $CheckModule=get-module Az.Accounts -ListAvailable
    if ($CheckModule.Name -eq 'Az.Accounts') {
        Write-warning "Found Azure PowerShell Module."
            
        $currentAzureContext = Get-AzContext
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
        $AccessToken=$profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId).AccessToken;

        if ($AccessToken -eq $null -or $AccessToken -eq "") {
            Connect-AzAccount

            $currentAzureContext = Get-AzContext
            $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
            $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
            $AccessToken=$profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId).AccessToken;
           
            if ($AccessToken -eq $null -or $AccessToken -eq "") {
                Write-warning "Could not obtain access token, quitting...";exit

            }


        }
    } else {
        #If the PowerShell Module was not found, attempt the AZ CLI Utility

        #Check if it is installed:
        $azcli=Start-Process "az" -NoNewWindow -ErrorAction SilentlyContinue -PassThru -Wait
        if ($azcli -ne $null) {
            Write-Warning "Found AZ CLI"
            $AccessToken=(az account get-access-token | convertfrom-json).accessToken
        

            if ($AccessToken -eq $null -or $AccessToken -eq "") {
                    Write-Warning "Please run az login first";exit
            }               
     
        } else {

            

        }
   }

   if ($AccessToken -eq $null -or $AccessToken -eq "") {
                    Write-warning "Could not obtain access token..";
                    Write-warning "Before you can use this script, you must install either"
                    Write-warning "      Azure PowerShell    https://aka.ms/azurepowershell"
                    Write-warning "                -- or --"
                    Write-warning "      Azure CLI           https://aka.ms/azcli"
                    exit
   }
           
   
   # If we made it this far, then
   Write-Warning "Got access token"     
   return $AccessToken

}




#region MAIN

# Obtain an Access token
#$AccessToken = GetAccessToken
$AccessToken=(GetAccessTokenViaDeviceCode -tenantid "common" -resourceid "https://management.core.windows.net/").access_token



    
    $Subs= (Invoke-ARMAPIQuery  "https://management.azure.com/subscriptions?api-version=2020-01-01").value

    $result=$Subs |  ForEach-Object {



        $Sub=$_

        Write-Warning "Processing $($Sub.DisplayName) ..."

        $Admins = Invoke-ARMAPIQuery "https://management.azure.com/subscriptions/$($Sub.SubscriptionId)/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01"

        $Admins.value.properties | ForEach-Object {


            $ServiceAdmin=($_ | where role -match "ServiceAdministrator").emailAddress
            $CoAdmins = ($_ | where role -match "CoAdministrator").emailAddress -join ", "

            [PSCustomObject]@{


                SubscriptionID=$sub.subscriptionid
                SubscriptionName=$sub.displayname
                ServiceAdministrator=$ServiceAdmin
                CoAdministrators=$CoAdmins
                State=$sub.state
                Tags=$sub.tags -join ', '
                TenantID=$sub.tenantId


            }


        }

    }

    $result | Export-Csv -NoTypeInformation -Path subowners.csv -Force
    $result | ft
    
    
    





 



#endregion