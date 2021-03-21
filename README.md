<p align="center">
  <img width="669" height="349" src="https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync/blob/main/img/AzureADDirectoryRoleMemberSync_Preview.png">
</p>

<br/>
<br/>

If you have an **AzureAD hybrid context** and you've tried to use *an on-premises synced group* as member of one of the **AzureAD Directory Roles**, probably you've found out that this option isn't currently [supported](https://docs.microsoft.com/en-us/azure/active-directory/roles/groups-concept#limitations). I enjoyed developing this script to find a workaround, and to let you **synchronize** a group's membership with one (*or more than one*, if needed) AzureAD Directory Role membership using **GraphAPIs** and **Certificate Token**.

<br/>
<br/>

### Improvement:
- Use **Certificate** to request a *Token*, so you can override limits against Admin (**with MFA**) interaction and schedule

- Avoid managing **ClientID** and **ClientSecret** (even if *alternative*, **are always a Username and a Password!**)

- Use **GraphAPIs**, instead of *AzureAD powershell module*

<br/>
<br/>

### Prerequisites:
- Create a Certificate (with [*New-SelfSignedCertificate.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#new-selfsignedcertificateps1) script you can generate a Self-Signed Certificate)

- [Create](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application) an **App Registration** in Azure
  
  - [Assign](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis#application-permission-to-microsoft-graph) the following **Application Permission** :
    
    - Directory.Read.All
    - Directory.ReadWrite.All
    - RoleManagement.Read.Directory
    - RoleManagement.ReadWrite.Directory

  - [Upload](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-a-certificate) the above **Certificate** to the **App Registration** in Azure 
  
- *Modify* the following variables in the [*New-SelfSignedCertificate.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#new-selfsignedcertificateps1) script with your Tenant reference:
``` powershell
    $TenantName = "contoso.onmicrosoft.com"
```
- *Modify* the following variables in the [*AzureADDirectoryRoleMemberSync.ps1*](https://github.com/sbotticelli/AzureADDirectoryRoleMemberSync#azureaddirectoryrolemembersyncps1) script with your Tenant, Certificate and ObjectIDs reference:
```powershell    
    $TenantId = "contoso.onmicrosoft.com"
    $AppId = ""
    $thumbprint = ""
    $RoleObjIDs = "",""  #(this varable represents an array of one [or more than one - comma separated] Directory Role ObjectID
    $OnPremGrpObjID = ""
```

<br/>
<br/>

### Code:

<br/>

#### New-SelfSignedCertificate.ps1:
```powershell
$TenantName        = "contoso.onmicrosoft.com"
$CerOutputPath     = ".\$($TenantName)_AzureADPowerShellGraphAPICert.cer"
$StoreLocation     = "Cert:\CurrentUser\My"
$ExpirationDate    = (Get-Date).AddYears(2)
$CreateCertificateSplat = @{
    FriendlyName      = "AzureApp"
    DnsName           = $TenantName
    CertStoreLocation = $StoreLocation
    NotAfter          = $ExpirationDate
    KeyExportPolicy   = "Exportable"
    KeySpec           = "Signature"
    Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    HashAlgorithm     = "SHA256"
}
$Certificate = New-SelfSignedCertificate @CreateCertificateSplat
$CertificatePath = Join-Path -Path $StoreLocation -ChildPath $Certificate.Thumbprint
Export-Certificate -Cert $CertificatePath -FilePath $CerOutputPath | Out-Null
```

<br/>

#### AzureADDirectoryRoleMemberSync.ps1:
```powershell
$TenantId = "contoso.onmicrosoft.com"
$AppId = ""
$thumbprint = ""
$RoleObjIDs = "",""
$OnPremGrpObjID = ""

$data = Get-Date
$logFile = ".\AzureADDirectoryRoleMemberSync_status_"+$data.year+$data.Month+$data.Day+"_"+$data.Hour+$data.Minute+".csv"
"RoleID,GroupID,UserUPN,UserDisplayName,ActionType,ActionResult" >> $logFile

Function Get-AccessTokenFromCertificate()
{
    $Certificate = Get-Item "Cert:\CurrentUser\My\$thumbprint"
    $Scope = "https://graph.microsoft.com/.default"
    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
    $JWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    }
    $JWTPayLoad = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        exp = $JWTExpiration
        iss = $AppId
        jti = [guid]::NewGuid()
        nbf = $NotBefore
        sub = $AppId
    }
    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
    $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
    $JWT = $EncodedHeader + "." + $EncodedPayload
    $PrivateKey = $Certificate.PrivateKey
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $Signature = [Convert]::ToBase64String(
        $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
    ) -replace '\+','-' -replace '/','_' -replace '='
    $JWT = $JWT + "." + $Signature
    $Body = @{
        client_id = $AppId
        client_assertion = $JWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope = $Scope
        grant_type = "client_credentials"
    }
    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Header = @{
        Authorization = "Bearer $JWT"
    }
    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $Body
        Uri = $Url
        Headers = $Header
    }
    $global:Request = Invoke-RestMethod @PostSplat
    Write-Host $global:Request.access_token -ForegroundColor Cyan
    $global:Head = @{
        Authorization = "$($global:Request.token_type) $($global:Request.access_token)"
    }
}

Write-Host "####################### REQUESTED NEW ACCESS TOKEN ########################" -ForegroundColor DarkCyan
Get-AccessTokenFromCertificate
Write-Host "###########################################################################" -ForegroundColor DarkCyan

foreach ($RoleObjID in $RoleObjIDs)
{

Write-Host "################### $RoleObjID ##################" -ForegroundColor DarkCyan  
$user = $null

    ########## CHECK ROLE MEMBERS ##########
    $ROLEResult = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleObjID/members" -Headers $global:Head
    $RoleMembers = $ROLEResult.value.Id
    ########################################

    ##########  CHECK GRP MEMBERS ##########
    $GRPResult = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$OnPremGrpObjID/members" -Headers $global:Head
    $grpMembers = $GRPResult.value.Id
    ########################################

    if (([string]::IsNullOrEmpty($RoleMembers)))
    {
        foreach ($member in $grpMembers)
        {
            ########## CHECK USERS ##########
            $User = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$member" -Headers $global:Head
            #################################
            Write-Host "User to add: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor DarkYellow -NoNewline

            try
            {
                
                ########## ADD USERS IN ROLE ##########
                $body = @{"@odata.id"="https://graph.microsoft.com/v1.0/directoryObjects/$member"} | ConvertTo-Json
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleObjID/members/`$ref" -Headers $global:Head -Method Post -Body $body -ContentType "application/json"
                #######################################

                Write-Host "[OK] - User added" -ForegroundColor Green  
                "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Add,OK" >> $logFile
            }
            catch
            {
                Write-Host "[ERR] - User not added: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor Red  
                "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Add,ERR" >> $logFile
            }
        }

        Write-Host "No Users to remove!" -ForegroundColor DarkCyan
        "$RoleObjID,$OnPremGrpObjID,,,No Users to remove,INFO" >> $logFile
    }
    else
    {

        $UsersToRemove = Compare-Object $grpMembers $RoleMembers | ?{$_.SideIndicator -eq "=>"}
        $UsersToAdd = Compare-Object $grpMembers $RoleMembers | ?{$_.SideIndicator -eq "<="}

        if (!([string]::IsNullOrEmpty($UsersToRemove.InputObject)))
        {
            $UsersToRemove.InputObject | %{
        
                ########## CHECK USERS ##########
                $User = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$_" -Headers $global:Head
                #################################
                Write-Host "User to remove: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor DarkYellow -NoNewline 
                try
                {
                
                    ########## REMOVE USERS IN ROLE ##########
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleObjID/members/$_/`$ref" -Headers $global:Head -Method Delete
                    ##########################################

                    Write-Host "[OK] - User removed" -ForegroundColor Green  
                    "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Remove,OK" >> $logFile
                }
                catch
                {
                    Write-Host "[ERR] - User not removed: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor Red  
                    "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Remove,ERR" >> $logFile
                }
            }
        }
        else
        {
            Write-Host "No Users to remove!" -ForegroundColor DarkCyan
            "$RoleObjID,$OnPremGrpObjID,,,No Users to remove,INFO" >> $logFile
        }

        if (!([string]::IsNullOrEmpty($UsersToAdd.InputObject)))
        {
            $UsersToAdd.InputObject | %{

                ########## CHECK USERS ##########
                $User = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$_" -Headers $global:Head
                #################################
                Write-Host "User to add: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor DarkYellow -NoNewline  
                try
                {
                
                    ########## ADD USERS IN ROLE ##########
                    $body = @{"@odata.id"="https://graph.microsoft.com/v1.0/directoryObjects/$_"} | ConvertTo-Json
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$RoleObjID/members/`$ref" -Headers $global:Head -Method Post -Body $body -ContentType "application/json"
                    #######################################

                    Write-Host "[OK] - User added" -ForegroundColor Green  
                    "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Add,OK" >> $logFile
                }
                catch
                {
                    Write-Host "[ERR] - User not added: $($user.UserPrincipalName) - $($user.DisplayName)" -ForegroundColor Red  
                    "$RoleObjID,$OnPremGrpObjID,$($user.UserPrincipalName),$($user.DisplayName),Add,ERR" >> $logFile
                }
            }
        }
        else
        {
            Write-Host "No Users to add!" -ForegroundColor DarkCyan
            "$RoleObjID,$OnPremGrpObjID,,,No Users to add,INFO" >> $logFile
        }
    }
}

Write-Host "############################## FUNCTION ENDED #############################" -ForegroundColor DarkCyan
```
<br/>
<br/>
<br/>



