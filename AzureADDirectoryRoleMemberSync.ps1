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
