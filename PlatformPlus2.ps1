#######################################
#region ### MAJOR FUNCTIONS ###########
#######################################

###########
#region ### global:Invoke-PlatformAPI # Invokes RestAPI using either the interactive session or the bearer token
###########
function global:Invoke-PlatformAPI
{
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Specify the API call to make.")]
        [System.String]$APICall,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the JSON Body payload.")]
        [System.String]$Body
    )

    # verifying an active platform connection
    #Verify-PlatformConnection

    # setting the url based on our PlatformConnection information
    $uri = ("https://{0}/{1}" -f $global:PlatformConnection.PodFqdn, $APICall)

    # Try
    Try
    {
		# Set Security Protocol for RestAPI (must use TLS 1.2)
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Write-Debug ("Uri=[{0}]" -f $uri)
        Write-Debug ("Body=[{0}]" -f $Body)

        # making the call using our a Splat version of our connection
        $Response = Invoke-RestMethod -Method Post -Uri $uri -Body $Body @global:SessionInformation

        # if the response was successful
        if ($Response.Success)
        {
            # return the results
            return $Response.Result
        }
        else
        {
            # otherwise throw what went wrong
            Throw $Response.Message
        }
    }# Try
    Catch
    {
        $LastError = [PlatformAPIException]::new("A PlatformAPI error has occured. Check `$LastError for more information")
        $LastError.APICall = $APICall
        $LastError.Payload = $Body
        $LastError.Response = $Response
        $LastError.ErrorMessage = $_.Exception.Message
        $global:LastError = $LastError
        Throw $_.Exception
    }
}# function global:Invoke-PlatformAPI 
#endregion
###########

###########
#region ### global:Connect-DelineaPlatform # Connects the user to a Delinea PAS tenant. Derived from Centrify.Platform.PowerShell.
###########
function global:Connect-DelineaPlatform
{
	param
	(
		[Parameter(Mandatory = $false, Position = 0, HelpMessage = "Specify the URL to use for the connection (e.g. oceanlab.my.centrify.com).")]
		[System.String]$Url,
		
		[Parameter(Mandatory = $true, ParameterSetName = "Interactive", HelpMessage = "Specify the User login to use for the connection (e.g. CloudAdmin@oceanlab.my.centrify.com).")]
		[System.String]$User,

		[Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Client ID to use to obtain a Bearer Token.")]
        [System.String]$Client,

		[Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Scope Name to claim a Bearer Token for.")]
        [System.String]$Scope,

		[Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Secret to use for the ClientID.")]
        [System.String]$Secret
	)
	
	# Debug preference
	if ($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		# Debug continue without waiting for confirmation
		$DebugPreference = "Continue"
	}
	else 
	{
		# Debug message are turned off
		$DebugPreference = "SilentlyContinue"
	}
	
	try
	{	
		# Set Security Protocol for RestAPI (must use TLS 1.2)
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Delete any existing connexion cache
        $Global:PlatformConnection = [Void]$null

		if (-not [System.String]::IsNullOrEmpty($Client))
        {
            # Check if URL provided has "https://" in front, if so, remove it.
            if ($Url.ToLower().Substring(0,8) -eq "https://")
            {
                $Url = $Url.Substring(8)
            }
            
            # Get Bearer Token from OAuth2 Client App
			$BearerToken = Get-PlatformBearerToken -Url $Url -Client $Client -Secret $Secret -Scope $Scope

            # Validate Bearer Token and obtain Session details
            $Uri = ("https://{0}/Security/Whoami" -f $Url)
			$ContentType = "application/json" 
			#$Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1"; "Authorization" = ("Bearer {0}" -f $BearerToken) }
			Write-Debug ("Connecting to Delinea Platform (https://{0}) using Bearer Token" -f $Url)
			
			# Debug informations
			Write-Debug ("Uri= {0}" -f $Uri)
			Write-Debug ("BearerToken={0}" -f $BearerToken)
			
			# Format Json query
			$Json = @{} | ConvertTo-Json
			
			# Connect using Certificate
			$WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PASSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header
            $WebResponseResult = $WebResponse.Content | ConvertFrom-Json
            if ($WebResponseResult.Success)
		    {
				# Get Connection details
				$Connection = $WebResponseResult.Result
				
				# Force URL into PodFqdn to retain URL when performing MachineCertificate authentication
				$Connection | Add-Member -MemberType NoteProperty -Name CustomerId -Value $Connection.TenantId
				$Connection | Add-Member -MemberType NoteProperty -Name PodFqdn -Value $Url
				
				# Add session to the Connection
				$Connection | Add-Member -MemberType NoteProperty -Name Session -Value $PASSession

				# Set Connection as global
				$Global:PlatformConnection = $Connection

                # setting the splat
                $global:SessionInformation = @{ Headers = $PlatformConnection.Session.Headers }

                # if the $PlatformConnections variable does not contain this Connection, add it
                if (-Not ($PlatformConnections | Where-Object {$_.PodFqdn -eq $Connection.PodFqdn}))
                {
                    # add a new PlatformConnection object and add it to our $PlatformConnectionsList
                    $obj = [PlatformConnection]::new($Connection.PodFqdn,$Connection,$global:SessionInformation)
                    $global:PlatformConnections.Add($obj) | Out-Null
                }
				
				# Return information values to confirm connection success
				return ($Connection | Select-Object -Property CustomerId, User, PodFqdn | Format-List)
            }
            else
            {
                Throw "Invalid Bearer Token."
            }
        }	
        else
		{
			# Check if URL provided has "https://" in front, if so, remove it.
            if ($Url.ToLower().Substring(0,8) -eq "https://")
            {
                $Url = $Url.Substring(8)
            }

			# adding the .identity part of the URL
			$Url = $Url -replace ".delinea.app",".identity.delinea.app"

            # Setup variable for interactive connection using MFA
			$Uri = ("https://{0}/Security/StartAuthentication" -f $Url)  
			$ContentType = "application/json" 
			#$Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1" }
			$Header = @{ "x-centrify-native-client" = "true" }
			Write-Host ("Connecting to Delinea Platform (https://{0}) as {1}`n" -f $Url, $User)
			
			# Debug informations
			Write-Debug ("Uri= {0}" -f $Uri)
			Write-Debug ("Login= {0}" -f $UserName)
			
			# Format Json query
			$Auth = @{}
			$Auth.User = $User
            $Auth.Version = "1.0"
			$Json = $Auth | ConvertTo-Json
			
			# Initiate connection
			$InitialResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PASSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header

    		# Getting Authentication challenges from initial Response
            $InitialResponseResult = $InitialResponse.Content | ConvertFrom-Json
		    if ($InitialResponseResult.Success)
		    {
			    Write-Debug ("InitialResponse=`n{0}" -f $InitialResponseResult)
                # Go through all challenges
                foreach ($Challenge in $InitialResponseResult.Result.Challenges)
                {
                    # Go through all available mechanisms
                    if ($Challenge.Mechanisms.Count -gt 1)
                    {
                        Write-Host "`n[Available mechanisms]"
                        # More than one mechanism available
                        $MechanismIndex = 1
                        foreach ($Mechanism in $Challenge.Mechanisms)
                        {
                            # Show Mechanism
                            Write-Host ("{0} - {1}" -f $MechanismIndex++, $Mechanism.PromptSelectMech)
                        }
                        
                        # Prompt for Mechanism selection
                        $Selection = Read-Host -Prompt "Please select a mechanism [1]"
                        # Default selection
                        if ([System.String]::IsNullOrEmpty($Selection))
                        {
                            # Default selection is 1
                            $Selection = 1
                        }
                        # Validate selection
                        if ($Selection -gt $Challenge.Mechanisms.Count)
                        {
                            # Selection must be in range
                            Throw "Invalid selection. Authentication challenge aborted." 
                        }
                    }
                    elseif($Challenge.Mechanisms.Count -eq 1)
                    {
                        # Force selection to unique mechanism
                        $Selection = 1
                    }
                    else
                    {
                        # Unknown error
                        Throw "Invalid number of mechanisms received. Authentication challenge aborted."
                    }

                    # Select chosen Mechanism and prepare answer
                    $ChosenMechanism = $Challenge.Mechanisms[$Selection - 1]

			        # Format Json query
			        $Auth = @{}
			        $Auth.TenantId = $InitialResponseResult.Result.TenantId
			        $Auth.SessionId = $InitialResponseResult.Result.SessionId
                    $Auth.MechanismId = $ChosenMechanism.MechanismId
                    
                    # Decide for Prompt or Out-of-bounds Auth
                    switch($ChosenMechanism.AnswerType)
                    {
                        "Text" # Prompt User for answer
                        {
                            $Auth.Action = "Answer"
                            # Prompt for User answer using SecureString to mask typing
                            $SecureString = Read-Host $ChosenMechanism.PromptMechChosen -AsSecureString
                            $Auth.Answer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
                        }
                        
                        "StartTextOob" # Out-of-bounds Authentication (User need to take action other than through typed answer)
                        {
                            $Auth.Action = "StartOOB"
                            # Notify User for further actions
                            Write-Host $ChosenMechanism.PromptMechChosen
                        }
                    }
	                $Json = $Auth | ConvertTo-Json
                    
                    # Send Challenge answer
			        $Uri = ("https://{0}/Security/AdvanceAuthentication" -f $Url)
			        $ContentType = "application/json" 
			        $Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1" }
			
			        # Send answer
			        $WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PASSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header

                    # Get Response
                    $WebResponseResult = $WebResponse.Content | ConvertFrom-Json
                    if ($WebResponseResult.Success)
		            {
                        # Evaluate Summary response
                        if($WebResponseResult.Result.Summary -eq "OobPending")
                        {
                            $Answer = Read-Host "Enter code or press <enter> to finish authentication"
                            # Send Poll message to Delinea Identity Platform after pressing enter key
			                $Uri = ("https://{0}/Security/AdvanceAuthentication" -f $Url)
			                $ContentType = "application/json" 
			                $Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1" }
			
			                # Format Json query
			                $Auth = @{}
			                $Auth.TenantId = $Url.Split('.')[0]
			                $Auth.SessionId = $InitialResponseResult.Result.SessionId
                            $Auth.MechanismId = $ChosenMechanism.MechanismId
                            
                            # Either send entered code or poll service for answer
                            if ([System.String]::IsNullOrEmpty($Answer))
                            {
                                $Auth.Action = "Poll"
                            }
                            else
                            {
                                $Auth.Action = "Answer"
                                $Auth.Answer = $Answer
                            }
			                $Json = $Auth | ConvertTo-Json
			
                            # Send Poll message or Answer
			                $WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PASSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header
                            $WebResponseResult = $WebResponse.Content | ConvertFrom-Json
                            if ($WebResponseResult.Result.Summary -ne "LoginSuccess")
                            {
                                Throw "Failed to receive challenge answer or answer is incorrect. Authentication challenge aborted."
                            }
                        }

                        # If summary return LoginSuccess at any step, we can proceed with session
                        if ($WebResponseResult.Result.Summary -eq "LoginSuccess")
		                {
                            # Get Session Token from successfull login
			                Write-Debug ("WebResponse=`n{0}" -f $WebResponseResult)
			                # Validate that a valid sessdata cookie has been returned for the PASConnection
			                $CookieUri = ("https://{0}" -f $Url)

							$CookieAuth = $PASSession.Cookies.GetCookies($CookieUri) | Where-Object { $_.Name -eq "sessdata" }
			
			                if ([System.String]::IsNullOrEmpty($CookieAuth))
			                {
				                # if cookie value is empty
				                Throw ("Failed to get a sessdata cookie for Url {0}. Verify Url and try again." -f $CookieUri)
			                }
			                else
			                {
				                # Get Connection details
				                $Connection = $WebResponseResult.Result
				
				                # Add session to the Connection
				                $Connection | Add-Member -MemberType NoteProperty -Name Session -Value $PASSession

				                # Set Connection as global
				                $Global:PlatformConnection = $Connection

								# setting bearer token in special header (new for P2)
								$Header = @{ "x-centrify-native-client" = "true" ; "Authorization" = ("Bearer {0}" -f $PlatformConnection.OAuthTokens.access_token) }

								# setting the splat for variable connection
								$global:SessionInformation = @{ Header = $Header }

                                # setting the splat for variable connection (old for P1)
                                #$global:SessionInformation = @{ WebSession = $PlatformConnection.Session }
								
								# if the $PlatformConnections variable does not contain this Connection, add it
                                if (-Not ($PlatformConnections | Where-Object {$_.PodFqdn -eq $Connection.PodFqdn}))
                                {
                                    # add a new PlatformConnection object and add it to our $PlatformConnectionsList
                                    $obj = [PlatformConnection]::new($Connection.PodFqdn,$Connection,$global:SessionInformation)
                                    $global:PlatformConnections.Add($obj) | Out-Null
                                }
				
				                # Return information values to confirm connection success
				                return ($Connection | Select-Object -Property CustomerId, User, PodFqdn | Format-List)
			                }# else
                        }# if ($WebResponseResult.Result.Summary -eq "LoginSuccess")
		            }# if ($WebResponseResult.Success)
		            else
		            {
                        # Unsuccesful connection
			            Throw $WebResponseResult.Message
		            }
                }# foreach ($Challenge in $InitialResponseResult.Result.Challenges)
		    }# if ($InitialResponseResult.Success)
		    else
		    {
			    # Unsuccesful connection
			    Throw $InitialResponseResult.Message
		    }
		}# else
	}# try
	catch
	{
		Throw $_.Exception
	}
}# function global:Connect-DelineaPlatform
#endregion
###########


###########
#region ### global:TEMPLATE # TEMPLATE
###########
#function global:Invoke-TEMPLATE
#{
#}# function global:Invoke-TEMPLATE
#endregion
###########

#######################################
#endregion ############################
#######################################

#######################################
#region ### SUB FUNCTIONS #############
#######################################

#######################################
#endregion ############################
#######################################

#######################################
#region ### CLASSES ###################
#######################################

# class to hold PlatformConnections
class PlatformConnection
{
    [System.String]$PodFqdn
    [PSCustomObject]$PlatformConnection
    [System.Collections.Hashtable]$SessionInformation

    PlatformConnection($po,$pc,$s)
    {
        $this.PodFqdn = $po
        $this.PlatformConnection = $pc
        $this.SessionInformation = $s
    }
}# class PlatformConnection

# class to hold a custom PlatformError
class PlatformAPIException : System.Exception
{
    [System.String]$APICall
    [System.String]$Payload
    [System.String]$ErrorMessage
    [PSCustomObject]$Response

    PlatformAPIException([System.String]$message) : base ($message) {}

    PlatformAPIException() {}
}# class PlatformAPIException : System.Exception

#######################################
#endregion ############################
#######################################

# initializing a List[PlatformConnection] if it is empty or null
if ($global:PlatformConnections -eq $null) {$global:PlatformConnections = New-Object System.Collections.Generic.List[PlatformConnection]}