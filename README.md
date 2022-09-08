# PlatformPlus2
A PowerShell-based enhancement script to programmatically interact with Delinea P2 tenants once you are authenticated. This script provides new functions and classes to work with data within your P2 tenant.

## Installation

To install the script via the command line, run the following:
```
(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/delineaps/PlatformPlus2/main/PlatformPlus2.ps1').Content | Out-File .\PlatformPlus.ps1
```

## Running the script

If scripts are not allowed to be run in your environment, an alternative method is the run the following once the script is downloaded:

```
([ScriptBlock]::Create((Get-Content .\PlatformPlus2.ps1 -Raw))).Invoke()
```

Alternatively, for a completely scriptless run, where the script's contents is retrieved from the internet, and immediately executed as a ScriptBlock object (basically combining the previous cmdlets):
```
([ScriptBlock]::Create(((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/delineaps/PlatformPlus2/main/PlatformPlus2.ps1').Content))).Invoke()
```

## Requirements

This script has only one requirement:
 - Authenticated to your P2 tenant via the Connect-DelineaPlatform cmdlet.
   - You can authenticated either interactively or using a bearer token, it does not matter. Only that the $PlatformConnection variable exists.

All results are based on your existing tenant permissions. If you are not getting expected results, ensure that your tenant permissions are accurate.

This script does not require privilege elevation to run.

### Invoke-PlatformAPI

This function enables you to make a basic RestAPI call with simple syntax. A JSON body can be provided for RestAPI calls that require it.

#### Syntax
```
PS:> Invoke-PlatformAPI [-APICall] <string> [[-Body] <string>] [<CommonParameters>]
```
 - APICall - The RestAPI call to make, remove the leading /.
   - for example: "Security/whoami"
 - Body - The JSON body payload. Must be in JSON format.

#### Example
```
PS:> Invoke-PlatformAPI -APICall Security/whoami

TenantId                              User              UserUuid
--------                              ----              --------
aaaaaaaa-0000-0000-0000-eeeeeeeeeeee  user@domain       aaaaaaaa-0000-0000-0000-eeeeeeeeeeee
````
