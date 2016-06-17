# USAGE:
# InteractiveWebsiteSetup.ps1 sitename [mandatory]

# On error resume; this requires custom code to catch any exceptions gracefully.
$ErrorActionPreference = "SilentlyContinue"

###################################### functions ###########################################
Function ReadReg
{
$temp = $Args[0]
$temp1 = $Args[1]
$Val = get-itemproperty -path $temp
Return $Val.$Temp1
}


Function CreateUser
{
    param
    (
    $tuserName, $tPass
    )
        # Create a user	
	    $UserObj = [ADSI]"WinNT://$Env:ComputerName"
        $User = $UserObj.Create("User", $tuserName)
        $User.SetPassword($tPass)
        $User.UserFlags = 64 + 65536 # This sets user cannot change password and password never expires
        $User.SetInfo()
        $User.Description = $tuserName + " IUSR" #Sets the user description; may pass this as an addition input
        $User.SetInfo()
        if (!$?) {# report user not added correctly
        }
    
        $gIUSRS = [ADSI]"WinNT://$Env:ComputerName/IIS_IUSRS"
        $gIUSRS.Add($User.path)
	    if (!$?) {# report user not added to group correctly
        }
}


Function DetectIIS
{
	$sVer = ReadReg "Hklm:\Software\Microsoft\Windows NT\CurrentVersion\" "CurrentVersion"
	
	switch ($sVer)
	{
		Default
		{
			Write-Host "No operating system version provided to the function!"
		}
		"6.0"
		{
			while (!$Valid)
			{
				$strComps = @{Comp1 = "Web-Server";Comp2 = "Web-WebServer";Comp3 = "Web-Static-Content";Comp4 = "Web-Default-Doc";Comp5 = "Web-Dir-Browsing";Comp6 = "Web-Http-Errors";Comp7 = "Web-Http-Logging";Comp8 = "Web-Filtering";Comp9 = "Web-Stat-Compression";Comp10 = "Web-Mgmt-Console"}
				$a = servermanagercmd.exe -query | ? {$_ -match "\[X\].+\[Web-(Server|WebServer|Static-Content|Default-Doc|Dir-Browsing|Http-Errors|Http-Logging|Filtering|Stat-Compression|Mgmt-Console)\]"}

					if ($a.Count -gt 9){

						$Valid = $true

					}
					else{
    
						Write-Host "Components installed:" -ForegroundColor Green
						
    
						$b = $a.Count -1

    						for ($z = 0;$z -le $b;$z++){
    
    	        				for ($c = 1;$c -le 10;$c++){
        
        						#lookup against the hashtable to determine what is not installed
        						$t = "Comp" + $c
        
            						if ($strComps.$t -ne $null){
                
                    					if ($a.GetValue($z) -match $strComps.$t){
                    
                    						# Investigate trimming the whitespace and other unnecessary text
                    						$g = $a.GetValue($z).Length
                    						$f = $a.GetValue($z).LastIndexOfAny("[")
                    						$h = $g - $f
                                       
                    						Write-Host $a.GetValue($z).SubString($f + 1,$h - 2) -ForegroundColor Green
                    						$strComps.Remove($t)
                    					}
            						}
        						}
    						}
		
								foreach ($e in $strComps){
									
									Write-Host "---------------------------------------------" -ForegroundColor Yellow	
    								Write-Host "Components required:" -ForegroundColor Red
    								$e.Values | Write-Host -ForegroundColor Red
						
								}
							
						Read-Host "Please install the components and press enter"		
					}	
			}			
		}
		"6.1"
		{
			while (!$Valid)
			{
				Import-Module ServerManager
				
				$a = Get-WindowsFeature | ? {$_.Name -match "Web-(Server|WebServer|Static-Content|Default-Doc|Dir-Browsing|Http-Errors|Http-Logging|Filtering|Stat-Compression|Mgmt-Console)"}
			
					$c = $a | ? {$_.Installed -eq $true}
					
					if ($c.Count -gt 9){

						$Valid = $true

					}
					else{
						
						Write-Host "Components installed:" -ForegroundColor Green
						$a | ? {$_.Installed -eq $true} | % {Write-Host $_.Name -ForegroundColor Green }
						Write-Host "---------------------------------------------" -ForegroundColor Yellow	
    					Write-Host "Components required:" -ForegroundColor Red
						$a | ? {$_.Installed -eq $false} | % {Write-Host $_.Name -ForegroundColor Red}
						
						read-host "Please install the required components, then press enter"
					}	
			}
		}
	}
Return $Valid	
}


Function Load_WebAdmin
{
	$sVer = ReadReg "Hklm:\Software\Microsoft\Windows NT\CurrentVersion\" "CurrentVersion"
		
		switch ($sVer)
		{
			Default
			{
				Write-Host "Unsupported operating system version" -ForegroundColor Red
			}
			"6.0"
			{
				while (!$Valid)
				{
					Add-PSSnapin WebAdministration
						if (!$?) {
				  			Write-Host "Windows 2008 detected, but no PS Snapin Available - Download from: http://www.iis.net/download/PowerShell" -ForegroundColor Red
               				Read-Host "Please install the WebAdministraton SnapIn, then press enter"
            			}
            			else{
							$Valid = $true
						}
				}
			}
			"6.1"
			{
				while (!$Valid)
				{
					Import-Module WebAdministration
						if (!$?) {
                			Write-Host "Windows R2 detected, but no WebAdministration Module Available - Install via Server Manager" -ForegroundColor Red
                			Read-Host "Please install the WebAdministraton module, then press enter"
            			}
						else{
            				$Valid = $true
						}
				}	
			}
		}	
Return $Valid
}


Function Unload_WebAdmin
{
	$sVer = ReadReg "Hklm:\Software\Microsoft\Windows NT\CurrentVersion\" "CurrentVersion"
	
	switch ($sVer)
	{
		Default
		{
			Write-Host "Unsupported operating system version" -ForegroundColor Red
		}
		"6.0"
    	{
			Remove-PSSnapin WebAdministration
          		if (!$?) {
              		Write-Host "WebAdmin SnapIn removal failed" -Foregroundcolor Red
           		}
		}
		"6.1"
		{
			Remove-Module WebAdministration
          		if (!$?){
              		Write-Host "WebAdmin Module removal failed" -Foregroundcolor Red
				}
		}
	}
}				


Function CheckDomain 
{
# Checks a domain name matches an expected format

    param
    (
    $sDomainName
    )
		if ($sDomainName -notmatch "^(?!www\.)(?!\.)([a-z0-9\-\.]+)+((com)|(co\.uk)|(eu)|(org))$"){
            Write-host $sDomainName "does not match the expected format for a domain name e.g. site.com|.co.uk|.eu|.org is valid" -ForegroundColor Red
            $Valid = $false
        }
		else{
			Write-Host "Domain name meets the required format" -ForegroundColor Green	
				if ((Get-WebBinding -HostHeader $sDomainName) -or (Get-WebBinding -HostHeader "www.$sDomainName")){
    				Write-Host "Oops that binding already exists" -ForegroundColor Red
					Write-Host "Try another site name or quit?" -ForegroundColor Yellow
					$sQuestionCheck = Read-Host "A for another or Q for quit"
						switch ($sQuestionCheck)
						{
							"A"
							{
								$Valid = $false
							}
							"Q"
							{
								Unload_WebAdmin
								exit
							}
							Default
							{
								Write-host "Erm...that wasn't an option!" -ForegroundColor Red
							}
						}			
            	}	       				
				else{
					Write-Host "No binding conflicts found" -ForegroundColor Green
					$Valid = $true
				}
		}
Return $Valid	
}


Function CheckIP
{
# checks the IP address matches a general pattern
    param
    (
    $sIPAddress
    )
        if ($sIPAddress -notmatch "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"){
        	write-host $sIPAddress "does not match the expected format for an IP address" -ForegroundColor Red
            $Valid = $false
        }
        else{
            $Valid = $true
    	}	  
Return $Valid
}


Function CheckUserName
{
#Checks for a username

    param
    (
    $sUserName
    )
		# To maximum length of the username is 20 characters in pre-windows 2000 format. If the username is a domain user 
		# the maxmium is 64 characters. 
		
		if ($sUserName.Length -gt 20){
		
			write-host $sUserName "is too long" -ForegroundColor Red
            # Return false 
			$Valid = $false
		}
		else{
			if ($sUserName -notmatch "^([a-z0-9_\-\.]+)$"){
				write-host $sUserName "does not match the expected username format" -ForegroundColor Red
            	$Valid = $false        
        	}
			else{
				$Valid = $true
			}
		}	
Return $Valid
}


Function CheckPassword
{
	#checks for a password
    param
    (
	    $sPassword
    )
			
        # Check the password meets the required length and complexity
        if ($sPassword -notmatch "^.*(?=.{16,})(?=.*[a-z])(?=.*[A-Z])(?=.*[\d\W]).*$"){
            write-host $sPassword "does not meet the password requirements" -ForegroundColor Red
		    $Valid = $false
        }
		else{
			$Valid = $true
		}
	        
Return $Valid
}


Function CheckPath
{
	param
	(
	$sPath
	)		
		# Check the path exists
		if (!(Test-path $sPath)){
			# If the path exists return true
			$Valid = $false
			Write-Host $sPath "does not exist" -ForegroundColor Red
		}
		else{
			# if the path doesn't exist return false
			$Valid = $true
		}
		
Return $Valid
}


Function GetIPAddresses
{
	# Does this computer have a static IP Address?
    # If it does get the IP addresses and set the flag to true	
    for ($iRegV1 = 0; $iRegV1 -le 2; $iRegV1++){
	    for ($iRegV2 = 0; $iRegV2 -le 9; $iRegV2++){
				
	       	# The registry key below is where all network card interfaces are found
           	# we are looking for the ethernet value as this is what defines the ethernet network interfaces
		   	$sfRes = ReadReg "HKLM:\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\00$iRegV1$iRegV2\Ndi\Interfaces\" "lowerrange"
	   
            if ($sfRes -eq "ethernet"){
		      	# we are going to use the GUID contained in $iRegV1 and $iRegV2 
			  	# to find the NetCfgInstanceId
		      	$sNetCfgId = ReadReg "HKLM:\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\00$iRegV1$iRegV2\" "NetCfgInstanceId"

			  	$sNic = ReadReg "HKLM:\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\00$iRegV1$iRegV2\" "DriverDesc"
				
              	$sfRes = ReadReg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$sNetCfgId\" "EnableDHCP"
			     
                if ($sfRes -eq "0"){
                	# We have a static IP Address
					$sfRes = ReadReg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$sNetCfgId\" "IPAddress"	
					
					$sfRes | % {$_}
					
				}
            }
        }
	}
}


###################################### functions ###########################################
###################################### Declare variables ###################################
[array]$sIPAddresses = $null

[string]$serverWideAttribs = $null
[string]$sDomain = $null
[string]$sWebSitePath = $null
[string]$sOS = $Null
[string]$sVer = $null
[string]$sInstModules = $Null
[string]$sfRes =$null
[string]$sNic =$null
[string]$sNetCfgId = $null
[string]$sOS = $Null
[string]$sUserName = $null
[string]$sPassword = $null
[string]$sModName = $Null
[string]$sIP = $null
[string]$sQuestionCheck = $null

[int]$iUsrLen = 16
[int]$iRegV1 = 0
[int]$iRegV2 = 0
[int]$iY = 1
[int]$iNumber = 0
$iSiteId = 0 # This will hold a random thus i'm not sure what the best variable type to define

[bool]$bFoundModule = $False
[bool]$bFlag = $False
[bool]$Valid = $false
###################################### Declare variables ###################################
###################################### Script Start ########################################
###################################### Prerequisite checks #################################
# Is IIS installed?
# Detect the version of Windows
	while (!$Valid)
	{
		Write-Host "Checking if the IIS components are installed:" -ForegroundColor Yellow	
		$Valid = DetectIIS
		Write-Host $Valid -ForegroundColor Green
	}
# Is the powershell component installed?
# Reset validator
$Valid = $false

	while (!$Valid)
	{
		Write-Host "Checking if the WebAdministration PowerShell component is installed:" -ForegroundColor Yellow
		$Valid = Load_WebAdmin
		Write-Host $Valid -ForegroundColor Green
	}
	# Web Administraton SnapIn / Module found 
	# Unload the Administration SnapIn / Module until we need it
	[void](Unload_WebAdmin)
###################################### Prerequisite checks ###########################################
###################################### User prompts ##################################################
# Reset validator
$Valid = $false
	
	while (!$Valid)
	{
		# Prompt the user for a domain name; the domain name will be checked 
		# for uniqueness and correctness using the CheckDomain function
		[void](Load_WebAdmin)
    	$sDomain = Read-Host "Please enter the name of the site you want to create"
		Write-Host "Checking domain name format and conflicting bindings:" -ForegroundColor Yellow
    	$Valid = CheckDomain -sDomainName $sDomain
		[void](Unload_WebAdmin)
	}
	
# Reset Validator
$Valid = $false

# Ask the EU for the IP address of the site
Write-Host "IP Address(es) found on this computer:"
GetIpAddresses
	while (!$Valid)
	{
	
		$sIP = Read-Host "please enter an IP address from the list above or specify your own" 
		# Check the IP address entered
		$Valid = CheckIP -sIPAddress $sIP
	
	}

# Reset Validator
$Valid = $false
Write-Host $sIP "is a valid IP address" -ForegroundColor Green

# Ask the EU for a username or password
	while (!$Valid){

	$sQuestionCheck = Read-Host "Do you wish to specify an alternative local or domain user? [Y/N] NOTE: if you specify NO a local user will be created for you"
	
		switch ($sQuestionCheck)
		{
			default 
			{	
				Write-Host "Please enter Y for Yes or N for No" -ForegroundColor Red
			}
			Y
			{
				while (!$Valid)
				{
					$sUserName = Read-Host "Please enter a username"
					$Valid = CheckUserName -sUserName $sUserName
				}
		
				# Reset Validator
				$Valid = $false
		
				while (!$Valid)
				{
					$sPassword = Read-Host "Please enter a password" -AsSecureString
					$Valid = CheckPassword -sPassword $sPassword		
				}
	
				Write-Host "The username:" $sUserName "and password are valid" -ForegroundColor Green	
			}
			N
			{
				Write-host "Ok, i'll create a user for you" -ForegroundColor Green
				$Valid = $true
			}			
		}
	}

# Reset Validator
$Valid = $false

# Ask the EU for a web root
while (!$Valid){

	$sWebSitePath = Read-Host "Please enter a web root e.g. e:\"
	$Valid = CheckPath -sPath $sWebSitePath

}
Write-Host "The web root" $sWebSitePath "exists" -ForegroundColor Green

# Reset Validator
$Valid = $false
###################################### User prompts ##################################################
################################# Lets create the site and folder structure ##########################
# Load the WebAdministration SnapIn / Module
[void](Load_WebAdmin)

#Set server-wide configuration
#First of all let check whether anything needs configuring
$serverWideAttribs = (Get-WebConfiguration /system.webServer/security/authentication/anonymousAuthentication -PSPath IIS:\).Attributes

#Check the attributes returned from the command above; if the userName value is $null we're happy. If not it'll get set via the 
#Set-WebConfigurationProperty command.
foreach ($g in $serverWideAttribs) {
    if ($g.Name -eq "userName" -and $g.Value -eq $Null){
        Write-Host "Anonymous Authentication is already configured to use the Application Pool" -Foregroundcolor Green
    }
    else{
        Set-WebConfigurationProperty /system.webServer/security/authentication/anonymousAuthentication -Name userName -Value "" -PSPath IIS:\
    }
}

if (($sUserName -eq "") -and ($sPassword -eq "")){

    #Generate a password for the local user
    [Reflection.Assembly]::LoadWithPartialName(“System.Web”)
    $sPassword=[System.Web.Security.Membership]::GeneratePassword(15,3)

    #Append _web to the username
    if ($sDomain.Length -le 16){
		$iUsrLen = $sDomain.length
    }
	
    $sUserName = $sDomain.Substring(0,$iUsrLen) + "_web"
    
    #Pass the Username and Password to the Create User function; the username will be returned.
    CreateUser -tuserName $sUserName -tPass $sPassword

    Write-host "User created: " $sUserName " with password: " $sPassword -ForegroundColor Green
    
}
else{

	Write-Host "Using predefined user name:"$sUserName "and password:"$sPassword 

}

# Create $sWebSitePath Domains\sitename
New-Item (join-path -Path $sWebSitePath -childpath Domains\$sDomain) -type directory

# Create $sWebSitePath Domains\sitename\logs
New-Item (Join-Path -Path $sWebSitePath -childpath Domains\$sDomain\logs) -type directory

# Create $sWebSitePath Domains\sitename\wwwroot
New-Item (join-path -path $sWebSitePath -childpath Domains\$sDomain\wwwroot) -type directory

# Set list contents for local user on Domains\sitename 
# (THIS OBJECT ONLY)

$acl1 = Get-Acl (Join-Path -Path $sWebSitePath -ChildPath Domains\$sDomain)
$permission1 = $sUserName,"ReadData","Allow"
$accessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule $permission1
$acl1.SetAccessRule($accessRule1)
$acl1 | Set-Acl (Join-Path -Path $sWebSitePath -ChildPath Domains\$sDomain)

# Set Read, Execute permissions for local user on Domains\sitename\wwwroot
# Including subfolders and files

$acl2 = Get-Acl (Join-Path -Path $sWebSitePath -ChildPath Domains\$sDomain\wwwroot)
$permission2 = $sUserName,"ReadAndExecute","ContainerInherit","ObjectInherit","None","Allow"
$accessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule $permission2
$acl2.SetAccessRule($accessRule2)
$acl2 | Set-Acl (Join-Path -Path $sWebSitePath -ChildPath Domains\$sDomain\wwwroot)

# Generate a random site id
while (!$Valid)
{
$iSiteId = New-Object Random
$iSiteId = $iSiteId.Next(1,1000)

	# create a random number, check whether the random number 
	# generated conflicts with an existing site id
	if (Get-WebSite){
		# found a website
		If (Get-WebSite | ? {$_.ID -ne $iSiteId}){
	
			$Valid = $true
	
		}		
	# if the random site id conflicts loop again	
	}
	else{
		# we haven't found any existing sites so 
		# we can use the first site id generated
		$Valid = $true
	
	}
	
}

# Create App Pool
New-WebAppPool -Name $sDomain

# Assign user to app pool 
Set-ItemProperty IIS:\AppPools\$sDomain -Name processModel -Value @{userName="$sUserName";password=$sPassword;identityType="SpecificUser"}

# Create site, set binding, set wwwroot location
New-Website -id $iSiteId -Name $sDomain -Port 80 -HostHeader $sDomain -PhysicalPath (Join-Path -Path $sWebSitePath -ChildPath Domains\$sDomain\wwwroot) -IPAddress $sIP -ApplicationPool $sDomain

# Set log file location
Set-ItemProperty IIS:\Sites\$sDomain -name logFile.directory -value (join-Path $sWebSitePath -ChildPath Domains\$sDomain\logs)

# create extra bindings for www.sitename and sitename
New-WebBinding -Name $sDomain -IPAddress $sIP -Port 80 -HostHeader www.$sDomain 


# Clean up
# Snapin module
Unload_WebAdmin           

###################################### Script end ###################################>