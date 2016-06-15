# this script is used to automate fetching and installing certificates from letencrypt.org
# using ACMESharp (https://github.com/ebekker/ACMESharp) SEE QUICK START FOR MORE INFO.
#   *** run these command before running this script ***
#     Initialize-ACMEVault
#     New-ACMERegistration -Contacts mailto:somebody@example.org -AcceptTos


$name = "NAME"              #used for alias
$site = "Default Web Site"  #IIS Site Name
$dns = "example.com"        #root dns name
$aliases = @()              #web site Aliases (SAN names)
$aliases += "www.example.com"
$aliases += "mail.example.com"

function Generate-Password()
{
  $retVal = "";$data=@();For ($a=33;$a –le 126;$a++) {$data+=,[char][byte]$a }
  for($i = 0; $i -lt 20; $i++) { $retVal += ($data | GET-RANDOM) }
  return $retVal
}

$pwd = Generate-Password  #automatically generate password - you'll never be able to use pfx...
#$pwd = Read-Host "Enter pfx password" #read password from input
#$pwd = "password"  #always use a known password

$path = $PSScriptRoot #path to save pfx

$index = 1
$now = [System.DateTime]::Now.ToString("yyyyMMddHHmm")
$check = @()  # used to check challenge status
Import-module ACMESharp

$alias = "$name$now"
$check += $alias

# start root dns name
Write-Host "Creating new dns identifier`: dns`: $dns Alias`: $alias"
$void = New-ACMEIdentifier -Dns $dns -Alias $alias

#Write-Host "Creating Challenge`: dns`: $dns Alias`: $alias Site`: $site"
$void = Complete-ACMEChallenge $alias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = $site }
start-sleep 4  # sleep - had problems just running flat
#Write-Host "Submitting Challenge`: dns`: $dns Alias`: $alias Site`: $site"
$void = Submit-ACMEChallenge $alias -ChallengeType http-01
$san = @()

# request SAN names / dns slias list
for($i = 0; $i -lt $aliases.Count; $i++) {
	$cindex = $i + 1
	$cname = $aliases[$i]
	$calias = "$cname$cindex`_$now"
    Write-Host "Creating new identifier`: dns`: $cname Alias`: $calias Site`: $site"
	$void = New-ACMEIdentifier -Dns $cname -Alias $calias
	$void = Complete-ACMEChallenge $calias -ChallengeType http-01 -Handler iis -HandlerParameters @{ WebSiteRef = $site }
    start-sleep 2
	$void = Submit-ACMEChallenge $calias -ChallengeType http-01
	$san += $calias
	$check += $calias
}
function isValid($alias) {
  $status = ((update-acmeidentifier $alias -ChallengeType http-01).challenges | where { $_.Type -eq "http-01"}).Status
  if ($status -eq "invalid") { throw "Challenge is invalid for $alias" }
  return ($status -eq "valid")
}

# check for status of each challenge.
for($i = 0; $i -lt $check.Count; $i++) {
  try {
    write-host ("checking status: " + $check[$i])
    while((isValid $check[$i]) -eq $false) { 
        start-sleep -seconds 5 
        write-host ("checking status: " + $check[$i])
    }
  } catch { 
    Write-Error $_.Exception.Message
    return -1
  }
  write-host "`tReady."
}

Write-Host "Requesting Certificate..."
$void = New-ACMECertificate $alias -Generate -AlternativeIdentifierRefs $san -Alias "$name-cert-$now"
start-sleep 2
$void = Submit-ACMECertificate "$name-cert-$now"
start-sleep 2
$void = Update-ACMECertificate "$name-cert-$now"
while((Update-ACMECertificate "$name-cert-$now").IssuerSerialNumber -notmatch ".+") 
{
    Write-host "Waiting for Certificate to be finalized..." 
    start-sleep -seconds 5 
}

Write-Host "Saving Certificate"
$pfxFile = "$path$site`.$now`.pfx"
$void = Get-ACMECertificate "$name-cert-$now" -ExportPkcs12 $pfxFile -CertificatePassword $pwd


function Install-Cert([System.Security.Cryptography.X509Certificates.X509Certificate2]$pfx, [string]$name="My", [string]$location="LocalMachine")
{
	Write-Host ("Installing Cert: " + $pfx.thumbPrint + " in $name/$location")
	$store = new-object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList($name, $location)
	$store.Open("ReadWrite")
	$store.Add($pfx)
	$store.Close()
}


function Remove-Cert([System.Security.Cryptography.X509Certificates.X509Certificate2]$pfx, [string]$name="My", [string]$location="LocalMachine")
{
	$store = new-object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList($name, $location)
	$store.Open("ReadWrite")
	$store.Remove($pfx)
	$store.Close()
}

$securePassword = ConvertTo-SecureString -String $pwd -Force -AsPlainText
$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList($pfxFile, $securePassword, ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet))
if ($pfx -ne $null -and ($pfx.HasPrivateKey -eq $false))
{
	throw "Certificate does not have private key: $pfxFile"
}

Write-Host "Checking to see if certificate is already installed."
$existingCert = Get-ChildItem "Cert:\LocalMachine\My" | where {$_ -eq $pfx}
if ($existingCert -ne $null) {
	Remove-Cert $existingCert
}

#be nice and set friendly name with expire date
$pfx.FriendlyName = ("$dns - " + $pfx.NotAfter.ToString("MM/dd/yyyy"))
Write-Host "Installing Certificate"
Install-Cert $pfx

function Set-HTTPSYS-SSLCertificate([String]$ipAddress, [String]$hostname, [int]$port, [String]$thumbprint, [String]$storename=$null, [Boolean]$force=$false)
{
	Write-Host "IIS::Set-HTTPSYS-SSLCertificate($ipAddress, $hostname, $port, $thumbprint, $storename, $force)"
	$ssl = $null
	$sslByIP = $null
	$sslByHost = $null

	$added = $false
	$httpsys = $null
	[System.Collections.ArrayList]$sslBindings = New-Object System.Collections.ArrayList($null)

  # we use netsh to match SAN names in the cert to registered SNI addresses or by IP
	$result = netsh http show sslcert | out-string
	$result -split "`n\s*`n" | select-object -skip 1 | foreach-object { 
		$sb = $_
		$ssl = $null
		$matches = ($sb | select-string "\s*(?<key>.*?)\s+\:(?<value>.*)" -AllMatches).Matches
		if ($matches.Count -gt 0) {
			$matches | foreach-object {
				
				$key = ($_.Groups['key'].Value -replace "[^a-zA-Z0-9]", "_").Trim()
				$value = $_.Groups['value'].Value.Trim()
				if ($key -match "^.+$") 
				{
					if ($ssl -eq $null) { $ssl = [PsCustomObject]@{} }

					if ($value -eq "(null)") { $value = $null }
					if ($value -eq "Disabled") { $value = $false }
					if ($value -eq "Enabled") { $value = $true }
					if ($key -eq "IP_port") {
						$reipp = [regex]"^(?<ip>.*)\:(?<port>\d+)$"
						$match = $reipp.Match($value)
						if ($match.Success) {
							Add-Member -InputObject $ssl -MemberType NoteProperty -Name ip -Value $match.Groups["ip"].Value
							Add-Member -InputObject $ssl -MemberType NoteProperty -Name port -Value ([int]($match.Groups["port"].Value))
						}
					}
					if ($key -eq "Hostname_port") {
						$reipp = [regex]"^(?<ip>.*)\:(?<port>\d+)$"
						$match = $reipp.Match($value)
						if ($match.Success) {
							Add-Member -InputObject $ssl -MemberType NoteProperty -Name ip -Value $match.Groups["ip"].Value
							Add-Member -InputObject $ssl -MemberType NoteProperty -Name port -Value ([int]($match.Groups["port"].Value))
						}
					}
					Add-Member -InputObject $ssl -MemberType NoteProperty -Name "$key" -Value $value
				}
			}
		}
		if ($ssl -ne $null) {
			if ($sslByIP -eq $null -and $ssl.port -eq $port -and (($ssl.ip -eq "0.0.0.0" -and $ipAddress -eq "*") -or ($ssl.ip -eq $ipAddress))) {
				$sslByIP = $ssl
			}
			if ($sslByHost -eq $null -and $ssl.port -eq $port -and $ssl.ip -eq $hostname) {
				$sslByHost = $ssl
			}
		}

	}

	function Has-NoteProperty($obj, [String]$name) {
		return ((Get-Member -inputobject $obj -name $name -Membertype Properties) -ne $null)
	}

	$ssl = $null
	$identifier = "ipport"
	if ($sslByIP -ne $null) { $ssl = $sslByIP }
	if ($sslByHost -ne $null) { 
		Write-Host ("HTTP.SYS: Found Match by Host`: " + $sslByHost.ip + " = " + $hostname + " (" + $ssl.Hostname_port  + ")")
		$ssl = $sslByHost 
		$identifier = "hostnameport"
	} else {
		if ($ssl -ne $null) { Write-Host ("HTTP.SYS: Found Match by IP: " + $ssl.IP_port) }
	}


	if ($ssl -ne $null) {
		if ($ssl.Certificate_Hash.ToLower() -ne $thumbprint.ToLower() -or $force) {
			if ($storename -match "^\s*$") { $storename = $ssl.Certificate_Store_Name }
			Write-Host ("HTTP.SYS: Removing SSL certificate: $identifier=" + $ssl.ip + ":" + $ssl.port)
			$cmd = ("http delete sslcert $identifier=" + $ssl.ip + ":" + $ssl.port)
			$cmd | netsh
			$cmd = ("http add sslcert $identifier=" + $ssl.ip + ":" + $ssl.port + " certhash=" + $thumbprint.ToLower() + " appid=" + $ssl.Application_ID + " certstorename=" + $storename)
			if ((Has-NoteProperty $ssl "Verify_Client_Certificate_Revocation") -and $ssl.Verify_Client_Certificate_Revocation -eq $false) { $cmd += " verifyclientcertrevocation=disable" }
			if ((Has-NoteProperty $ssl "Verify_Revocation_Using_Cached_Client_Certificate_Only") -and $ssl.Verify_Revocation_Using_Cached_Client_Certificate_Only -eq $true) { $cmd += " verifyrevocationwithcachedclientcertonly=enable" }
			if ((Has-NoteProperty $ssl "Usage_Check") -and $ssl.Usage_Check -eq $false) { $cmd += " usagecheck=disable" }
			if ((Has-NoteProperty $ssl "Ctl_Identifier") -and $ssl.Ctl_Identifier -match "^.+$") { $cmd += (" sslctlidentifier=" + $ssl.Ctl_Identifier) }
			if ((Has-NoteProperty $ssl "Ctl_Store_Name") -and $ssl.Ctl_Store_Name -match "^.+$") { $cmd += (" sslctlstorename=" + $ssl.Ctl_Store_Name) }
			if ((Has-NoteProperty $ssl "Revocation_Freshness_Time") -and $ssl.Revocation_Freshness_Time -match "^[1-9]") { $cmd += (" revocationfreshnesstime=" + $ssl.Revocation_Freshness_Time) }
			if ((Has-NoteProperty $ssl "URL_Retrieval_Timeout") -and $ssl.URL_Retrieval_Timeout -match "^[1-9]") { $cmd += (" urlretrievaltimeout=" + $ssl.URL_Retrieval_Timeout) }
			if ((Has-NoteProperty $ssl "DS_Mapper_Usage") -and $ssl.DS_Mapper_Usage -eq $true) { $cmd += "dsmapperusage=enable" }
			if ((Has-NoteProperty $ssl "Negotiate_Client_Certificate") -and $ssl.Negotiate_Client_Certificate -eq $true) { $cmd += " clientcertnegotiation=enable" }
			Write-Host "HTTP.SYS: Adding SSL Certificate: netsh $cmd"
			$cmd | netsh

		} else {
			Write-Host ("HTTP.SYS: " + $ssl.IP_port + " already has thumbprint: " + $thumbprint)
		}
	}
	else 
	{
		Write-Host "HTTP.SYS: No match found for binding"
	}
}

function Site-HasHost([object]$site, [String]$hostname, [Boolean]$httpsOnly=$false)
{
	$verbose = $false

	$regexHostname = $hostname.replace("*", "[^\.]+").replace(".", "\.")
    foreach($binding in $site.Bindings.Collection)
    {
        if ($httpsOnly -eq $false -and $binding.protocol -eq "http" -and $binding.bindingInformation -match ("^[^:]+\:[^:]+\:" + $regexHostname + "$"))
        {
            return $true
        }
        if ($binding.protocol -eq "https")
        {
			if ($verbose) { Write-Host ("Site: " + $site.Name + " - checking binding: "+ $binding.bindingInformation) }
            #if the host is "", then we will have to look at the cert
            if ($binding.bindingInformation -match ("^.*?\:.*?\:$"))
            {
                $match = [regex]::match($binding.bindingInformation,'^(.*?)\:(.*?)\:$');
                $ip = $match.Groups[1].Value
                if ($ip -eq "*") { $ip="0.0.0.0" }
                $port = $match.Groups[2].Value
                $cert = get-item "IIS:\sslBindings\$ip!$port" | select Store, Thumbprint
                $cert = get-item ("cert:\LocalMachine\" + $cert.Store + "\" + $cert.Thumbprint) 
                if ($cert.Subject -match ("^CN=\s*" + $hostname.replace(".", "\.").replace("*", "\*") +"\s*,"))
                {
 					if ($verbose) { Write-Host ("`tSite: " + $site.Name + " - checking match: ("+ $cert.Subject + " -match ""^CN=\s*" + $hostname.replace(".", "\.").replace("*", "\*") +"\s*,"") =true") }
					return $true
                }
				else
				{
					if ($verbose) { Write-Host ("`tSite: " + $site.Name + " - checking match: ("+ $cert.Subject + " -match ""^CN=\s*" + $hostname.replace(".", "\.").replace("*", "\*") +"\s*,"") =false") }
				}
				#check san names...
				$sanNames = ($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"})
				if ($sanNames -ne $null)
				{
					$sanNames.Format(1) | foreach-object {
						$dnsName = [regex]::match($_, "^[^=]+=([^,]+)(,|$)").Groups[1].Value
						if ($dnsName -Match $regexHostname)
						{
							if ($verbose) { Write-Host ("`tSite: " + $site.Name + " - checking match: ("+ $dnsName + " -match $regexHostname) =true") }
							return $true
						}
						else
						{
							if ($verbose) { Write-Host ("`tSite: " + $site.Name + " - checking match: ("+ $dnsName + " -match $regexHostname) =false") }
						}
					}
				}

            }
            else
            {
                if ($binding.bindingInformation -match ("^[^:]+\:[^:]+\:" + $regexHostname + "$"))
                {
                    return $true
                }
            }
        }
    }
    return $false
}

function Set-SSLCertificate([System.Security.Cryptography.X509Certificates.X509Certificate2] $cert, [string]$storeName = "My", [Boolean]$force = $false)
{
	#if ($cert -eq $null) { throw "Certificate is null." }
	#if ($cert.HasPrivateKey -eq $false) { throw "Certificate does not contain private key." }
	Import-Module WebAdministration

	$dnsNames = @()
	$cn = [regex]::match($cert.Subject, "^CN=([^,]+)(,|$)").Groups[1].Value
	$dnsNames += $cn
	Write-Host ("Setting IIS Bindings for Certificate: $cn, " + $cert.GetCertHashString() + ", Expires=" + $cert.NotAfter.ToString("MM/dd/yyyy"))
	if ($verbose) { Write-Host ("Adding: $cn") }
	$sanNames = ($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"})
	if ($sanNames -ne $null)
	{
		[regex]::matches($sanNames.Format(1), "^DNS Name=(.*)$", 'MultiLine') | foreach-object {
			$dnsName = $_.Groups[1].Value.Trim()
			if (!($dnsNames -contains $dnsName))
			{
				if ($verbose) { Write-Host "Adding: $dnsName" }
				$dnsNames += $dnsName
			}
		}
	}

	$dnsNames | foreach-object { 
		$dnsName = $_

		Write-Host "Finding sites for: $dnsName"
		Get-ChildItem "IIS:\Sites" | where-object { (Site-HasHost $_ $dnsName $true) -eq $true } | foreach-object {
			$site = $_
			$site.Bindings.Collection | where-object { $_.protocol -eq "https" } | foreach-object {
				$bindingParts = $_.bindingInformation.split(':')
				$ipAddress = $bindingParts[0]
				if ((! $ipAddress) -or ($ipAddress -eq '*')) {
					$ipAddress = "0.0.0.0"
				}
				$port = $bindingParts[1]
				$hostname = $bindingParts[2]
				$sslBindingsPath = ("IIS:\SslBindings\" + $ipAddress + "!" + $port)
				Write-Host ("`tFound Match: """ + $site.Name + """ - $ipAddress`:$port`:$hostname")
				Set-HTTPSYS-SSLCertificate $ipAddress $hostname $port $cert.Thumbprint $storeName $force
			}
		}
	}
}

Set-SSLCertificate $pfx


