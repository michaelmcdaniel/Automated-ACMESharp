# Automated-ACMESharp
Powershell script that can be used to automate installation of <a href="http://letsencrypt.org/">letsencrypt.org</a> certificates using <a href="https://github.com/ebekker/ACMESharp">ACMESharp</a>

---
Do you want to just have your single server update it's own free certificates using Let's Encrypt?  Download <a href="https://github.com/michaelmcdaniel/Automated-ACMESharp/raw/master/RenewCertificate.ps1">RenewCertificate.ps1</a> 
and add as a scheduled task to run every 2 months!  That's right, Free Automated Certificate Installation.

After downloading the powershell script, update the following parameters:<br/>
$name = "NAME"              # This is just a friendly name used as the site identifier by ACMESharp<br/>
$site = "Default Web Site"  # This is the IIS Site Name that has the bindings you need<br/>
$dns = "example.com"        # This is the root dns name<br/>

<i>Add your aliases!</i><br/>
$alias += "www.example.com"<br/>
$alias += "ftp.example.com"<br/>

$pwd = Generate-Password  # or don't and use something you know.

*PFX files will be stored in the same directory that the script gets run in.*

If you've never used ACMESharp, don't forget to initalize the vault and agree to the terms of service!  See ACMESharp for more details.
<pre>
PS:> Import-Module ACMESharp
PS:> Initialize-ACMEVault
PS:> New-ACMERegistration -Contacts mailto:somebody@example.org -AcceptTos
</pre>


---

To set up a scheduled task, create a batch file that runs the script. <br/>
<div>
<label>run.bat</label><br/>
<pre>c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe "c:\powershell\renewcertificate.ps1"</pre>
</div>

Open Task Scheduler<br/>
Create Basic Task...<br/>
Set Monthly Trigger to every other month<br/>
Action: Start a program</br/>
Select your batch file<br/>

---

<h4>Notes</h4>
This script assumes that you already have https bindings for your sites.  It replaces the certificate using netsh using 
the matching bindings that it finds for the certificate.  







