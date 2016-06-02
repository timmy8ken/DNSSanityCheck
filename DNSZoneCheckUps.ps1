function Get-DNSScavengingStatus {
    <#
.SYNOPSIS
Get DNS zone and server Scavenging status

.DESCRIPTION
The purpose of this function is to check that scavenging is enabled on specified DNS servers and zones. It will also check to see which DNS records will be scavenged based on the timestamp of redords.

.PARAMETER dnsServer
This parameter is for the DNS server it can be provided in either IP address, hostname or fully qualified domain name. However the last two must be resolvable by DNS, so in cross forest situations the best option is IP address or FQDN. 
There is a parameter validation process that will check to see if the provided host is actually a DNS server.

.PARAMETER path
This parameter is for the location the script will use to export the scavengable records. If this parameter is not provided then the script will not export the scavengable records to a file and will just be provided in the resultant object.
The path has to exist and there is parameter validation that will check for the path before proceeding with the script.

.EXAMPLE
Get-DNSScavengingStatus -dnsServer 10.10.10.10

This will run the script against the server 10.10.10.10 and will check against all zones that are primary, not automatically created and not the 'TrustAnchors' zone.  

.EXAMPLE
PowerShell will number them for you when it displays your help text to a user.

.OUTPUT
PowerShell Custom Object. The output has the details of the DNS Sscavenging as custom PowerShell object
#>
      Param(
        [parameter(ValueFromPipeline)]
        [ValidateScript({
        If (-not ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')) {
            
            $ipAddress = (Resolve-DnsName $_).IpAddress
            
        } else {
            
            $ipAddress = $_
            
        
        }
        If ((Test-DnsServer -ComputerName $_ -IPAddress $ipaddress).result -eq "Success") {
                $True
                
            } Else {
                Throw "$ipAddress ($_) is not a DNS Server!"
            }
        })]
        [string]$dnsServer,

        [parameter(HelpMessage="The location that the script will export the scavengable DNS records")]
        [ValidateScript({
            if (Test-Path -Path $_) {
                
                $true
            
            } else {
                
                throw "$_ is not a valid path, either create the path or use an alternate location."
            
            }
        
        })]
        [string]$path = $null
)

        $results = @()
        
        
        #Get All zones
        $zones = Get-DnsServerZone -ComputerName $dnsServer | Where-Object {$_.ZoneType -eq 'Primary' -and $_.IsAutoCreated -eq $false -and $_.ZoneName -ne 'TrustAnchors'} | Select-Object -ExpandProperty ZoneName

        foreach ($zone in $zones) {

        $alert = $false
        $alertMessage = @()

            #Confirm Scavenging is enabled on the zone
            $agingStatus = Get-DnsServerZoneAging -ComputerName $dnsServer -Name $zone
            
            
            if ($agingStatus.AgingEnabled -eq $false) {

                $alert = $true
                $alertMessage += "$($zone) does not have Scavenging enabled"
                    
            }
            
            #Check that Scavenging server has scavenging enabled
            $scavengingServerStatus = Get-DnsServerScavenging -ComputerName $agingStatus.ScavengeServers

            if ($scavengingServerStatus.ScavengingState -eq $false)  {

                $alert = $true
                $alertMessage += "$($dnsServer) does not have scavenging enabled"

            }

            <# Check the records to be deleted at next scavenge and write them to a file #>
   
            $scavengableRecords = Get-DnsServerResourceRecord -ZoneName $zone -ComputerName $dnsServer | where {$_.TimeStamp -lt (Get-Date).adddays(-14) -and $_.timeStamp -ne $null} 
            
            #Variable to hold the scavengable records custom object
            $objRecords = @()
            if ($scavengableRecords) {

                

                foreach ($record in $scavengableRecords) {
                    $objRecords += [pscustomobject]@{
                        Zone = $zone
                        Hostname = $record.Hostname
                        RecordType = $record.RecordType
                        TimeStamp = if ($record.TimeStamp) {
                                    
                                        $record.TimeStamp

                                    } else {
                                    
                                        "Static"

                                    }
                        RecordData = switch ($record.RecordType) { 
                                        A {$record.recordData.IPv4Address.IPAddressToString} 
                                        AAAA {$record.RecordData.IPv6Address.IPv6AddressToString}
                                        PTR {$record.RecordData.ptrDomainname} 
                                        SRV {(@($record.RecordData.Weight,$record.RecordData.Priority,$record.RecordData.Port,$record.RecordData.DomainName) -join ',')} 
                                        MX {(@($record.RecordData.Preference,$record.RecordData.MailExchange) -join ',')} 
                                        NS {$record.RecordData.NameServer} 
                                        CNAME {$record.RecordData.HostnameAlias} 
                                        SOA {(@($record.RecordData.SerialNumber,$record.RecordData.PrimaryServer,$record.RecordData.ResponsiblePerson,$record.RecordData.ExpireLimit) -join ',')}
                                        default {"The Record Type could not be resolved"}
                                    }

                    } 
            } 
            
            if ($path) {

                $objRecords | export-csv "$path\$(Get-Date -UFormat %Y%m%d)_ScavengableRecords_$($dnsServer)_$($zone).csv" -NoTypeInformation

            }
            
            
            }
                

            $objHash = @{
                ZoneName = $zone
                ZoneScavengingServer = $agingStatus.ScavengeServers
                Alert = $alert
                AlertMessage = $alertMessage
                ScavengableRecords = $objRecords.HostName
                

            }
            
            $results += New-Object PSObject -Property $objHash

            

        }

      $results  
}


function backup-DNSZones {
    
      Param(
        [parameter(ParameterSetName='base',Mandatory)]
        [parameter(ParameterSetName='email')]
        [ValidateScript({
        If (-not ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')) {
            
            $ipAddress = (Resolve-DnsName $_).IpAddress
            
        } else {
            
            $ipAddress = $_
            
        
        }
        If ((Test-DnsServer -ComputerName sydwindca -IPAddress $ipaddress).result -eq "Success") {
                $True
                
            } Else {
                Throw "$ipAddress ($_) is not a DNS Server!"
            }
        })]
        [string]$dnsServer,

        [parameter(ParameterSetName='email')]
        [switch]$email,

        [parameter(ParameterSetName='email',Mandatory)]
        [validateScript({
        
            if ($_ -match '^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$') {
                $true
            }
            else {
                Throw "$_ is not a valid email address."
            }

        })]
        [string]$toAddress,

        [parameter(ParameterSetName='email')]
        [ValidateScript({
            if ((test-Netconnection $_ -Port 25).TcpTestSucceeded -eq $true) {
                $true
            } else {
                throw "$_ is not responding onport 25, is it a mail server?"
            }

        })]
        [string]$smtpServer = 'email.syd.com.au'
    )

    #ensure all zones are up to date in the file
    #Dnscmd $dnsServer /writebackfiles

    #get all AD Integrated zones on the DNS Server
    $zones = Get-DnsServerZone -ComputerName $dnsServer | Where-Object {$_.ZoneType -eq 'Primary' -and $_.IsAutoCreated -eq $false -and $_.ZoneName -ne 'TrustAnchors'} | Select-Object -ExpandProperty ZoneName

    foreach ($zone in $zones) {

        try {
            
            Export-DnsServerZone -ComputerName $dnsServer -Name $zone -FileName "\backup\$($zone)_backup_$(Get-Date -UFormat %Y%m%d).dns.backup"
        
        } catch {
            
            if ($email) {
                $FQEI = ($_.FullyQualifiedErrorId).split(",")
                $FQEIMessage = switch ($FQEI[0]) { 
                                            'WIN32 1722' {"WIN32 1722: The Server is not available"} 
                                            'WIN32 183' {"WIN32 183: The destination file already exists, a backup has probably been taken today"}
                                            default {"Check the Win32 error ID $FQEI[0] at https://msdn.microsoft.com/en-us/library/cc231199.aspx"}
                                        }
                send-mailmessage -from "DNS Backup <dnsbackup@syd.com.au>" -to "tim.aitken@syd.com.au" -subject "Backing Up DNS Zone failed" -BodyAsHtml -body "The automated DNS backup service on $env:computername failed. <br><br>Exception Message: $($_.Exception.Message) <br><br>Fully Qualified Exception ID: $FQEIMessage" -priority High -smtpServer $smtpServer
            }
            Write-error $_ 
        }

    }
}
