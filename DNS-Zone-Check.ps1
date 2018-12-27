# This script uses WMI to check DNS A records for a given zone and looks for several things.
# It pings the host for Online status. It checks the A records to see if they are static and for staleness.
# It checks the PTR records for presence, and to see if they are static or stale.
# The output is color coded for the results.
# The host being online can be White, Green, or Yellow. 
# If the hostname and Online are in White, it has a Static A record.
# If the hostname and Online are in Green, it has a recently updated A record. 
# If the hostname and Online are in Yellow, it has a stale A record. 
# If the host is offline, it will be in Red.
# Static DNS records are White, Updated DNS records are Green, Stale DNS records are Yellow, No DNS records = Red
# If the reverse DNS zone exists it will be in Green.

# Set some variables up
$dnsServer = "dc1vsdc101a.lsi.local"
$dnsDomainName = "lsi.local"
$staledate = (Get-Date).AddDays(-90)
$ProgressCounter = 0

# Define static date for later comparison
$staticdate = "1/1/1601 12:00:00 AM"

# Function to create the PTR records, invoked below 
function CreatePTR($dnsServer,$reverse_zone,$reverse_ip,$hostname) {
	Invoke-WmiMethod -Name CreateInstanceFromPropertyData -Class MicrosoftDNS_PTRType `
	-Namespace root\MicrosoftDNS -ArgumentList "$reverse_zone","$dnsServer","$reverse_ip","$hostname" `
	-ComputerName $dnsServer
}

# Get all PTR records and turn it into a hash table for lookup name verifications
$record_R_list = Gwmi -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_PTRtype -ComputerName $dnsServer | Select Ownername,RecordData
# Initialize empty hash table
$record_R_hash = @{}
# Loop through all records and add them as key entries to the hash table
Foreach ($hrecord in $record_R_list) {
$record_R_hash.($hrecord.ownername) = $hrecord.recorddata
}

# Get all PTR records with timestamps and make new hashtable named $record_R_date for stale date check
# datetime expression converts WMI time to readable time
$record_R_datelist = Gwmi -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_PTRtype -ComputerName $dnsServer | 
Select OwnerName,@{n="Timestamp";e={([datetime]"1.1.1601").AddHours($_.Timestamp)}}
# Initialize empty hash table
$record_R_date = @{}
# Loop through all records and add them as key entries to the hash table
Foreach ($drecord in $record_R_datelist) {
$record_R_date.($drecord.ownername) = $drecord.Timestamp
}

# Get all A records with datetime expression to convert WMI time to readable time. Filter out msdcs records
$record_A_list = Gwmi -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_Atype -ComputerName $dnsServer |
Select ownername,IPaddress,@{n="Timestamp";e={([datetime]"1.1.1601").AddHours($_.Timestamp)}} | 
Where {($_.ownername -like "*.$dnsDomainName") -and ($_.ownername -notlike "*msdcs*") -and ($_.ownername -notlike "*dnszones*")}

# Get all reverse zones
$reverse_zone_list = Gwmi MicrosoftDNS_Zone -Namespace 'root\MicrosoftDNS' -filter "reverse=true" -computer $dnsServer | Select Name -ExpandProperty Name

# Write header
Write-Host -NoNewLine -Foreground White "Static = White "
Write-Host -NoNewLine -Foreground Green "Updated = Green "
Write-Host -NoNewLine -Foreground Yellow "Stale = Yellow "
Write-Host -Foreground Red "Not Present = Red"
Write-Host -Foreground White "Computer Status IP ReverseZone"

# Loop through all A records and verify their ping status and check for PTR records and reverse zone presence
Foreach ($a_record in $record_A_list) {
	# Build hostname with trailing dot.
    $hostname = $a_record.ownername+"."

    # Get the IP address from the A record and convert to reverse format
	$ipaddress = $a_record.IPaddress
    $arr = $ipaddress.split(".")
	[array]::Reverse($arr)
	$reverse_ip = ($arr -join '.') + ".in-addr.arpa"

	# Check ping status and stale check and write first part of line with no new line
    $PingStatus = Gwmi Win32_PingStatus -Filter "Address = '$hostname'" | Select-Object StatusCode
	If ($PingStatus.StatusCode -eq 0) {
        If ($a_record.Timestamp -eq $staticdate) {
        Write-Host -NoNewLine -Foreground White $hostname "Online "
        }
        ElseIf ($a_record.Timestamp -ge $staledate) {
        Write-Host -NoNewLine -Foreground Green $hostname "Online "
        }
        Else {
        Write-Host -NoNewLine -Foreground Yellow $hostname "Online "
        # Cleanup - Dangerous
        # $tempname = ($a_record.ownername.TrimEnd(".$dnsDomainName"))
        # Get-DnsServerResourceRecord -ZoneName $dnsDomainName -RRType A -ComputerName $dnsServer -Name $tempname | Remove-DnsServerResourceRecord -Confirm
        }
    }
    Else {
        Write-Host -NoNewline -Foreground Red $hostname "Offline "
        # Cleanup - Dangerous
        # $tempname = ($a_record.ownername.TrimEnd(".$dnsDomainName"))
        # Get-DnsServerResourceRecord -ZoneName $dnsDomainName -RRType A -ComputerName $dnsServer -Name $tempname | Remove-DnsServerResourceRecord -Confirm
    }

    # Check to see if the host is in the PTR list or not and if it is stale and write the next part of the line
    If ($record_R_hash[$reverse_ip] -eq $hostname) {
        If ($record_R_date[$reverse_ip] -eq $staticdate) {
        Write-Host -NoNewline -Foreground White $ipaddress ""
        }
        Elseif ($record_R_date[$reverse_ip] -ge $staledate) {
        Write-Host -NoNewline -Foreground Green $ipaddress ""
        }
        Else {
        Write-Host -NoNewline -Foreground Yellow $ipaddress ""
        # Cleanup - Dangerous
        # Gwmi -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_PTRtype -ComputerName $dnsServer | Where {$_.ownername -eq $reverse_ip} | Remove-WmiObject -Confirm
        }
    }
    Else {
	    Write-Host -NoNewline -Foreground Red $ipaddress ""
    }
    
    #detect the correct dns reverse lookup zone
	$arr_rvr = $reverse_ip.Split(".")
	$arr_rvr1 = $arr_rvr[1] + "." + $arr_rvr[2] + "." + $arr_rvr[3] + ".in-addr.arpa"
	$arr_rvr2 = $arr_rvr[2] + "." + $arr_rvr[3] + ".in-addr.arpa"
	$arr_rvr3 = $arr_rvr[3] + ".in-addr.arpa"
    If ($reverse_zone_list -contains $arr_rvr1) {
        Write-Host -Foreground Green $arr_rvr1 
        #CreatePTR $dnsServer $arr_rvr1 $reverse_ip $hostname
        }
    ElseIf ($reverse_zone_list -contains $arr_rvr2) {
        Write-Host -Foreground Green $arr_rvr2
        #CreatePTR $dnsServer $arr_rvr2 $reverse_ip $hostname
        }
    ElseIf ($reverse_zone_list -contains $arr_rvr3) {
        Write-Host -Foreground Green $arr_rvr3
        #CreatePTR $dnsServer $arr_rvr3 $reverse_ip $hostname
        }
    Else {
    Write-Host -Foreground Red "Reverse lookup zone does not exist."
    }

# Increment and write out the progress bar
$ProgressCounter++
Write-Progress -activity "Working on $hostname" -status "Please wait ..." -PercentComplete (($ProgressCounter / ($record_A_list.length + 1)) * 100)

# End of A record loop
}

