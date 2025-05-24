<#
.SYNOPSIS
Resolve process access rights from hex to human readable format.

.DESCRIPTION
Resolve process access rights from hex to human readable format. These access rights grant a caller specific rights
over a process handle when accessed with a function such as OpenProcess, authorizing the caller to perform specific
actions on the process.

.PARAMETER Value
A hex value representing the access rights to resolve

.OUTPUTS
System.Object

.EXAMPLE
PS> Resolve-ProcessAccessRights -Value 0x1410
PROCESS_QUERY_LIMITED_INFORMATION
PROCESS_QUERY_INFORMATION
PROCESS_VM_REA

.LINK
https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

.LINK
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
#>
function Resolve-ProcessAccessRights {
    param(
        [int]$Value
    )

    $ProcessAccessRights = @{
        PROCESS_TERMINATE                   = 0x0001
        PROCESS_CREATE_THREAD               = 0x0002
        PROCESS_SET_SESSIONID               = 0x0004
        PROCESS_VM_OPERATION                = 0x0008
        PROCESS_VM_READ                     = 0x0010
        PROCESS_VM_WRITE                    = 0x0020
        PROCESS_DUP_HANDLE                  = 0x0040
        PROCESS_CREATE_PROCESS              = 0x0080
        PROCESS_SET_QUOTA                   = 0x0100
        PROCESS_SET_INFORMATION             = 0x0200
        PROCESS_QUERY_INFORMATION           = 0x0400
        PROCESS_SUSPEND_RESUME              = 0x0800
        PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000
        PROCESS_SET_LIMITED_INFORMATION     = 0x2000
        PROCESS_ALL_ACCESS                  = 0x1FFFFF
    };

    $Rights = @()
    foreach ( $Right in $ProcessAccessRights.Keys ) {
        if ( ($Value -band $ProcessAccessRights[$Right]) -eq $ProcessAccessRights[$Right] ) {
            $Rights += $Right
        }
    }
    return $Rights
}

<#
.SYNOPSIS
Parse events from the sysmon operational event log channel.

.DESCRIPTION
Parse events from the sysmon operational event log channel. Events are parsed into a powershell object where the event properties
become object properties, accesible through object.property syntax. Additional data & is added to each event such as the EventType 
& EventMessage fields which describe the type of event & translate the event respectively. Light normalization has been applied to 
field names.

.PARAMETER StartTime
Parse all events where the event was logged on or after this time.

.PARAMETER EndTime
Parse all events where the event was logged on or before this time.

.PARAMETER EventIds
A list of specific event ids to retrieve

.PARAMETER ProcessId
Filter on events generated with a specific process id (source)

.PARAMETER ProcessGuid
Filter on events generated with a specific process guid (source)

.PARAMETER MaxEvents
A maximum amount of events to retrive. Retrieves all events if left unspecified.

.OUTPUTS
System.Object
.LINK
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
#>
function Get-SysmonEvents {
    param(
        [CmdletBinding()]
        
        [Parameter(Mandatory = $False)]
        $StartTime      = $False,
        
        [Parameter(Mandatory = $False)]
        $EndTime        = $False,

        [Parameter(Mandatory = $False)]
        $EventIds       = @(),

        [Parameter(Mandatory = $False)]
        $ProcessId      = 0,

        [Parameter(Mandatory = $False)]
        $ProcessGuid    = 0,

        [Parameter(Mandatory = $False)]
        $MaxEvents      = 0
    )

    # Begin creating xpath filters
    #
    # Create event id filter if any were specified
    if ($EventIds.Count -ne 0) {
        $XPathFilterEventId = "Event[System[("
        foreach ($EventId in $EventIds) {
            if ($EventId -eq $EventIds[-1]){
                $XPathFilterEventId += "EventID=$($EventId))"
            }
            else {
                $XPathFilterEventId += "EventID=$($EventId) or "
            }
        }
        $XPathFilterEventId += "]]"
    }

    # Create start & end time filters
    if ($StartTime -or $EndTime) {
        $XPathFilterTimeCreated += "TimeCreated["
        if ($StartTime) {
            $XPathFilterTimeCreated += "@SystemTime>='$( $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") )'"
            if ($EndTime) {
                $XPathFilterTimeCreated += " and "
            }
        }
        if ($EndTime) {
            $XPathFilterTimeCreated += "@SystemTime<='$( $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") )'"
        }
        $XPathFilterTimeCreated += "]"
    }

    # Create process id & process guid filters
    if ($ProcessId) {
        $XPathFilterProcessId   = "Event[EventData[Data[@Name='ProcessId']='$ProcessId']] or Event[EventData[Data[@Name='SourceProcessId']='$ProcessId']]"
    }
    if ($ProcessGuid) {
        $XPathFilterProcessGuid = "Event[EventData[Data[@Name='ProcessGuid']='$ProcessGuid']] or Event[EventData[Data[@Name='SourceProcessGuid']='$ProcessGuid']] or Event[EventData[Data[@Name='ParentProcessGuid']='$ProcessGuid']]"
    }

    # Merge filters into a single xpath filter
    $Filters = Get-Variable XPathFilter* -Scope Local
    switch ($Filters.Count) {
        0 {
            $XPathFilter = "*"
        }

        1 {
            $XPathFilter = $Filters.Value
        }

        { $_ -gt 1 } {
            foreach ($Filter in $Filters) {
                if ($Filter.Value -eq $Filters.Value[-1]) {
                    $XPathFilter += "$($Filter.Value)"
                }
                else {
                    $XPathFilter += "$($Filter.Value) and "
                }
            }
        }
    }

    Write-Verbose "Collecting raw events from Microsoft-Windows-Sysmon/Operational using the xpath filter: $($XPathFilter)"

    # Collect the raw sysmon events
    #$Error = 'SilentyContinue'
    $Events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $XPathFilter -ErrorAction SilentlyContinue
    if (!$Events) {

    }
    #$VerbosePreference = 'Continue'
    
    # Parse each event into a powershell object
    Write-Verbose "Collected raw data. Beginning data normalization operations..."
    $ParsedEvents      = @()
    foreach ( $Event in $Events ) {
        $Parsed = @{}
        [xml]$Xml   = $Event.ToXml()
        
        $Parsed.EventID         = $Xml.Event.System.EventID
        $Parsed.TimeGenerated   = [DateTime]::Parse($Xml.Event.System.TimeCreated.SystemTime).ToString("MMMM dd yyyy, hh:mm:ss.fff tt")
        
        # Normalize the field names to a single schema
        foreach ( $Item in $Xml.Event.EventData.Data ) {
            switch ($Item.Name) {
                { $_ -in @("Image", "SourceImage") }    { $Item.Name = "Process"; break }
                "ParentImage"                           { $Item.Name = "ParentProcess"; break }
                "TargetImage"                           { $Item.Name = "TargetProcess"; break }
                "SourceProcessId"                       { $Item.Name = "ProcessId"; break }
                "TargetObject"                          { $Item.Name = "RegistryKey"; break }
                "Details"                               { $Item.Name = "RegistryValueData"; break }
            }
            $Parsed."$($Item.Name)" = $Item.'#text'
        }

        # Enrich the data inside of each event based on the event id of the current event
        switch ($Parsed.EventID) {
            
            # -- Process Creation (Event ID 1) --
            1  { 
                $Parsed.EventType    = "Process Created"
                $Parsed.EventMessage = "$($Parsed.ParentProcess.Split('\\')[-1]) ($($Parsed.ParentProcessId)) ($($Parsed.ParentUser)) started the process $($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.User)) with a $($Parsed.IntegrityLevel) integrity level using the command line $($Parsed.CommandLine)"
                break 
            }
            
            # -- A process changed a file creation time (Event ID 2) --
            2  { 
                $Parsed.EventType                   = "File Creatiom Time Modification"
                $Parsed.CreationSystemTime          = [DateTime]::Parse($Parsed.CreationUtcTime).ToString("MMMM dd yyyy, hh:mm:ss.fff tt")
                $Parsed.PreviousCreationSystemTime  = [DateTime]::Parse($Parsed.PreviousCreationUtcTime).ToString("MMMM dd yyyy, hh:mm:ss.fff tt")
                $Parsed.EventMessage                = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) changed the file creation time from [$($Parsed.PreviousCreationSystemTime)] to [$($Parsed.CreationSystemTime)]" 
                break 
            }
            
            ## -- Network connection (Event ID 3) --
            3  {
                $Parsed.EventType = "Network Connection"
                switch ( $Parsed.Initiated ) {
                    'false' { 
                        $Parsed.Direction = "Inbound"
                        $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) @ $($Parsed.DestinationIp):$($Parsed.DestinationPort) received an inbound $($Parsed.Protocol) connection from $($Parsed.SourceIp):$($Parsed.SourcePort)"
                        break 
                    }
                    'true'  { 
                        $Parsed.Direction = "Outbound"
                        $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) @ $($Parsed.SourceIp):$($Parsed.SourcePort) connected to $($Parsed.DestinationIp) over $($Parsed.Protocol) port $($Parsed.DestinationPort)"
                        break 
                    }
                }
                break 
            }
            
            ## -- Sysmon service state changed (Event ID 4) --
            4  { 
                $Parsed.EventType = "Sysmon Service State Changed"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Process terminated (Event ID 5) --
            5  { 
                $Parsed.EventType = "Process Terminated"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) was terminated."
                break
            }
            
            ## -- Driver Loaded (Event ID 6) --
            6  { 
                $Parsed.EventType = "Driver Loaded"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Image Loaded (Event ID 7) --
            7  {
                $Parsed.EventType = "Image Loaded"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) loaded the image $($Parsed.ImageLoaded.Split('\\')[-1]) from $($Parsed.ImageLoaded.Replace($Parsed.ImageLoaded.Split('\\')[-1], ''))"
                switch ($Parsed) {
                    { $_.Signed -eq 'true' -and $_.SignatureStatus -eq 'Valid' } { $Parsed.EventMessage += " with a valid signature from $($_.Signature)."; break }
                    { $_.Signed -eq 'true' -and $_.SignatureStatus -ne 'Valid' } { $Parsed.EventMessage += " with a(n) $($_.SignatureStatus.ToLower()) signature from $($_.Signature)"}
                    { $_.Signed -eq 'false' }                                    { $Parsed.EventMessage += " without a digital signature."}
                }
                break 
            }
            
            ## -- CreateRemoteThread (Event ID 8) --
            8  { 
                $Parsed.EventType = "Remote Thread Created"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.SourceUser)) started a remote thread ($($Parsed.NewThreadId)) in $($Parsed.TargetProcess.Split('\\')[-1]) ($($Parsed.TargetProcessId)) ($($Parsed.TargetUser))"
                switch ($Parsed) {
                    { $_.StartModule -ne '-' -and $_.StartFunction -ne '-' } { $Parsed.EventMessage += " starting at the function $($_.StartFunction) ($($_.StartAddress)) in $($_.StartModule)"; break}
                    
                    default
                    { $Parsed.EventMessage += " starting at the address $($_.StartAddress)"}
                }
                break 
            }
            
            ## -- Raw Access Read (Event ID 9) --
            9  { 
                $Parsed.EventType = "Raw Access Read"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Process Access (Event ID 10) --
            10 { 
                $Parsed.EventType = "Process Accessed"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.SourceUser)) opened a handle to $($Parsed.Process.Split('\\')[-1]) ($($Parsed.TargetProcessId)) ($($Parsed.TargetUser)) with the access rights [ $((Resolve-ProcessAccessRights -Value $Parsed.GrantedAccess) -join ' | ' ) ]"
                $Parsed.AccessRights = (Resolve-ProcessAccessRights -Value $Parsed.GrantedAccess).Replace("[ ", "").Replace(" ]","").Trim() -split "  "
                break
            }
            
            ## -- File Creation (Event ID 11) --
            11 { 
                $Parsed.EventType = "File Created"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) created the file $($Parsed.TargetFilename.Split('\\')[-1]) in the directory $($Parsed.TargetFilename.Replace($Parsed.TargetFilename.Split('\\')[-1], ''))"
                break 
            }
            
            ## -- Registry Event (Event ID 12) --
            12 {
                switch ($Parsed.EventType) {
                    { $Parsed.EventType -eq "CreateKey" } {
                        $Parsed.EventType       = "Registry Key Created"
                        $Parsed.EventMessage    = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) created the registry key $($Parsed.RegistryKey)"
                        break
                    }

                    { $Parsed.EventType -eq "CreateValue" } {
                        $Parsed.EventType       = "Registry Value Created"
                        $Parsed.RegistryValue   = $Parsed.RegistryKey.Split('\\')[-1]
                        $Parsed.RegistryKey     = $Parsed.RegistryKey.Replace("\\$($Parsed.RegistryValue)", '')
                        $Parsed.EventMessage    = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) deleted the value $($Parsed.RegistryValue) from $($Parsed.RegistryKey)"
                        break
                    }

                    { $Parsed.EventType -eq "DeleteKey" } {
                        $Parsed.EventType       = "Registry Key Deleted"
                        $Parsed.EventMessage    = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) deleted the registry key $($Parsed.RegistryKey)"
                        break
                    }
                    
                    { $Parsed.EventType -eq "DeleteValue" } {
                        $Parsed.EventType       = "Registry Value Deleted"
                        $Parsed.RegistryValue   = $Parsed.RegistryKey.Split('\\')[-1]
                        $Parsed.RegistryKey     = $Parsed.RegistryKey.Replace("\$($Parsed.RegistryValue)", '')
                        $Parsed.EventMessage    = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) deleted the value $($Parsed.RegistryValue) from $($Parsed.RegistryKey)"
                        break
                    }
                }
                break
            }
            
            # -- Registry Value Set (Event ID 13) --
            13 { 
                $Parsed.EventType       = "Registry Value Set"
                $Parsed.RegistryValue   = $Parsed.RegistryKey.Split('\\')[-1]
                $Parsed.RegistryKey     = $Parsed.RegistryKey.Replace("\$($Parsed.RegistryValue)", '')
                $Parsed.EventMessage    = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) set the value $($Parsed.RegistryValue) to $($Parsed.RegistryValueData) in the key $($Parsed.RegistryKey)" 
                break
            }

            ## -- Registry Key & Value Renamed (Event ID 14) --
            14 {
                switch ($Parsed.EventType) {
                    "RenameKey" {
                        $Parsed.EventType = "Registry Key Renamed"
                        $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.User)) renamed the registry key $($Parsed.RegistryKey.Split('\\')[-1]) to $($Parsed.NewName.Split('\\')[-1]) at the reg path $($Parsed.NewName.Replace("\$($Parsed.NewName.Split('\\')[-1])", ''))"
                        break
                    }
                    
                    default {
                        $Parsed.EventType = "Unparsed Registry Rename Event"
                        $Parsed.EventMessage = "The event message for event id $($Parsed.EventID) type ($($Parsed.EventType)) has not been parsed."
                    }
                }
                
                break 
            }
            
            # -- File Stream Created (Event ID 15) -- 
            15 { 
                $Parsed.EventType = "File Stream Created"
                if ($Parsed.TargetFilename.Split(":").Count -eq 3) {
                    $Parsed.StreamName = $Parsed.TargetFilename.Split(":")[-1]
                }
                else {
                    $Parsed.StreamName = "`$DATA"
                }
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) created a new file stream using the name $($Parsed.StreamName) at the path $($Parsed.TargetFilename)"
                break
            }

            ## -- Sysmon service configuration change (Event ID 16) --
            16 { 
                $Parsed.EventType = "Sysmon Service Configuration Change"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break
            }
            
            ## -- Pipe Created (Event ID 17) --
            17 { 
                $Parsed.EventType = "Pipe Created"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.User)) created the pipe $($Parsed.PipeName)"
                break 
            }
            
            ## -- Pipe Connected (Event ID 18) --
            18 { 
                $Parsed.EventType = "Pipe Connected" 
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- WMI Event Filter Registration (Event ID 19) --
            19 { 
                $Parsed.EventType = "WMI Event Filter Registered"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- WMI Event Consumer Registration (Event ID 20) --
            20 { 
                $Parsed.EventType = "WMI Event Consumer Registered"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }

            ## -- WMI Consumer Bound to Event (Event ID 21) --
            21 { 
                $Parsed.EventType = "WMI Consumer Bound To Filter"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Dns Query (Event ID 22) --
            22 { 
                $Parsed.EventType = "Dns Query"
                $Parsed.QueryResults = $Parsed.QueryResults.Replace("type:  5 ", "").Split(";")
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.User)) "
                switch ($Parsed.QueryStatus) {
                    0 {
                        $Parsed.EventMessage += "resolved the domain $($Parsed.QueryName) to the host(s) [$($Parsed.QueryResults)]"
                    }

                    default {
                        $Parsed.EventMessage += "attempted to resolve the domain $($Parsed.QueryName) but failed with the return code $($Parsed.QueryStatus)"
                    }
                }
                break 
            }
            
            ## -- File Deletion (Archived) (Event ID 23) --
            23 { 
                $Parsed.EventType = "File Deleted (Archived)"
                $Parsed.EventMessage = "$($Parsed.Process.Split('\\')[-1]) ($($Parsed.ProcessId)) ($($Parsed.User)) deleted the file $($Parsed.TargetFilename)."
                break 
            }
            
            ## -- New content added to clipboard (Event ID 24) --
            24 { 
                $Parsed.EventType = "New Clipboard Content Added"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Process Tampering (Event ID 25) -- 
            25 { 
                $Parsed.EventType = "Process Tampering"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break
            }
            
            ## -- File Deletion (Event ID 26) --
            26 { 
                $Parsed.EventType = "File Deleted"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }

            ## -- File Block Executable (Event ID 27) -- 
            27 { 
                $Parsed.EventType = "Executable Blocked"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- File Block Shredding (Event ID 28) --
            28 { 
                $Parsed.EventType = "File Shredding Blocked"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break
            }
            
            ## -- File Executable Detected (Event ID 29) --
            29 { 
                $Parsed.EventType = "File Executable Detected"
                $Parsed.EventMessage = "The event message for event id $($_) has not been parsed."
                break 
            }
            
            ## -- Error (Event ID 255) --
            255 { 
                $Parsed.EventType = "Error"
                $Parsed.EventMessage = "An error occurred event id $($Parsed.ID). Error info: $($Parsed.Description) "
                break 
            }
        }

        $ParsedEvents += [PSCustomObject]$Parsed
    }

    if ($MaxEvents -ne 0) {
        return $ParsedEvents | select -First $MaxEvents
    }

    return $ParsedEvents

}