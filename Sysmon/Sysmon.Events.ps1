function Get-ProcessCreationEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime   = $StartTime
        EndTime     = $EndTime
        ProcessId   = $ProcessId
        ProcessGuid = $ProcessGuid
        EventIds    = 1
        MaxEvents   = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-NetworkConnectionEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 3
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-ProcessTerminationEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 5
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-DriverLoadEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 6
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-ImageLoadEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 7
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-CreateRemoteThreadEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 8
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-ProcessAccessEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 10
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Get-FileCreationEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 11
        MaxEvents       = $MaxEvents
    }
    return Get-SysmonEvents @Parameters
}

function Get-DnsQueryEvents {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,
        $ProcessId      = 0,
        $ProcessGuid    = 0,
        $MaxEvents      = 0
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessId       = $ProcessId
        ProcessGuid     = $ProcessGuid
        EventIds        = 3
        MaxEvents       = $MaxEvents
    }

    return Get-SysmonEvents @Parameters
}

function Resolve-ProcessGuid {
    param(
        [CmdletBinding()]
        $StartTime      = $False,
        $EndTime        = $False,

        [Parameter( Mandatory = $true )]
        $ProcessGuid
    )

    $Parameters = @{
        StartTime       = $StartTime
        EndTime         = $EndTime
        ProcessGuid     = $ProcessGuid
    }

    return Get-SysmonEvents @Parameters | select TimeGenerated, EventType, EventMessage
}