rule Suspicious_Shell_Command
{
    meta:
        description = "Detection de commandes shell potentiellement suspectes"
        author = "ESGI TP2"

    strings:
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $shell3 = "curl " ascii
        $shell4 = "wget " ascii

    condition:
        any of them
}

rule Potential_C2_Communication
{
    meta:
        description = "Detection d'indices de communication C2"
        author = "ESGI TP2"

    strings:
        $url = /https?:\/\/[a-zA-Z0-9.-]+\/gate\.php/ ascii
        $mutex = "Global\\" ascii
        $registry = "CurrentVersion\\Run" ascii

    condition:
        $url and ($mutex or $registry)
}

rule Suspicious_Windows_Persistence
{
    meta:
        description = "Detection d'indices de persistance Windows"
        author = "ESGI TP2"

    strings:
        $run1 = "CurrentVersion\\Run" ascii
        $run2 = "CurrentVersion\\RunOnce" ascii
        $hive1 = "HKCU\\" ascii
        $hive2 = "HKLM\\" ascii

    condition:
        ($run1 or $run2) and ($hive1 or $hive2)
}

rule Potential_Keylogging_Indicators
{
    meta:
        description = "Detection d'indices de capture clavier"
        author = "ESGI TP2"

    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetKeyboardState" ascii
        $api4 = "GetKeyState" ascii

    condition:
        any of them
}