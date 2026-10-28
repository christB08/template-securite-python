rule Suspicious_Shell_Command
{
    meta:
        description = "Detection de commandes shell"
        author = "ESGI TP2"

    strings:
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $shell3 = "curl " ascii
        $shell4 = "wget " ascii

    condition:
        any of them
}

rule Suspicious_Network_Indicators
{
    meta:
        description = "Detection d'indicateurs reseau"
        author = "ESGI TP2"

    strings:
        $net1 = "http://" ascii
        $net2 = "https://" ascii
        $net3 = "socket" ascii
        $net4 = "connect" ascii

    condition:
        any of them
}