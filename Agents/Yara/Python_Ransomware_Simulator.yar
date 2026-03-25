rule Python_Ransomware_Simulator
{
    meta:
        description = "Python ransomware-like behavior simulator"
        severity = 80
        action = "quarantine"

    strings:
        $walk = "os.walk"
        $rename = "os.rename"
        $locked = ".locked"
        $ransom1 = "Your files are encrypted"
        $ransom2 = "bitcoin"
        $ransom3 = ".onion"

    condition:
        2 of ($ransom*) and
        $walk and
        $rename and
        $locked
}
