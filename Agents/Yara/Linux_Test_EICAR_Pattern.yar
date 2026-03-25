rule Linux_Test_EICAR_Pattern
{
    meta:
        description = "Pattern-based detection of EICAR-like antivirus test strings"
        author = "Vistra Scanner"
        severity = 80
        action = "quarantine"
        category = "test"

    strings:
        /* Core identifiers */
        $kw1 = "EICAR" nocase
        $kw2 = "ANTIVIRUS" nocase
        $kw3 = "TEST" nocase

        /* Suspicious high-entropy pattern */
        $entropy_pattern = /[A-Z0-9!@#$%^&*(){}[\]\\]{20,}/

    condition:
        filesize < 5KB and
        uint32(0) != 0x464c457f and   // NOT ELF
        2 of ($kw*) and
        $entropy_pattern

}
