rule Linux_Ransomware_TOR_Payment
{
    meta:
        severity = 45
        action = "quarantine"

    strings:
        $tor1 = ".onion"
        $tor2 = "torproject"
        $pay1 = "bitcoin"
        $pay2 = "monero"

    condition:
        uint32(0) == 0x464c457f and
        1 of ($tor*) and
        1 of ($pay*)
}
