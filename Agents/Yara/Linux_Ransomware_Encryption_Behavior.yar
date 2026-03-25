rule Linux_Ransomware_Encryption_Behavior
{
    meta:
        severity = 65
        action = "quarantine"

    strings:
        $crypto1 = "AES"
        $crypto2 = "RSA"
        $crypto3 = "ChaCha20"
        $crypto4 = "EVP_EncryptInit"

        $fs1 = "opendir"
        $fs2 = "readdir"
        $fs3 = "rename"
        $fs4 = "unlink"

    condition:
        uint32(0) == 0x464c457f and
        2 of ($crypto*) and
        2 of ($fs*)
}
