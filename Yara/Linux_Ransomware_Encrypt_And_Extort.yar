rule Linux_Ransomware_Encrypt_And_Extort
{
    meta:
        description = "Linux ransomware with encryption + ransom demand"
        severity = 95
        action = "delete"

    strings:
        /* Crypto */
        $crypto1 = "AES"
        $crypto2 = "RSA"
        $crypto3 = "ChaCha20"
        $crypto4 = "EVP_EncryptInit"

        /* File traversal */
        $fs1 = "opendir"
        $fs2 = "readdir"
        $fs3 = "rename"
        $fs4 = "unlink"

        /* Ransom indicators */
        $ransom1 = "decrypt your files"
        $ransom2 = "bitcoin"
        $ransom3 = "monero"
        $ransom4 = ".onion"
        $ransom5 = "send payment"

    condition:
        uint32(0) == 0x464c457f and
        2 of ($crypto*) and
        2 of ($fs*) and
        1 of ($ransom*)
}
