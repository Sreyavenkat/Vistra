rule Linux_ELF_Executable
{
    meta:
        description = "ELF executable file"
        severity = 50
        action = "ignore"
        layer = "static"

    condition:
        uint32(0) == 0x464c457f
}
