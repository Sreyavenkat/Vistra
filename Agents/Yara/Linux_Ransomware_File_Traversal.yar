rule Linux_Ransomware_File_Traversal
{
    meta:
        description = "Mass file traversal and deletion behavior"
        severity = 60
        action = "quarantine"

    strings:
        $op1 = "opendir"
        $op2 = "readdir"
        $op3 = "rename"
        $op4 = "unlink"
        $op5 = "remove"

    condition:
        3 of them
}
