rule Linux_Ransom_Note_Generic
{
    meta:
        severity = 35
        action = "ignore"

    strings:
        $note1 = "decrypt your files"
        $note2 = "your files have been encrypted"
        $note3 = "send payment"

    condition:
        2 of ($note*)
}

