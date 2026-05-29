rule eicar_test_string
{
    meta:
        description = "ThreatScope bootstrap rule — matches EICAR test file content"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
