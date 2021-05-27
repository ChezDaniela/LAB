rule my_first_yara_rule : find_andromeda
{
    meta:
        description = "This is my first yara rule"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = "fireman.carsassurance.info" nocase wide ascii
        $b = "www.ecb.europa.eu" nocase wide ascii
        $c = "ztjyuncjqvi1e.com" nocase wide ascii
        $d = "rmfytrwemvvk.com" nocase wide ascii
        $e = "hzyhgagvadhu.com" nocase wide ascii
        $f = "dom.altincopps.com" nocase wide ascii
        $g = "thingstodo.viator.com" nocase wide ascii
        $h = "folesd.tk" nocase wide ascii

    condition:
        $a or $b or $c or $d or $e or $f or $g or $h 
}