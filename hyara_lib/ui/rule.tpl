$imports
rule $name {
    meta:
        date    = "$date"
        md5     = "$md5"
        sha256  = "$sha256"
    strings:
$strings
    condition:
        filesize < $size and all of them $conditions
}
