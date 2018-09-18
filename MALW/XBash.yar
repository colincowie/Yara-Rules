/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: XBash (IronGroup)
   Reference: https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/
*/

/* Rule Set ----------------------------------------------------------------- */

import "hash"

rule XBash_Windows {
   meta:
      description = "Detects XBash Windows Malware"
      author = "Colin Cowie"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18"
   strings:
      $s1 = "Visual Studio setup bootstrapper" wide ascii
      $s2 = "040904b0" wide ascii
      $s3 = "CompanyName" wide ascii
      $s4 = "Durbanville1" wide ascii
      $upx_sig = "UPX!"
      $upx1 = {55505830000000}
      $upx2 = {55505831000000}
   condition:
      $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) and
      3 of ($s1, $s2, $s3, $s4) or
      hash.md5(0, filesize) == "3a3ae909caee915af927c29a6025d16c"
}

import "elf"

rule XBash_Linux {
  meta:
     description = "Detects XBash Linux Malware"
     author = "Colin Cowie"
     reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
     date = "2018-09-18"
  strings:
     $s1 = "Crypto.Cipher.DES"
     $s2 = "pydata"
     $s3 = "pymongo"
     $s4 = "zout00-PYZ.pyz"
     $s5 = "sXshell"
  condition:
     all of them and
     elf.machine == elf.EM_X86_64 and
     (filesize > 9MB or filesize < 12MB) or
     hash.md5(0, filesize) == "7b5008d312465307905d96b4b8366326"
}
