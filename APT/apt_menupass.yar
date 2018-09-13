/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: APT 10 (MenuPass)
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-117A
*/

/* Rule Set ----------------------------------------------------------------- */

import "hash"

rule MenuPass_Phishing {
   meta:
      description = "Detects APT10 MenuPass Phishing"
      author = "Colin Cowie"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
   strings:
      $s1 = "C:\\ProgramData\\padre1.txt"
      $s2 = "C:\\ProgramData\\padre2.txt"
      $s3 = "C:\\ProgramData\\padre3.txt"
      $s5 = "C:\\ProgramData\\libcurl.txt"
      $s6 = "C:\\ProgramData\\3F2E3AB9"
   condition:
      any of them or
      hash.md5(0, filesize) == "4f83c01e8f7507d23c67ab085bf79e97" or
      hash.md5(0, filesize) == "f188936d2c8423cf064d6b8160769f21" or
      hash.md5(0, filesize) == "cca227f70a64e1e7fcf5bccdc6cc25dd"
}

rule MenuPass_UPPERCUT {
  meta:
     description = "Detects APT10 MenuPass UPPERCUT"
     author = "Colin Cowie"
     reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
     date = "2018-09-13"
  strings:
     $ip1 = "51.106.53.147"
     $ip2 = "153.92.210.208"
     $ip3 = "eservake.jetos.com"
     $c1 = "0x97A168D9697D40DD" wide
     $c2 = "0x7CF812296CCC68D5" wide
     $c3 = "0x652CB1CEFF1C0A00" wide
     $c4 = "0x27595F1F74B55278" wide
     $c5 = "0xD290626C85FB1CE3" wide
     $c6 = "0x409C7A89CFF0A727" wide 
  condition:
     any of them or
     hash.md5(0, filesize) == "aa3f303c3319b14b4829fe2faa5999c1" or
     hash.md5(0, filesize) == "126067d634d94c45084cbe1d9873d895" or
     hash.md5(0, filesize) == "fce54b4886cac5c61eda1e7605483ca3"
}
