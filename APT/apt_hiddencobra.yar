/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-08-04
   Identifier: Hidden Cobra
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-164A
*/

/* Rule Set ----------------------------------------------------------------- */

rule HiddenCobra_Attachment {
   meta:
      description = "Detects Hidden Cobra Dropper Attachment"
      author = "Colin Cowie"
      reference = "https://www.virustotal.com/#/file/9c3221dfc49b159f032eda70e8cb207c60e73ea5f51f9ddc90629292deacf90c/community"
      date = "2018-08-4"
      hash = "9c3221dfc49b159f032eda70e8cb207c60e73ea5f51f9ddc90629292deacf90c"
   strings:
      $s1 = "sharnon.kim@gmail.com" wide
      $s2 = "BIN0001.jpeg" wide
      $s3 = "BIN0002.PS" wide
   condition:
      all of them
}
