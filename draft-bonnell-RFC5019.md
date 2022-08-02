---
title: "Updates Lightweight OCSP Profile for High Volume Environments"
abbrev: "RFC5019bis"
category: std

docname: draft-bonnell-RFC5019-latest
submissiontype: IETF  
number:
date:
consensus: true
v: 3
area: SEC
workgroup: individual # WG Working Group
keyword:
 - OCSP
 - SHA-1

venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Corey Bonnell
    organization: Digicert, Inc.
    email: corey.bonnell@digicert.com
-
    fullname: Clint Wilson
    organization: Apple, Inc.
    email: clintw@apple.com
-
    fullname: Tadahiko Ito
    organization: SECOM CO., LTD.
    email: tadahiko.ito.public@gmail.com
-
    fullname: Sean Turner
    organization: sn3rd
    email: sean@sn3rd.com

normative:
  RFC5019:

informative:


--- abstract

This document updates RFC5019, and allow OCSP client to use SHA-256 in addition to SHA-1.

--- middle

# Introduction

{{!RFC5019}} specifies...
{{RFC5019}} describes that "Clients MUST use SHA1 as the hashing algorithm for the
CertID.issuerNameHash and the CertID.issuerKeyHash values."
This draft allow client use SHA-256 as the hashing alggorithm for the CertID.issuerNameHash and the CertID.issuerKeyHash values.


# Conventions and Definitions

{::boilerplate bcp14-tagged}



# Security Considerations

This document introduces no new security considerations beyond those found in {{RFC5019}}.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
