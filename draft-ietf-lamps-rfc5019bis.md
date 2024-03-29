---
title: "Updates to Lightweight OCSP Profile for High Volume Environments"
abbrev: "Lightweight OCSP Profile Update"
category: std

docname: draft-ietf-lamps-rfc5019bis-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: SEC
# workgroup: LAMPS Working Group
keyword: Internet-Draft
obsoletes: 5019

author:
 -
    fullname:
      :: 伊藤 忠彦
      ascii: Tadahiko Ito
    organization: SECOM CO., LTD.
    email: tadahiko.ito.public@gmail.com
 -
    fullname: Clint Wilson
    organization: Apple, Inc.
    email: clintw@apple.com
 -
    fullname: Corey Bonnell
    organization: DigiCert, Inc.
    email: corey.bonnell@digicert.com
 -
    fullname: Sean Turner
    organization: sn3rd
    email: sean@sn3rd.com

normative:

informative:
  OCSPMP:
    title: "OCSP Mobile Profile V1.0"
    author:
      org: Open Mobile Alliance
    date: false
    seriesinfo: www.openmobilealliance.org


--- abstract

This specification defines a profile of the Online Certificate Status
Protocol (OCSP) that addresses the scalability issues inherent when
using OCSP in large scale (high volume) Public Key Infrastructure
(PKI) environments and/or in PKI environments that require a
lightweight solution to minimize communication bandwidth and client-
side processing.

Since initial publication, this specification has been updated to allow
and recommend the use of SHA-256 over SHA-1.



--- middle

# Introduction

The Online Certificate Status Protocol {{!RFC6960}} specifies a mechanism
used to determine the status of digital certificates, in lieu of
using Certificate Revocation Lists (CRLs). Since its definition in
1999, it has been deployed in a variety of environments and has
proven to be a useful certificate status checking mechanism. (For
brevity we refer to OCSP as being used to verify certificate status,
but only the revocation status of a certificate is checked via this
protocol.)

To date, many OCSP deployments have been used to ensure timely and
secure certificate status information for high-value electronic
transactions or highly sensitive information, such as in the banking
and financial environments. As such, the requirement for an OCSP
responder to respond in "real time" (i.e., generating a new OCSP
response for each OCSP request) has been important. In addition,
these deployments have operated in environments where bandwidth usage
is not an issue, and have run on client and server systems where
processing power is not constrained.

As the use of PKI continues to grow and move into diverse
environments, so does the need for a scalable and cost-effective
certificate status mechanism. Although OCSP as currently defined and
deployed meets the need of small to medium-sized PKIs that operate on
powerful systems on wired networks, there is a limit as to how these
OCSP deployments scale from both an efficiency and cost perspective.
Mobile environments, where network bandwidth may be at a premium and
client-side devices are constrained from a processing point of view,
require the careful use of OCSP to minimize bandwidth usage and
client-side processing complexity. [OCSPMP]

PKI continues to be deployed into environments where millions if not
hundreds of millions of certificates have been issued. In many of
these environments, an even larger number of users (also known as
relying parties) have the need to ensure that the certificate they
are relying upon has not been revoked. As such, it is important that
OCSP is used in such a way that ensures the load on OCSP responders
and the network infrastructure required to host those responders are
kept to a minimum.

This document addresses the scalability issues inherent when using
OCSP in PKI environments described above by defining a message
profile and clarifying OCSP client and responder behavior that will
permit:

1. OCSP response pre-production and distribution.
2. Reduced OCSP message size to lower bandwidth usage.
3. Response message caching both in the network and on the client.

It is intended that the normative requirements defined in this
profile will be adopted by OCSP clients and OCSP responders operating
in very large-scale (high-volume) PKI environments or PKI
environments that require a lightweight solution to minimize
bandwidth and client-side processing power (or both), as described
above.

OCSP does not have the means to signal responder capabilities within the
protocol. Thus, clients will need to use out-of-band mechanisms to
determine whether a responder conforms to the profile defined in this
document. Regardless of the availability of such out-of-band mechanisms,
this profile ensures that interoperability will still occur between an
OCSP client that fully conforms with {{RFC6960}} and a responder that is
operating in a mode as described in this specification.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# OCSP Message Profile

This section defines a subset of OCSPRequest and OCSPResponse
functionality as defined in {{RFC6960}}.

## OCSP Request Profile {#req-profile}

### OCSPRequest Structure {#certid}

Provided for convenience here, but unchanged from {{!RFC6960}},
the ASN.1 structure corresponding to the OCSPRequest with the relevant
CertID is:

~~~~~~
OCSPRequest     ::=     SEQUENCE {
   tbsRequest                  TBSRequest,
   optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

TBSRequest      ::=     SEQUENCE {
   version             [0]     EXPLICIT Version DEFAULT v1,
   requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
   requestList                 SEQUENCE OF Request,
   requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

Request         ::=     SEQUENCE {
   reqCert                     CertID,
   singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }

CertID          ::=     SEQUENCE {
   hashAlgorithm       AlgorithmIdentifier,
   issuerNameHash      OCTET STRING, -- Hash of issuer's DN
   issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
   serialNumber        CertificateSerialNumber }
~~~~~~

OCSPRequests that conform to this profile MUST include only one Request
in the OCSPRequest.RequestList structure.

The CertID.issuerNameHash and CertID.issuerKeyHash fields contain hashes
of the issuer's DN and public key, respectively. OCSP clients that
conform with this profile MUST use SHA-256 as defined in {{!RFC6234}} as
the hashing algorithm for the CertID.issuerNameHash and the
CertID.issuerKeyHash values.

Older OCSP clients which provide backward compatibility with
{{!RFC5019}} use SHA-1 as defined in {{!RFC3174}} as the hashing
algorithm for the CertID.issuerNameHash and the
CertID.issuerKeyHash values. However, these OCSP clients should
transition from SHA-1 to SHA-256 as soon as practical.

Clients MUST NOT include the singleRequestExtensions structure.

Clients SHOULD NOT include the requestExtensions structure. If a
requestExtensions structure is included, this profile RECOMMENDS that
it contain only the nonce extension (id-pkix-ocsp-nonce). See
{{fresh}} for issues concerning the use of a nonce in high-volume
OCSP environments.

### Signed OCSPRequests

Clients SHOULD NOT send signed OCSPRequests. Responders MAY ignore
the signature on OCSPRequests.

If the OCSPRequest is signed, the client SHALL specify its name in
the OCSPRequest.requestorName field; otherwise, clients SHOULD NOT
include the requestorName field in the OCSPRequest. OCSP servers
MUST be prepared to receive unsigned OCSP requests that contain the
requestorName field, but MUST handle such requests as if the
requestorName field were absent.

## OCSP Response Profile

### OCSPResponse Structure
The ASN.1 structure corresponding to the OCSPResponse
with the relevant CertID is:

~~~~~~
OCSPResponse ::= SEQUENCE {
   responseStatus         OCSPResponseStatus,
   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }

ResponseBytes ::=       SEQUENCE {
   responseType   OBJECT IDENTIFIER,
   response       OCTET STRING }

The value for response SHALL be the DER encoding of BasicOCSPResponse.

BasicOCSPResponse       ::= SEQUENCE {
   tbsResponseData      ResponseData,
   signatureAlgorithm   AlgorithmIdentifier,
   signature            BIT STRING,
   certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

ResponseData ::= SEQUENCE {
   version              [0] EXPLICIT Version DEFAULT v1,
   responderID              ResponderID,
   producedAt               GeneralizedTime,
   responses                SEQUENCE OF SingleResponse,
   responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

SingleResponse ::= SEQUENCE {
   certID                       CertID,
   certStatus                   CertStatus,
   thisUpdate                   GeneralizedTime,
   nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
   singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
~~~~~~

Responders MUST generate a BasicOCSPResponse as identified by the
id-pkix-ocsp-basic OID. Clients MUST be able to parse and accept a
BasicOCSPResponse. OCSPResponses that conform to this profile SHOULD
include only one SingleResponse in the
ResponseData.responses structure, but MAY include
additional SingleResponse elements if necessary to improve response
pre-generation performance or cache efficiency, and
to ensure backward compatibility. For instance,
to provide support to OCSP clients which do not yet support the
use of SHA-256 for CertID hash calculation, the OCSP responder
MAY include two SingleResponses in a BasicOCSPResponse.
In that BasicOCSPResponse, the CertID of one of the SingleResponses
uses SHA-1 for the hash calculation, and the CertID in the other
SingleResponse uses SHA-256. OCSP responders SHOULD NOT distribute
OCSP responses that contain CertIDs that use SHA-1 if the OCSP
responder has no clients that require the use of SHA-1.
Operators of OCSP responders may consider logging the hash
algorithm used by OCSP clients to inform their determination of
when it is appropriate to obsolete the distribution of OCSP responses
that employ SHA-1 for CertID field hashes. See {#sha-sec} for more
information on the security considerations for the continued use of
SHA-1.

The responder SHOULD NOT include responseExtensions. As specified in
{{RFC6960}}, clients MUST ignore unrecognized non-critical
responseExtensions in the response.

In the case where a responder does not have the ability to respond to
an OCSP request containing an option not supported by the server, it
SHOULD return the most complete response it can. For example, in the
case where a responder only supports pre-produced responses and does
not have the ability to respond to an OCSP request containing a
nonce, it SHOULD return a response that does not include a nonce.

Clients SHOULD attempt to process a response even if the response
does not include a nonce. See {{fresh}} for details on validating
responses that do not contain a nonce. See also {{sec-cons}} for
relevant security considerations.

Responders that do not have the ability to respond to OCSP requests
that contain an unsupported option such as a nonce MAY forward the
request to an OCSP responder capable of doing so.

The responder MAY include the singleResponse.singleResponse
extensions structure.

### Signed OCSPResponses {#byKey}

Clients MUST validate the signature on the returned OCSPResponse.

If the response is signed by a delegate of the issuing certification
authority (CA), a valid responder certificate MUST be referenced in
the BasicOCSPResponse.certs structure.

It is RECOMMENDED that the OCSP responder's certificate contain the
id-pkix-ocsp-nocheck extension, as defined in {{RFC6960}}, to indicate
to the client that it need not check the certificate's status. In
addition, it is RECOMMENDED that neither an OCSP authorityInfoAccess
(AIA) extension nor cRLDistributionPoints (CRLDP) extension be
included in the OCSP responder's certificate. Accordingly, the
responder's signing certificate SHOULD be relatively short-lived and
renewed regularly.

Clients MUST be able to identify OCSP responder certificates using
the byKey field and SHOULD be able to identify OCSP responder
certificates using the byName field of the ResponseData.ResponderID
choices.

Older responders which provide backward compatibility with {{RFC5019}}
MAY use the byName field to represent the ResponderID, but should
transition to using the byKey field as soon as practical.

Newer responders that conform to this profile MUST use the byKey
field to represent the ResponderID to reduce the size of the response.

### OCSPResponseStatus Values

As long as the OCSP infrastructure has authoritative records for a
particular certificate, an OCSPResponseStatus of "successful" will be
returned. When access to authoritative records for a particular
certificate is not available, the responder MUST return an
OCSPResponseStatus of "unauthorized". As such, this profile extends
the {{RFC6960}} definition of "unauthorized" as follows:

The response "unauthorized" is returned in cases where the client
is not authorized to make this query to this server or the server
is not capable of responding authoritatively.

For example, OCSP responders that do not have access to authoritative
records for a requested certificate, such as those that generate and
distribute OCSP responses in advance and thus do not have the ability
to properly respond with a signed "successful" yet "unknown"
response, will respond with an OCSPResponseStatus of "unauthorized".
Also, in order to ensure the database of revocation information does
not grow unbounded over time, the responder MAY remove the status
records of expired certificates. Requests from clients for
certificates whose record has been removed will result in an
OCSPResponseStatus of "unauthorized".

Security considerations regarding the use of unsigned responses are
discussed in {{RFC6960}}.

### thisUpdate, nextUpdate, and producedAt {#times}

When pre-producing OCSPResponse messages, the responder MUST set the
thisUpdate, nextUpdate, and producedAt times as follows:

thisUpdate:
: The time at which the status being indicated is known to be correct.

nextUpdate:
: The time at or before which newer information will be available
about the status of the certificate. Responders MUST always include
this value to aid in response caching. See {{cache-recs}} for additional
information on caching.

producedAt:
: The time at which the OCSP response was signed.

<aside markdown="block">
Note: In many cases the value of thisUpdate and producedAt will be
  the same.
</aside>

For the purposes of this profile, ASN.1-encoded GeneralizedTime
values such as thisUpdate, nextUpdate, and producedAt MUST be
expressed Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
times are YYYYMMDDHHMMSSZ), even where the number of seconds is zero.
GeneralizedTime values MUST NOT include fractional seconds.

# Client Behavior

## OCSP Responder Discovery

Clients MUST support the authorityInfoAccess extension as defined in
{{!RFC5280}} and MUST recognize the id-ad-ocsp access method. This
enables CAs to inform clients how they can contact the OCSP service.

In the case where a client is checking the status of a certificate
that contains both an authorityInformationAccess (AIA) extension
pointing to an OCSP responder and a cRLDistributionPoints extension
pointing to a CRL, the client SHOULD attempt to contact the OCSP
responder first. Clients MAY attempt to retrieve the CRL if no
OCSPResponse is received from the responder after a locally
configured timeout and number of retries.

## Sending an OCSP Request

To avoid needless network traffic, applications MUST verify the
signature of signed data before asking an OCSP client to check the
status of certificates used to verify the data. If the signature is
invalid or the application is not able to verify it, an OCSP check
MUST NOT be requested.

Similarly, an application MUST validate the signature on certificates
in a chain, before asking an OCSP client to check the status of the
certificate. If the certificate signature is invalid or the
application is not able to verify it, an OCSP check MUST NOT be
requested. Clients SHOULD NOT make a request to check the status of
expired certificates.

# Ensuring an OCSPResponse Is Fresh {#fresh}

In order to ensure that a client does not accept an out-of-date
response that indicates a 'good' status when in fact there is a more
up-to-date response that specifies the status of 'revoked', a client
must ensure the responses they receive are fresh.

In general, two mechanisms are available to clients to ensure a
response is fresh. The first uses nonces, and the second is based on
time. In order for time-based mechanisms to work, both clients and
responders MUST have access to an accurate source of time.

Because this profile specifies that clients SHOULD NOT include a
requestExtensions structure in OCSPRequests (see {{req-profile}}),
clients MUST be able to determine OCSPResponse freshness based on an
accurate source of time. Clients that opt to include a nonce in the
request SHOULD NOT reject a corresponding OCSPResponse solely on the
basis of the nonexistent expected nonce, but MUST fall back to
validating the OCSPResponse based on time.

Clients that do not include a nonce in the request MUST ignore any
nonce that may be present in the response.

Clients MUST check for the existence of the nextUpdate field and MUST
ensure the current time, expressed in GMT time as described in
{{times}}, falls between the thisUpdate and nextUpdate times. If
the nextUpdate field is absent, the client MUST reject the response.

If the nextUpdate field is present, the client MUST ensure that it is
not earlier than the current time. If the current time on the client
is later than the time specified in the nextUpdate field, the client
MUST reject the response as stale. Clients MAY allow configuration
of a small tolerance period for acceptance of responses after
nextUpdate to handle minor clock differences relative to responders
and caches. This tolerance period should be chosen based on the
accuracy and precision of time synchronization technology available
to the calling application environment. For example, Internet peers
with low latency connections typically expect NTP time
synchronization to keep them accurate within parts of a second;
higher latency environments or where an NTP analogue is not available
may have to be more liberal in their tolerance
(e.g. allow one day difference).

See the security considerations in {{sec-cons}} for additional details
on replay and man-in-the-middle attacks.

# Transport Profile {#transport}

OCSP clients can send HTTP-based OCSP requests using either the GET
or POST method.
The OCSP responder MUST support requests and responses over HTTP.
When sending requests that are less than or equal to 255 bytes in
total (after encoding) including the scheme and delimiters (http://),
server name and base64-encoded OCSPRequest structure, clients MUST
use the GET method (to enable OCSP response caching). OCSP requests
larger than 255 bytes SHOULD be submitted using the POST method. In
all cases, clients MUST follow the descriptions in A.1 of {{RFC6960}}
when constructing these messages.

When constructing a GET message, OCSP clients MUST base64-encode the
OCSPRequest structure according to {{!RFC4648}}, section 4. Clients
MUST NOT include whitespace or any other characters that are not part of
the base64 character repertoire in the base64-encoded string. Clients
MUST properly URL-encode the base64-encoded OCSPRequest according to
{{!RFC3986}}. OCSP clients MUST append the base64-encoded OCSPRequest
to the URI specified in the AIA extension {{RFC5280}}. For example:

~~~~~~
   http://ocsp.example.com/MEowSDBGMEQwQjAKBggqhkiG9w0CBQQQ7sp6GTKpL2dA
   deGaW267owQQqInESWQD0mGeBArSgv%2FBWQIQLJx%2Fg9xF8oySYzol80Mbpg%3D%3D
~~~~~~

In response to properly formatted OCSPRequests that are cachable
(i.e., responses that contain a nextUpdate value), the responder will
include the binary value of the DER encoding of the OCSPResponse
preceded by the following HTTP {{!RFC9110}} and {{!RFC9111}} headers.

~~~~~~
   Content-type: application/ocsp-response
   Content-length: < OCSP response length >
   Last-modified: < producedAt HTTP-date >
   ETag: "< strong validator >"
   Expires: < nextUpdate HTTP-date >
   Cache-control: max-age=< n >, public, no-transform, must-revalidate
   Date: < current HTTP-date >
~~~~~~

See {{http-proxies}} for details on the use of these headers.

# Caching Recommendations {#cache-recs}

The ability to cache OCSP responses throughout the network is an
important factor in high volume OCSP deployments. This section
discusses the recommended caching behavior of OCSP clients and HTTP
proxies and the steps that should be taken to minimize the number of
times that OCSP clients "hit the wire". In addition, the concept of
including OCSP responses in protocol exchanges (aka stapling or
piggybacking), such as has been defined in TLS, is also discussed.

## Caching at the Client

To minimize bandwidth usage, clients MUST locally cache authoritative
OCSP responses (i.e., a response with a signature that has been
successfully validated and that indicate an OCSPResponseStatus of
'successful').

Most OCSP clients will send OCSPRequests at or near the nextUpdate
time (when a cached response expires). To avoid large spikes in
responder load that might occur when many clients refresh cached
responses for a popular certificate, responders MAY indicate when the
client should fetch an updated OCSP response by using the cache-
control:max-age directive. Clients SHOULD fetch the updated OCSP
Response on or after the max-age time. To ensure that clients
receive an updated OCSP response, OCSP responders MUST refresh the
OCSP response before the max-age time.

## HTTP Proxies {#http-proxies}

The responder SHOULD set the HTTP headers of the OCSP response in
such a way as to allow for the intelligent use of intermediate HTTP
proxy servers. See {{RFC9110}} and {{RFC9111}} for the full definition
of these headers and the proper format of any date and time values.

| HTTP Header | Description |
|:---|:---|
| Date | The date and time at which the OCSP server generated the HTTP response. |
| Last-Modified | This value specifies the date and time at which the OCSP responder last modified the response. This date and time will be the same as the thisUpdate timestamp in the request itself. |
| Expires | Specifies how long the response is considered fresh. This date and time will be the same as the nextUpdate timestamp in the OCSP response itself. |
| ETag | A string that identifies a particular version of the associated data. This profile RECOMMENDS that the ETag value be the ASCII HEX representation of the SHA-256 hash of the OCSPResponse structure. |
| Cache-Control | Contains a number of caching directives. <br> * max-age = < n > -where n is a time value later than thisUpdate but earlier than nextUpdate. <br> * public -makes normally uncachable response cachable by both shared and nonshared caches. <br> * no-transform -specifies that a proxy cache cannot change the type, length, or encoding of the object content. <br> * must-revalidate -prevents caches from intentionally returning stale responses. |
{: #http-headers title="HTTP Headers"}

OCSP responders MUST NOT include a "Pragma: no-cache", "Cache-
Control: no-cache", or "Cache-Control: no-store" header in
authoritative OCSP responses.

OCSP responders SHOULD include one or more of these headers in non-
authoritative OCSP responses.

For example, assume that an OCSP response has the following timestamp
values:

~~~~~~
   thisUpdate = March 19, 2023 01:00:00 GMT
   nextUpdate = March 21, 2023 01:00:00 GMT
   productedAt = March 19, 2023 01:00:00 GMT
~~~~~~

and that an OCSP client requests the response on March 20, 2023 01:00:00
GMT. In this scenario, the HTTP response may look like this:

~~~~~~
   Content-Type: application/ocsp-response
   Content-Length: 1000
   Date: Mon, 20 Mar 2023 01:00:00 GMT
   Last-Modified: Sun, 19 Mar 2023 01:00:00 GMT
   ETag: "97df3588b5a3f24babc3851b372f0ba7
         1a9dcdded43b14b9d06961bfc1707d9d"
   Expires: Tue, 21 Mar 2023 01:00:00 GMT
   Cache-Control: max-age=86000,public,no-transform,must-revalidate
   <...>
~~~~~~

OCSP clients MUST NOT include a no-cache header in OCSP request
messages, unless the client encounters an expired response which may
be a result of an intermediate proxy caching stale data. In this
situation, clients SHOULD resend the request specifying that proxies
should be bypassed by including an appropriate HTTP header in the
request (i.e., Pragma: no-cache or Cache-Control: no-cache).

## Caching at Servers

In some scenarios, it is advantageous to include OCSP response
information within the protocol being utilized between the client and
server. Including OCSP responses in this manner has a few attractive
effects.

First, it allows for the caching of OCSP responses on the server,
thus lowering the number of hits to the OCSP responder.

Second, it enables certificate validation in the event the client is
not connected to a network and thus eliminates the need for clients
to establish a new HTTP session with the responder.

Third, it reduces the number of round trips the client needs to make
in order to complete a handshake.

Fourth, it simplifies the client-side OCSP implementation by enabling
a situation where the client need only the ability to parse and
recognize OCSP responses.

This functionality has been specified as an extension to the TLS
{{!I-D.ietf-tls-rfc8446bis}} protocol in
{{Section 4.4.2 of !I-D.ietf-tls-rfc8446bis}},
but can be applied to any client-server protocol.

This profile RECOMMENDS that both TLS clients and servers implement
the certificate status request extension mechanism for TLS.

Further information regarding caching issues can be obtained
from {{?RFC3143}}.

# Security Considerations {#sec-cons}

The following considerations apply in addition to the security
considerations addressed in {{Section 5 of RFC6960}}.

## Replay Attacks

Because the use of nonces in this profile is optional, there is a
possibility that an out of date OCSP response could be replayed, thus
causing a client to accept a good response when in fact there is a
more up-to-date response that specifies the status of revoked. In
order to mitigate this attack, clients MUST have access to an
accurate source of time and ensure that the OCSP responses they
receive are sufficiently fresh.

Clients that do not have an accurate source of date and time are
vulnerable to service disruption. For example, a client with a
sufficiently fast clock may reject a fresh OCSP response. Similarly
a client with a sufficiently slow clock may incorrectly accept
expired valid responses for certificates that may in fact be revoked.

Future versions of the OCSP protocol may provide a way for the client
to know whether the server supports nonces or does not support
nonces. If a client can determine that the server supports nonces,
it MUST reject a reply that does not contain an expected nonce.
Otherwise, clients that opt to include a nonce in the request SHOULD
NOT reject a corresponding OCSPResponse solely on the basis of the
nonexistent expected nonce, but MUST fall back to validating the
OCSPResponse based on time.

## Man-in-the-Middle Attacks

To mitigate risk associated with this class of attack, the client
must properly validate the signature on the response.

The use of signed responses in OCSP serves to authenticate the
identity of the OCSP responder and to verify that it is authorized to
sign responses on the CA's behalf.

Clients MUST ensure that they are communicating with an authorized
responder by the rules described in {{Section 4.2.2.2 of RFC6960}}.

## Impersonation Attacks

The use of signed responses in OCSP serves to authenticate the
identity of OCSP responder.

As detailed in {{RFC6960}}, clients must properly validate the signature
of the OCSP response and the signature on the OCSP response signer
certificate to ensure an authorized responder created it.

## Denial-of-Service Attacks

OCSP responders should take measures to prevent or mitigate denial-
of-service attacks. As this profile specifies the use of unsigned
OCSPRequests, access to the responder may be implicitly given to
everyone who can send a request to a responder, and thus the ability
to mount a denial-of-service attack via a flood of requests may be
greater. For example, a responder could limit the rate of incoming
requests from a particular IP address if questionable behavior is
detected.

## Modification of HTTP Headers

Values included in HTTP headers, as described in {{transport}}
and {{cache-recs}},
are not cryptographically protected; they may be manipulated by an
attacker. Clients SHOULD use these values for caching guidance only
and ultimately SHOULD rely only on the values present in the signed
OCSPResponse. Clients SHOULD NOT rely on cached responses beyond the
nextUpdate time.

## Request Authentication and Authorization

The suggested use of unsigned requests in this environment removes an
option that allows the responder to determine the authenticity of
incoming request. Thus, access to the responder may be implicitly
given to everyone who can send a request to a responder.
Environments where explicit authorization to access the OCSP
responder is necessary can utilize other mechanisms to authenticate
requestors or restrict or meter service.

## Use of SHA-1 for the calculation of CertID field values {#sha1-sec}

Although the use of SHA-1 for the calculation of CertID field values is
not of concern from a cryptographic security standpoint, the continued
use of SHA-1 in an ecosystem requires that software that interoperates
with the ecosystem maintain support for SHA-1. This increases
implementation complexity and potential attack surface for the software
in question. Thus, the continued use of SHA-1 in an ecosystem to
maintain interoperability with legacy software must be weighed against
the increased implementation complexity and potential attack surface.

# IANA Considerations

This document has no IANA actions.

--- back

# Differences from RFC 5019

This document obsoletes {{!RFC5019}}. {{!RFC5019}} defines a lightweight
profile for OCSP that makes the protocol more suitable for use in
high-volume environments. The lightweight profile specifies the
mandatory use of SHA-1 when calculating the values of several fields in
OCSP requests and responses. In recent years, weaknesses have been
demonstrated with the SHA-1 algorithm. As a result, SHA-1 is
increasingly falling out of use even for non-security relevant
use cases. This document obsoletes the lightweight profile as specified
in RFC 5019 to instead recommend the use of SHA-256 where SHA-1 was
previously required. An {{!RFC5019}}-compliant OCSP client is still able
to use SHA-1, but the use of SHA-1 may become obsolete in the future.

Substantive changes to RFC 5019:

- {{certid}} requires new OCSP clients to use SHA-256 to
support migration for OCSP clients.

- {{byKey}} requires new OCSP responders to use the byKey field,
and support migration from byName fields.

- {{transport}} clarifies that OCSP clients MUST NOT include
whitespace or any other characters that are not part of
the base64 character repertoire in the base64-encoded string.

# Examples

## Root Certification Authority Certificate

This is a self-signed certificate for the certification authority that
issued the end-entity certificate and OCSP delegated responder
example certificates below.

-----BEGIN CERTIFICATE-----
MIICKTCCAYqgAwIBAgIBATAKBggqhkjOPQQDBDA4MQswCQYDVQQGEwJYWDEUMBIG
A1UECgwLQ2VydHMgJ3IgVXMxEzARBgNVBAMMCklzc3VpbmcgQ0EwHhcNMjQwMzI5
MTM0ODM4WhcNMjUwMzI5MTM0ODM4WjA4MQswCQYDVQQGEwJYWDEUMBIGA1UECgwL
Q2VydHMgJ3IgVXMxEzARBgNVBAMMCklzc3VpbmcgQ0EwgZswEAYHKoZIzj0CAQYF
K4EEACMDgYYABAHQ/XJXqEx0f1YldcBzhdvr8vUr6lgIPbgv3RUx2KrjzIdf8C/3
+i2iYNjrYtbS9dZJJ44yFzagYoy7swMItuYY2wD2KtIExkYDWbyBiriWG/Dw/A7F
quikKBc85W8A3psVfB5cgsZPVi/K3vxKTCj200LPPvYW/ILTO3KFySHyvzb92KNC
MEAwHQYDVR0OBBYEFI7CFAlgduqQOOk5rhttUsQXfZ++MA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgIEMAoGCCqGSM49BAMEA4GMADCBiAJCANlgNm6mhhsB
qYs1+QkmwZzqs7/ELOBn27K8vFIJeqzbW4IZIuKNIU4EwbE2NTvGsk1r6oVKhmfa
K7wogMBCOcNCAkIBZbbaspmRuDsdkqMeV2qX1PEw/rmFbhbUUqpidVlfy1x2TxTy
Csa6QX2FciQ/1xynp8OLMohxQ2Dd0l58Vkufi2A=
-----END CERTIFICATE-----

  0 553: SEQUENCE {
  4 394:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13   1:     INTEGER 1
 16  10:     SEQUENCE {
 18   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 28  56:     SEQUENCE {
 30  11:       SET {
 32   9:         SEQUENCE {
 34   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 39   2:           PrintableString 'XX'
       :           }
       :         }
 43  20:       SET {
 45  18:         SEQUENCE {
 47   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 52  11:           UTF8String 'Certs 'r Us'
       :           }
       :         }
 65  19:       SET {
 67  17:         SEQUENCE {
 69   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 74  10:           UTF8String 'Issuing CA'
       :           }
       :         }
       :       }
 86  30:     SEQUENCE {
 88  13:       UTCTime 29/03/2024 13:48:38 GMT
103  13:       UTCTime 29/03/2025 13:48:38 GMT
       :       }
118  56:     SEQUENCE {
120  11:       SET {
122   9:         SEQUENCE {
124   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
129   2:           PrintableString 'XX'
       :           }
       :         }
133  20:       SET {
135  18:         SEQUENCE {
137   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
142  11:           UTF8String 'Certs 'r Us'
       :           }
       :         }
155  19:       SET {
157  17:         SEQUENCE {
159   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
164  10:           UTF8String 'Issuing CA'
       :           }
       :         }
       :       }
176 155:     SEQUENCE {
179  16:       SEQUENCE {
181   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
190   5:         OBJECT IDENTIFIER secp521r1 (1 3 132 0 35)
       :         }
197 134:       BIT STRING
       :         04 01 D0 FD 72 57 A8 4C 74 7F 56 25 75 C0 73 85
       :         DB EB F2 F5 2B EA 58 08 3D B8 2F DD 15 31 D8 AA
       :         E3 CC 87 5F F0 2F F7 FA 2D A2 60 D8 EB 62 D6 D2
       :         F5 D6 49 27 8E 32 17 36 A0 62 8C BB B3 03 08 B6
       :         E6 18 DB 00 F6 2A D2 04 C6 46 03 59 BC 81 8A B8
       :         96 1B F0 F0 FC 0E C5 AA E8 A4 28 17 3C E5 6F 00
       :         DE 9B 15 7C 1E 5C 82 C6 4F 56 2F CA DE FC 4A 4C
       :         28 F6 D3 42 CF 3E F6 16 FC 82 D3 3B 72 85 C9 21
       :         F2 BF 36 FD D8
       :       }
334  66:     [3] {
336  64:       SEQUENCE {
338  29:         SEQUENCE {
340   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
345  22:           OCTET STRING, encapsulates {
347  20:             OCTET STRING
       :               8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :               17 7D 9F BE
       :             }
       :           }
369  15:         SEQUENCE {
371   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
376   1:           BOOLEAN TRUE
379   5:           OCTET STRING, encapsulates {
381   3:             SEQUENCE {
383   1:               BOOLEAN TRUE
       :               }
       :             }
       :           }
386  14:         SEQUENCE {
388   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
393   1:           BOOLEAN TRUE
396   4:           OCTET STRING, encapsulates {
398   2:             BIT STRING 2 unused bits
       :               '100000'B (bit 5)
       :             }
       :           }
       :         }
       :       }
       :     }
402  10:   SEQUENCE {
404   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
414 140:   BIT STRING, encapsulates {
418 136:     SEQUENCE {
421  66:       INTEGER
       :         00 D9 60 36 6E A6 86 1B 01 A9 8B 35 F9 09 26 C1
       :         9C EA B3 BF C4 2C E0 67 DB B2 BC BC 52 09 7A AC
       :         DB 5B 82 19 22 E2 8D 21 4E 04 C1 B1 36 35 3B C6
       :         B2 4D 6B EA 85 4A 86 67 DA 2B BC 28 80 C0 42 39
       :         C3 42
489  66:       INTEGER
       :         01 65 B6 DA B2 99 91 B8 3B 1D 92 A3 1E 57 6A 97
       :         D4 F1 30 FE B9 85 6E 16 D4 52 AA 62 75 59 5F CB
       :         5C 76 4F 14 F2 0A C6 BA 41 7D 85 72 24 3F D7 1C
       :         A7 A7 C3 8B 32 88 71 43 60 DD D2 5E 7C 56 4B 9F
       :         8B 60
       :       }
       :     }
       :   }

## End-entity Certificate

This is an end-entity certificate whose status is requested and
returned in the OCSP request and response examples below.

-----BEGIN CERTIFICATE-----
MIIB2jCCATygAwIBAgIEAarwDTAKBggqhkjOPQQDBDA4MQswCQYDVQQGEwJYWDEU
MBIGA1UECgwLQ2VydHMgJ3IgVXMxEzARBgNVBAMMCklzc3VpbmcgQ0EwHhcNMjQw
MzI5MTM0ODM4WhcNMjUwMzI5MTM0ODM4WjAcMRowGAYDVQQDDBF4bi0tMThqNGQu
ZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyjdERS
xyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36QpCpJ
QnKjUDBOMB0GA1UdDgQWBBRbcKeYF/ef9jfS9+PcRGwhCde71DAfBgNVHSMEGDAW
gBSOwhQJYHbqkDjpOa4bbVLEF32fvjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAME
A4GLADCBhwJCAIwWNjfqcv9BKpHYAoXAHfOsECaC/RbhOtl6dNINKC6Pnp/0SeBJ
+rldnyWe/60dLmZ98+E/0F6yqXvp/Q7GS0sGAkFWbsahsjQdiMHe/J/JOlpe30N+
C07Q1LzeiJTgSiyO7O3zpRC3/AjQlRKUXi6fr8fU05wbuZBMz3vJmqqGH4aKvw==
-----END CERTIFICATE-----

  0 474: SEQUENCE {
  4 316:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13   4:     INTEGER 27979789
 19  10:     SEQUENCE {
 21   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 31  56:     SEQUENCE {
 33  11:       SET {
 35   9:         SEQUENCE {
 37   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 42   2:           PrintableString 'XX'
       :           }
       :         }
 46  20:       SET {
 48  18:         SEQUENCE {
 50   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 55  11:           UTF8String 'Certs 'r Us'
       :           }
       :         }
 68  19:       SET {
 70  17:         SEQUENCE {
 72   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 77  10:           UTF8String 'Issuing CA'
       :           }
       :         }
       :       }
 89  30:     SEQUENCE {
 91  13:       UTCTime 29/03/2024 13:48:38 GMT
106  13:       UTCTime 29/03/2025 13:48:38 GMT
       :       }
121  28:     SEQUENCE {
123  26:       SET {
125  24:         SEQUENCE {
127   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
132  17:           UTF8String 'xn--18j4d.example'
       :           }
       :         }
       :       }
151  89:     SEQUENCE {
153  19:       SEQUENCE {
155   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
164   8:         OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :         }
174  66:       BIT STRING
       :         04 42 25 48 F8 8F B7 82 FF B5 EC A3 74 44 52 C7
       :         2A 1E 55 8F BD 6F 73 BE 5E 48 E9 32 32 CC 45 C5
       :         B1 6C 4C D1 0C 4C B8 D5 B8 A1 71 39 E9 48 82 C8
       :         99 25 72 99 34 25 F4 14 19 AB 7E 90 A4 2A 49 42
       :         72
       :       }
242  80:     [3] {
244  78:       SEQUENCE {
246  29:         SEQUENCE {
248   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
253  22:           OCTET STRING, encapsulates {
255  20:             OCTET STRING
       :               5B 70 A7 98 17 F7 9F F6 37 D2 F7 E3 DC 44 6C 21
       :               09 D7 BB D4
       :             }
       :           }
277  31:         SEQUENCE {
279   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
284  24:           OCTET STRING, encapsulates {
286  22:             SEQUENCE {
288  20:               [0]
       :               8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :               17 7D 9F BE
       :               }
       :             }
       :           }
310  12:         SEQUENCE {
312   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
317   1:           BOOLEAN TRUE
320   2:           OCTET STRING, encapsulates {
322   0:             SEQUENCE {}
       :             }
       :           }
       :         }
       :       }
       :     }
324  10:   SEQUENCE {
326   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
336 139:   BIT STRING, encapsulates {
340 135:     SEQUENCE {
343  66:       INTEGER
       :         00 8C 16 36 37 EA 72 FF 41 2A 91 D8 02 85 C0 1D
       :         F3 AC 10 26 82 FD 16 E1 3A D9 7A 74 D2 0D 28 2E
       :         8F 9E 9F F4 49 E0 49 FA B9 5D 9F 25 9E FF AD 1D
       :         2E 66 7D F3 E1 3F D0 5E B2 A9 7B E9 FD 0E C6 4B
       :         4B 06
411  65:       INTEGER
       :         56 6E C6 A1 B2 34 1D 88 C1 DE FC 9F C9 3A 5A 5E
       :         DF 43 7E 0B 4E D0 D4 BC DE 88 94 E0 4A 2C 8E EC
       :         ED F3 A5 10 B7 FC 08 D0 95 12 94 5E 2E 9F AF C7
       :         D4 D3 9C 1B B9 90 4C CF 7B C9 9A AA 86 1F 86 8A
       :         BF
       :       }
       :     }
       :   }

## OCSP Responder Certificate

This is a certificate for the OCSP delegated response that signed the
OCSP response example below.

-----BEGIN CERTIFICATE-----
MIICOjCCAZugAwIBAgIBATAKBggqhkjOPQQDBDA4MQswCQYDVQQGEwJYWDEUMBIG
A1UECgwLQ2VydHMgJ3IgVXMxEzARBgNVBAMMCklzc3VpbmcgQ0EwHhcNMjQwMzI5
MTM0ODM4WhcNMjUwMzI5MTM0ODM4WjA8MQswCQYDVQQGEwJYWDEUMBIGA1UECgwL
Q2VydHMgJ3IgVXMxFzAVBgNVBAMMDk9DU1AgUmVzcG9uZGVyMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr/soRsdla27VHNK9X
C/grcijPImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWNprNGOWE6j7m1qNpI
xnRxF/mRnoQk837Io3UwczAdBgNVHQ4EFgQUCuOg/p3UJXaYtety68oM57899fEw
HwYDVR0jBBgwFoAUjsIUCWB26pA46TmuG21SxBd9n74wDAYDVR0TAQH/BAIwADAO
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwCgYIKoZIzj0EAwQD
gYwAMIGIAkIBgzvGLy3l1ZyKyaNpkWQOyvtu0ZSoKmjyDC3POJ140PplWTbwoRb0
PapVKKcwjvcny64wiWNZxbED0e0ndMtps68CQgFxAskzkPmLklGw+bDZCQ9r37cK
knDPqT9POGQixb49esHjcSKlSekQ9FabbvYah+aNWtFhpY8WxZDKUEsWHXNJ/Q==
-----END CERTIFICATE-----

  0 570: SEQUENCE {
  4 411:   SEQUENCE {
  8   3:     [0] {
 10   1:       INTEGER 2
       :       }
 13   1:     INTEGER 1
 16  10:     SEQUENCE {
 18   8:       OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :       }
 28  56:     SEQUENCE {
 30  11:       SET {
 32   9:         SEQUENCE {
 34   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 39   2:           PrintableString 'XX'
       :           }
       :         }
 43  20:       SET {
 45  18:         SEQUENCE {
 47   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 52  11:           UTF8String 'Certs 'r Us'
       :           }
       :         }
 65  19:       SET {
 67  17:         SEQUENCE {
 69   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 74  10:           UTF8String 'Issuing CA'
       :           }
       :         }
       :       }
 86  30:     SEQUENCE {
 88  13:       UTCTime 29/03/2024 13:48:38 GMT
103  13:       UTCTime 29/03/2025 13:48:38 GMT
       :       }
118  60:     SEQUENCE {
120  11:       SET {
122   9:         SEQUENCE {
124   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
129   2:           PrintableString 'XX'
       :           }
       :         }
133  20:       SET {
135  18:         SEQUENCE {
137   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
142  11:           UTF8String 'Certs 'r Us'
       :           }
       :         }
155  23:       SET {
157  21:         SEQUENCE {
159   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
164  14:           UTF8String 'OCSP Responder'
       :           }
       :         }
       :       }
180 118:     SEQUENCE {
182  16:       SEQUENCE {
184   7:         OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
193   5:         OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
       :         }
200  98:       BIT STRING
       :         04 5B 09 01 B8 85 23 29 6E B9 19 D5 0F FA 1A 9C
       :         B3 74 BC 4D 40 95 86 28 2B FE CA 11 B1 D9 5A DB
       :         B5 47 34 AF 57 0B F8 2B 72 28 CF 22 6B CF 4C 25
       :         DD BC FE 3B 1A 3A D3 94 30 EF F7 63 E1 D6 8D 2E
       :         15 1D 91 72 0B 77 95 B5 8D A6 B3 46 39 61 3A 8F
       :         B9 B5 A8 DA 48 C6 74 71 17 F9 91 9E 84 24 F3 7E
       :         C8
       :       }
300 117:     [3] {
302 115:       SEQUENCE {
304  29:         SEQUENCE {
306   3:           OBJECT IDENTIFIER subjectKeyIdentifier (2 5 29 14)
311  22:           OCTET STRING, encapsulates {
313  20:             OCTET STRING
       :               0A E3 A0 FE 9D D4 25 76 98 B5 EB 72 EB CA 0C E7
       :               BF 3D F5 F1
       :             }
       :           }
335  31:         SEQUENCE {
337   3:           OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
342  24:           OCTET STRING, encapsulates {
344  22:             SEQUENCE {
346  20:               [0]
       :               8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :               17 7D 9F BE
       :               }
       :             }
       :           }
368  12:         SEQUENCE {
370   3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
375   1:           BOOLEAN TRUE
378   2:           OCTET STRING, encapsulates {
380   0:             SEQUENCE {}
       :             }
       :           }
382  14:         SEQUENCE {
384   3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
389   1:           BOOLEAN TRUE
392   4:           OCTET STRING, encapsulates {
394   2:             BIT STRING 7 unused bits
       :               '1'B (bit 0)
       :             }
       :           }
398  19:         SEQUENCE {
400   3:           OBJECT IDENTIFIER extKeyUsage (2 5 29 37)
405  12:           OCTET STRING, encapsulates {
407  10:             SEQUENCE {
409   8:               OBJECT IDENTIFIER ocspSigning (1 3 6 1 5 5 7 3 9)
       :               }
       :             }
       :           }
       :         }
       :       }
       :     }
419  10:   SEQUENCE {
421   8:     OBJECT IDENTIFIER ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :     }
431 140:   BIT STRING, encapsulates {
435 136:     SEQUENCE {
438  66:       INTEGER
       :         01 83 3B C6 2F 2D E5 D5 9C 8A C9 A3 69 91 64 0E
       :         CA FB 6E D1 94 A8 2A 68 F2 0C 2D CF 38 9D 78 D0
       :         FA 65 59 36 F0 A1 16 F4 3D AA 55 28 A7 30 8E F7
       :         27 CB AE 30 89 63 59 C5 B1 03 D1 ED 27 74 CB 69
       :         B3 AF
506  66:       INTEGER
       :         01 71 02 C9 33 90 F9 8B 92 51 B0 F9 B0 D9 09 0F
       :         6B DF B7 0A 92 70 CF A9 3F 4F 38 64 22 C5 BE 3D
       :         7A C1 E3 71 22 A5 49 E9 10 F4 56 9B 6E F6 1A 87
       :         E6 8D 5A D1 61 A5 8F 16 C5 90 CA 50 4B 16 1D 73
       :         49 FD
       :       }
       :     }
       :   }

## OCSP Request

This is a base64-encoded OCSP request for the end-entity certificate
above.

MGEwXzBdMFswWTANBglghkgBZQMEAgEFAAQgOplGd1aAc6cHv95QGGNF5M1hNNsI
Xrqh0QQl8DtvCOoEIEdKbKMB8j3J9/cHhwThx/X8lucWdfbtiC56tlw/WEVDAgQB
qvAN
  0  97: SEQUENCE {
  2  95:   SEQUENCE {
  4  93:     SEQUENCE {
  6  91:       SEQUENCE {
  8  89:         SEQUENCE {
 10  13:           SEQUENCE {
 12   9:             OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)
 23   0:             NULL
       :             }
 25  32:           OCTET STRING
       :             3A 99 46 77 56 80 73 A7 07 BF DE 50 18 63 45 E4
       :             CD 61 34 DB 08 5E BA A1 D1 04 25 F0 3B 6F 08 EA
 59  32:           OCTET STRING
       :             47 4A 6C A3 01 F2 3D C9 F7 F7 07 87 04 E1 C7 F5
       :             FC 96 E7 16 75 F6 ED 88 2E 7A B6 5C 3F 58 45 43
 93   4:           INTEGER 27979789
       :           }
       :         }
       :       }
       :     }
       :   }

## OCSP Response

This is a base64-encoded OCSP response for the end-entity certificate
above.

MIIDjgoBAKCCA4cwggODBgkrBgEFBQcwAQEEggN0MIIDcDCBsKIWBBQK46D+ndQl
dpi163Lrygznvz318RgPMjAyNDAzMjkxMzQ4MzhaMIGEMIGBMFkwDQYJYIZIAWUD
BAIBBQAEIDqZRndWgHOnB7/eUBhjReTNYTTbCF66odEEJfA7bwjqBCBHSmyjAfI9
yff3B4cE4cf1/JbnFnX27YguerZcP1hFQwIEAarwDYAAGA8yMDI0MDMzMDEzNDgz
OFqgERgPMjAyNDA0MDYxMzQ4MzhaMAoGCCqGSM49BAMDA2kAMGYCMQCQhPNMOvmZ
1gZ2dOfmn69HlPHrAezVzXkSBZduV5yvBbdEu+21pWIfpHBX/dz0TssCMQD5VN8n
/9IDHqIy1BGXfKEskzK4l86ef9mw2atx5jbso2ztXT2Vzjd137jMhJsV2zqgggJC
MIICPjCCAjowggGboAMCAQICAQEwCgYIKoZIzj0EAwQwODELMAkGA1UEBhMCWFgx
FDASBgNVBAoMC0NlcnRzICdyIFVzMRMwEQYDVQQDDApJc3N1aW5nIENBMB4XDTI0
MDMyOTEzNDgzOFoXDTI1MDMyOTEzNDgzOFowPDELMAkGA1UEBhMCWFgxFDASBgNV
BAoMC0NlcnRzICdyIFVzMRcwFQYDVQQDDA5PQ1NQIFJlc3BvbmRlcjB2MBAGByqG
SM49AgEGBSuBBAAiA2IABFsJAbiFIyluuRnVD/oanLN0vE1AlYYoK/7KEbHZWtu1
RzSvVwv4K3IozyJrz0wl3bz+Oxo605Qw7/dj4daNLhUdkXILd5W1jaazRjlhOo+5
tajaSMZ0cRf5kZ6EJPN+yKN1MHMwHQYDVR0OBBYEFArjoP6d1CV2mLXrcuvKDOe/
PfXxMB8GA1UdIwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++MAwGA1UdEwEB/wQC
MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMAoGCCqGSM49
BAMEA4GMADCBiAJCAYM7xi8t5dWcismjaZFkDsr7btGUqCpo8gwtzzideND6ZVk2
8KEW9D2qVSinMI73J8uuMIljWcWxA9HtJ3TLabOvAkIBcQLJM5D5i5JRsPmw2QkP
a9+3CpJwz6k/TzhkIsW+PXrB43EipUnpEPRWm272GofmjVrRYaWPFsWQylBLFh1z
Sf0=
  0 910: SEQUENCE {
  4   1:   ENUMERATED 0
  7 903:   [0] {
 11 899:     SEQUENCE {
 15   9:       OBJECT IDENTIFIER ocspBasic (1 3 6 1 5 5 7 48 1 1)
 26 884:       OCTET STRING, encapsulates {
 30 880:         SEQUENCE {
 34 176:           SEQUENCE {
 37  22:             [2] {
 39  20:               OCTET STRING
       :               0A E3 A0 FE 9D D4 25 76 98 B5 EB 72 EB CA 0C E7
       :               BF 3D F5 F1
       :               }
 61  15:             GeneralizedTime 29/03/2024 13:48:38 GMT
 78 132:             SEQUENCE {
 81 129:               SEQUENCE {
 84  89:                 SEQUENCE {
 86  13:                   SEQUENCE {
 88   9:                     OBJECT IDENTIFIER
       :                       sha-256 (2 16 840 1 101 3 4 2 1)
 99   0:                     NULL
       :                     }
101  32:                   OCTET STRING
       :               3A 99 46 77 56 80 73 A7 07 BF DE 50 18 63 45 E4
       :               CD 61 34 DB 08 5E BA A1 D1 04 25 F0 3B 6F 08 EA
135  32:                   OCTET STRING
       :               47 4A 6C A3 01 F2 3D C9 F7 F7 07 87 04 E1 C7 F5
       :               FC 96 E7 16 75 F6 ED 88 2E 7A B6 5C 3F 58 45 43
169   4:                   INTEGER 27979789
       :                   }
175   0:                 [0]
177  15:                 GeneralizedTime 30/03/2024 13:48:38 GMT
194  17:                 [0] {
196  15:                   GeneralizedTime 06/04/2024 13:48:38 GMT
       :                   }
       :                 }
       :               }
       :             }
213  10:           SEQUENCE {
215   8:             OBJECT IDENTIFIER
       :               ecdsaWithSHA384 (1 2 840 10045 4 3 3)
       :             }
225 105:           BIT STRING, encapsulates {
228 102:             SEQUENCE {
230  49:               INTEGER
       :               00 90 84 F3 4C 3A F9 99 D6 06 76 74 E7 E6 9F AF
       :               47 94 F1 EB 01 EC D5 CD 79 12 05 97 6E 57 9C AF
       :               05 B7 44 BB ED B5 A5 62 1F A4 70 57 FD DC F4 4E
       :               CB
281  49:               INTEGER
       :               00 F9 54 DF 27 FF D2 03 1E A2 32 D4 11 97 7C A1
       :               2C 93 32 B8 97 CE 9E 7F D9 B0 D9 AB 71 E6 36 EC
       :               A3 6C ED 5D 3D 95 CE 37 75 DF B8 CC 84 9B 15 DB
       :               3A
       :               }
       :             }
332 578:           [0] {
336 574:             SEQUENCE {
340 570:               SEQUENCE {
344 411:                 SEQUENCE {
348   3:                   [0] {
350   1:                     INTEGER 2
       :                     }
353   1:                   INTEGER 1
356  10:                   SEQUENCE {
358   8:                     OBJECT IDENTIFIER
       :                       ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :                     }
368  56:                   SEQUENCE {
370  11:                     SET {
372   9:                       SEQUENCE {
374   3:                         OBJECT IDENTIFIER countryName (2 5 4 6)
379   2:                         PrintableString 'XX'
       :                         }
       :                       }
383  20:                     SET {
385  18:                       SEQUENCE {
387   3:                         OBJECT IDENTIFIER
       :                           organizationName (2 5 4 10)
392  11:                         UTF8String 'Certs 'r Us'
       :                         }
       :                       }
405  19:                     SET {
407  17:                       SEQUENCE {
409   3:                         OBJECT IDENTIFIER commonName (2 5 4 3)
414  10:                         UTF8String 'Issuing CA'
       :                         }
       :                       }
       :                     }
426  30:                   SEQUENCE {
428  13:                     UTCTime 29/03/2024 13:48:38 GMT
443  13:                     UTCTime 29/03/2025 13:48:38 GMT
       :                     }
458  60:                   SEQUENCE {
460  11:                     SET {
462   9:                       SEQUENCE {
464   3:                         OBJECT IDENTIFIER countryName (2 5 4 6)
469   2:                         PrintableString 'XX'
       :                         }
       :                       }
473  20:                     SET {
475  18:                       SEQUENCE {
477   3:                         OBJECT IDENTIFIER
       :                           organizationName (2 5 4 10)
482  11:                         UTF8String 'Certs 'r Us'
       :                         }
       :                       }
495  23:                     SET {
497  21:                       SEQUENCE {
499   3:                         OBJECT IDENTIFIER commonName (2 5 4 3)
504  14:                         UTF8String 'OCSP Responder'
       :                         }
       :                       }
       :                     }
520 118:                   SEQUENCE {
522  16:                     SEQUENCE {
524   7:                       OBJECT IDENTIFIER
       :                         ecPublicKey (1 2 840 10045 2 1)
533   5:                       OBJECT IDENTIFIER
       :                         secp384r1 (1 3 132 0 34)
       :                       }
540  98:                     BIT STRING
       :               04 5B 09 01 B8 85 23 29 6E B9 19 D5 0F FA 1A 9C
       :               B3 74 BC 4D 40 95 86 28 2B FE CA 11 B1 D9 5A DB
       :               B5 47 34 AF 57 0B F8 2B 72 28 CF 22 6B CF 4C 25
       :               DD BC FE 3B 1A 3A D3 94 30 EF F7 63 E1 D6 8D 2E
       :               15 1D 91 72 0B 77 95 B5 8D A6 B3 46 39 61 3A 8F
       :               B9 B5 A8 DA 48 C6 74 71 17 F9 91 9E 84 24 F3 7E
       :               C8
       :                     }
640 117:                   [3] {
642 115:                     SEQUENCE {
644  29:                       SEQUENCE {
646   3:                         OBJECT IDENTIFIER
       :                           subjectKeyIdentifier (2 5 29 14)
651  22:                         OCTET STRING, encapsulates {
653  20:                           OCTET STRING
       :               0A E3 A0 FE 9D D4 25 76 98 B5 EB 72 EB CA 0C E7
       :               BF 3D F5 F1
       :                           }
       :                         }
675  31:                       SEQUENCE {
677   3:                         OBJECT IDENTIFIER
       :                           authorityKeyIdentifier (2 5 29 35)
682  24:                         OCTET STRING, encapsulates {
684  22:                           SEQUENCE {
686  20:                             [0]
       :               8E C2 14 09 60 76 EA 90 38 E9 39 AE 1B 6D 52 C4
       :               17 7D 9F BE
       :                             }
       :                           }
       :                         }
708  12:                       SEQUENCE {
710   3:                         OBJECT IDENTIFIER
       :                           basicConstraints (2 5 29 19)
715   1:                         BOOLEAN TRUE
718   2:                         OCTET STRING, encapsulates {
720   0:                           SEQUENCE {}
       :                           }
       :                         }
722  14:                       SEQUENCE {
724   3:                         OBJECT IDENTIFIER keyUsage (2 5 29 15)
729   1:                         BOOLEAN TRUE
732   4:                         OCTET STRING, encapsulates {
734   2:                           BIT STRING 7 unused bits
       :                             '1'B (bit 0)
       :                           }
       :                         }
738  19:                       SEQUENCE {
740   3:                         OBJECT IDENTIFIER
       :                           extKeyUsage (2 5 29 37)
745  12:                         OCTET STRING, encapsulates {
747  10:                           SEQUENCE {
749   8:                             OBJECT IDENTIFIER
       :                               ocspSigning (1 3 6 1 5 5 7 3 9)
       :                             }
       :                           }
       :                         }
       :                       }
       :                     }
       :                   }
759  10:                 SEQUENCE {
761   8:                   OBJECT IDENTIFIER
       :                     ecdsaWithSHA512 (1 2 840 10045 4 3 4)
       :                   }
771 140:                 BIT STRING, encapsulates {
775 136:                   SEQUENCE {
778  66:                     INTEGER
       :               01 83 3B C6 2F 2D E5 D5 9C 8A C9 A3 69 91 64 0E
       :               CA FB 6E D1 94 A8 2A 68 F2 0C 2D CF 38 9D 78 D0
       :               FA 65 59 36 F0 A1 16 F4 3D AA 55 28 A7 30 8E F7
       :               27 CB AE 30 89 63 59 C5 B1 03 D1 ED 27 74 CB 69
       :               B3 AF
846  66:                     INTEGER
       :               01 71 02 C9 33 90 F9 8B 92 51 B0 F9 B0 D9 09 0F
       :               6B DF B7 0A 92 70 CF A9 3F 4F 38 64 22 C5 BE 3D
       :               7A C1 E3 71 22 A5 49 E9 10 F4 56 9B 6E F6 1A 87
       :               E6 8D 5A D1 61 A5 8F 16 C5 90 CA 50 4B 16 1D 73
       :               49 FD
       :                     }
       :                   }
       :                 }
       :               }
       :             }
       :           }
       :         }
       :       }
       :     }
       :   }

# Acknowledgments
{:numbered="false"}

The authors of this version of the document wish to thank Alex Deacon
and Ryan Hurst for their work to produce the original version
of the lightweight profile for the OCSP protocol.

The authors of this version of the document wish to thank
Paul Kyzivat, Russ Housley, Rob Stradling, Roman Danyliw, and
Wendy Brown for their reviews, feedback, and suggestions.

The authors wish to thank Magnus Nystrom of RSA Security, Inc.,
Jagjeet Sondh of Vodafone Group R&D, and David Engberg of CoreStreet,
Ltd. for their contributions to the original {{RFC5019}} specification.
Listed organizational affiliations reflect the author’s affiliation
at the time of RFC5019 was published.
