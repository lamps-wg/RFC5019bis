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

RFC 5019 defines a lightweight profile for OCSP that makes the protocol
more suitable for use in high-volume environments. The lightweight
profile specifies the mandatory use of SHA-1 when calculating the values
of several fields in OCSP requests and responses. In recent years,
weaknesses have been demonstrated with the SHA-1 algorithm. As a result,
SHA-1 is increasingly falling out of use even for non-security relevant
use cases. This document obsoletes the lightweight profile as specified
in RFC 5019 to instead recommend the use of SHA-256 where SHA-1 was
previously required. An RFC 5019-compliant OCSP client is still able to
use SHA-1, but the use of SHA-1 may become obsolete in the future.

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

Substantive changes to RFC 5019:

- {{certid}} requires new OCSP clients to use SHA-256 to
support migration for OCSP clients.

- {{byKey}} requires new OCSP responders to use the byKey field,
and support migration from byName fields.

- {{transport}} clarifies OCSP clients not include
whitespace or any other characters that are not part of
the base64 character repertoire in the base64-encoded string.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# OCSP Message Profile

This section defines a subset of OCSPRequest and OCSPResponse
functionality as defined in {{RFC6960}}.

## OCSP Request Profile {#req-profile}

### OCSPRequest Structure {#certid}

The ASN.1 structure corresponding to the OCSPRequest
with the relevant CertID is:

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
that employ SHA-1 for CertID field hashes.

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


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The authors of this version of the document wish to thank Alex Deacon
and Ryan Hurst for their work to produce the original version
of the lightweight profile for the OCSP protocol.

The authors of this version of the document wish to thank
Russ Housley, Rob Stradling, Roman Danyliw, and Wendy Brown for the
feedback and suggestions.

The authors wish to thank Magnus Nystrom of RSA Security, Inc.,
Jagjeet Sondh of Vodafone Group R&D, and David Engberg of CoreStreet,
Ltd. for their contributions to the original {{RFC5019}} specification.
Listed organizational affiliations reflect the author’s affiliation
at the time of RFC5019 was published.
