import base64
import datetime
import subprocess
import tempfile

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization, hashes

_CA_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB2STcygqIf42Zdno32HTmN6Esy0d9bghmU1ZpTWi3ZV5QaWOP3ntF
yFQBPcd6NbGGVbhMlmpgIg1A+R7Z9RRYAuqgBwYFK4EEACOhgYkDgYYABAHQ/XJX
qEx0f1YldcBzhdvr8vUr6lgIPbgv3RUx2KrjzIdf8C/3+i2iYNjrYtbS9dZJJ44y
FzagYoy7swMItuYY2wD2KtIExkYDWbyBiriWG/Dw/A7FquikKBc85W8A3psVfB5c
gsZPVi/K3vxKTCj200LPPvYW/ILTO3KFySHyvzb92A==
-----END EC PRIVATE KEY-----
""".encode(), password=None)


_EE_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49
AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END EC PRIVATE KEY-----
""".encode(), password=None)


_RESPONDER_KEY = serialization.load_pem_private_key("""
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDiVjMo36v2gYhga5EyQoHB1YpEVkMbCdUQs1/syfMHyhgihG+iZxNx
qagbrA41dJ2gBwYFK4EEACKhZANiAARbCQG4hSMpbrkZ1Q/6GpyzdLxNQJWGKCv+
yhGx2VrbtUc0r1cL+CtyKM8ia89MJd28/jsaOtOUMO/3Y+HWjS4VHZFyC3eVtY2m
s0Y5YTqPubWo2kjGdHEX+ZGehCTzfsg=
-----END EC PRIVATE KEY-----
""".encode(), password=None)


ca_name = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'XX'),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Certs \'r Us'),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Issuing CA')
])

responder_name = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'XX'),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Certs \'r Us'),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'OCSP Responder')
])

ee_name = x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, 'xn--18j4d.example')
])

now = datetime.datetime.now(tz=datetime.timezone.utc)


ca_cert = (
    x509.CertificateBuilder()
    .serial_number(1)
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .issuer_name(ca_name)
    .subject_name(ca_name)
    .public_key(_CA_KEY.public_key())
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(_CA_KEY.public_key()), False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    .add_extension(x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True, crl_sign=False, encipher_only=False, decipher_only=False
    ), True)
    .sign(_CA_KEY, hashes.SHA512())
)


ee_cert = (
    x509.CertificateBuilder()
    .serial_number(27979789)
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .issuer_name(ca_name)
    .subject_name(ee_name)
    .public_key(_EE_KEY.public_key())
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(_EE_KEY.public_key()), False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(_CA_KEY.public_key()), False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    .sign(_CA_KEY, hashes.SHA512())
)

ocsp_cert = (
    x509.CertificateBuilder()
    .serial_number(1)
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .issuer_name(ca_name)
    .subject_name(responder_name)
    .public_key(_RESPONDER_KEY.public_key())
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(_RESPONDER_KEY.public_key()), False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(_CA_KEY.public_key()), False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
    .add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
    ), True)
    .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.OCSP_SIGNING]), False)
    .sign(_CA_KEY, hashes.SHA512())
)

request = (
    ocsp.OCSPRequestBuilder()
    .add_certificate(ee_cert, ca_cert, hashes.SHA256())
    .build()
)


response = (
    ocsp.OCSPResponseBuilder()
    .responder_id(ocsp.OCSPResponderEncoding.HASH, ocsp_cert)
    .add_response(ee_cert, ca_cert, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD,
                  now + datetime.timedelta(days=1),
                  now + datetime.timedelta(days=8), None, None)
    .certificates([ocsp_cert])
    .sign(_RESPONDER_KEY, hashes.SHA384())
)


def _dumpasn1(doc):
    octets = doc.public_bytes(serialization.Encoding.DER)

    if isinstance(doc, x509.Certificate):
        print(doc.public_bytes(serialization.Encoding.PEM).decode())
    else:
        b64 = base64.b64encode(octets).decode()

        print('\n'.join((b64[p:p + 64] for p in range(0, len(b64), 64))))

    with tempfile.NamedTemporaryFile() as f:
        f.write(octets)
        f.flush()

        output = subprocess.check_output(['dumpasn1', '-z', '-w72', f.name], stderr=subprocess.DEVNULL).decode()

        print(output)


_dumpasn1(ca_cert)
_dumpasn1(ee_cert)
_dumpasn1(ocsp_cert)

_dumpasn1(request)
_dumpasn1(response)
