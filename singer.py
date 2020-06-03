import hashlib
import nacl.signing
import nacl.encoding
from pyld import jsonld
from pyld.jsonld import JsonLdProcessor


proof= {
    '@context':'https://w3id.org/security/v2',
    'type': 'Ed25519Signature2018',
    'created': '2020-06-03T01:05:47Z', #<---- this should not be hardcoded
    'verificationMethod': 'did:self:GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza#key1',
    'proofPurpose': 'assertionMethod'
  }

doc = {
    '@context':'https://w3id.org/security/v2',
    'id': 'did:self:GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza',
    'publicKey': [
      {
        'type': 'Ed25519VerificationKey2018',
        'id': 'did:self:GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza#key1',
        'controller': 'did:self:GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza',
        'publicKeyBase58':'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
      }
    ],
    'authentication': [
      {
        'type':'ED25519SigningAuthentication',
        'publicKey': 'did:self:GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza#key1'
      }
    ]
}

jws_header       = b'{"alg":"EdDSA","b64":false,"crit":["b64"]}'
privkey          = '826CB6B9EA7C0752F78F600805F9005ACB66CAA340B0F5CFA6BF41D470D49475'
normalized_doc   = jsonld.normalize(doc , {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
normalized_proof = jsonld.normalize(proof, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
doc_hash         = hashlib.sha256()
proof_hash       = hashlib.sha256()

doc_hash.update(normalized_doc.encode('utf-8'))
proof_hash.update(normalized_proof.encode('utf-8'))
signing_key   = nacl.signing.SigningKey(privkey,nacl.encoding.HexEncoder)
encodedHeader = nacl.encoding.URLSafeBase64Encoder.encode(jws_header)
to_sign       = encodedHeader + b'.' + proof_hash.digest() + doc_hash.digest()
signed_data   = signing_key.sign(to_sign)
jws           = encodedHeader + b'..' + nacl.encoding.URLSafeBase64Encoder.encode(signed_data.signature)
proof['jws']  = jws.decode()[:-2]
del proof['@context']
print(proof)