---
layout: default
title:  "Public Key Infrastructure (PKI)"
date:   2024-02-06 09:00:00 +0000
categories: pki ssl tls encryption
---

# Public Key Infrastructure (PKI)

## INTRODUCTION
Public Key Infrastructure (PKI) is a set of policies, procedures and technologies that are used to create and manage assymetric key-pairs which are used to secure public Internet traffic through encryption. PKI encompasses the creation, distribution, storage and revocation of these assymetric keys in the form of digital signatures.

Asymetric key-pairs (also known as public-key cryptography) are a pair of mathematically linked cryptographic keys where one key can be used to decrypt messages encrypted by the other key, and vice versa. The concept behind assymetric encryption is that one key (known as the private key) is kept secret by the owner of the key-pair and the other key (known as the public key) can be distributed publicly and known by everyone. If someone wants to send an encrypted message to the owner which can only be decrypted by the owner then they will encrypt that message using the owner's public key. Since the only key that can decrypt that message is the owner's private key, then only the owner can decrypt the message. This remains true as long as the private key is still secret and has not been comprimised. In this way assymetric keys can provide confidentiality to messages sent.</p>

Assymetric keys can also provide integrity, authenticity and non-repudiation to messages as the owner of the key-paircan use their private key to digitally sign messages they send. This signature can be valildated using the owner's public key, thus proving that the owner was the actual sender of the message and the message was not altered during transit.

PKI provides the means for servers to prove their identity online and distribute their public key through the use ofSSL certificates. These SSL certificates are provided by third-party vendors known as Certificate Authorities (CA) who act as "trust services" and, having gone through a thorough validation of a requestor's identity, will providethe Subject with a certificate signed by their own private key. Any visitor to the Subject's website can validatethe signature using the public key of the CA, thus proving that the CA provided the certificate.

## HOW IT WORKS
The entity requesting the SSL certificate (i.e. the thing to be secured, known as the Subject) will typically create their own assymetrickey-pair and keep one of those keys secret as their private key. The Subject then creates a Certificate Signing Request which containsinformation about the Subject and the non-secret public key from the pair. This CSR is signed (encrypted) using the Subject's privatekey and sent to a Registration Authority (RA) who will perform checks to verify the identity of the Subject and validate the information in the CSR.

When the RA is satisfied that the Subject identity is true the CSR will be passed to a Certificate Authority (CA). The CA will create an SSL certificate using the details and the public key from the CSR and a serial number unique to the certificate. The certificate will only be valid for a limited time (generally 1 year) and this information will be stored in the certificate. The CA will then digitally sign this SSL certificate by creating a hash of the certificate and encrypting this hash with the CA's own private key. The encrypted hash (i.e. the digital signature) and the hashing algorithm used are added to the certificate. This SSL certificate is bound to the Subject in the CA's database. The SSL certificate and the digital signature are given to the Subject.

The Subject can then make the signed certificate available to the public. The digital signature can be used to sign anything from emails to files to software packages<span class="prompt">*</span> provided by the Subject. Any Client can use the certificate to confirm the identity of the Subject. The certificate contains information about the CA who performed the identity verification of the Subject. If the Client trusts the CA then the Client can create their own hash of the certificate using the same hashing algorithm that the CA used to create the digital signature. The Client can then use the CA's public key to decrypt the signature contained in the certificate. If the decrypted hash is equal to the hash the Client generated then they can be asssured that the certificate, and the public key contained in the certificate are valid. The Subject's public key can then be used by the Client to send encrypted messages to the Subject, or to exchange symmetric keys for setting up an encrypted communication tunnel (SSL/TLS) between itself and the Subject.

IMAGE MISSING

## CERTIFICATE REVOCATION LIST
An important part of the PKI is the use of Certificate Revocation Lists (CLR). During the certificate verification stage a Client may check to see if the Subject's certificate has been added to a CLR (CA's must issue a CRL of comprimised certificates but it is up to the Client to check these lists). These lists contain any SSL certificates that are not to be trusted, even if they are within their  validity period. If a Subject's private key were to be conprimised then the associated public key and certificate containing that key can no longer be trusted. The CA would add that comprimised certificate to the CLR so that Clients would know not to trust that certificate. If a CA's private key were comprimised then every certificate digitally signed by that private key could no longer be trusted and would need to be added to the CRL.</p>

> This is how the SolarWinds hack of 2020 was so effective in it's widespread delivery. The malicious code was injected into the build process before the compiled package was signed. With the malware included in the signed software, the software was implicitly trusted by upgrade and installation processes of customers of SolarWinds. One of the first steps performed by SolarWinds once they  became aware of the infection was to add the certificates to the CRL so that the infected software packages would no longer be  trusted by operating systems.
