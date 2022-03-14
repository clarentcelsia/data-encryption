Data Encryption
================
- [RSA (Rivest-Shamir-Adleman)](#rsa-encryption)
- [AES (Advanced Encryption Standard)](#aes-encryption)

RSA-Encryption
=====
RSA is asymmetric key encryption algorithm which uses 2 key called public key and private key.
Public key is used to encrypt the message while private key is used to decrypt the message. Mainly used for exchanging little information i.e digital signature.

How RSA encryption works ?
--------------------------
- User has a generated key pair (public and private). <br/>
- Public key will be used to encrypt the data then it results cipher text. With the private key, cipher text will be decrypted.<br/>
- Each user can have more than 1 public key from different users, for they send the data (encrypt) to that user and the only way to read the sent message is by using receiver's private key.
<br/>

<img src="https://miro.medium.com/max/762/1*3jC0DfMU78HVVq2Ci_2eXg.png" alt="rsa">

*src: <https://medium.com/@jinkyulim96/algorithms-explained-rsa-encryption-9a37083aaa62>*
<br/>

What is signing and verifying in RSA ?
--------------------------------------
Signing asserts the authenticity of the data.
RSA Signing often called "Signature" that is generated from the message using private key.
User who wants to send the message have to send their signature as well signifies that the message actually came from the party by whom the public key is issued.

AES-Encryption
==============
AES is a symmetric key encryption algorithm where one key can be used to encrypt and decrypt the message.
AES is widely used for protecting data at REST and also for encrypted communications and secure data storage.

How AES encryption works ?
---------------------------

AES includes 3 block ciphers:

1. AES-128 uses 128-bit key length to encrypt & decrypt a block of messages.
2. AES-192 uses 192-bit key length to encrypt & decrypt a block of messages.
3. AES-256 uses 256-bit key length to encrypt & decrypt a block of messages.

<br/>
<img src="https://cdn.ttgtmedia.com/rms/onlineImages/security-aes_design.jpg" alt="drawing" width="450"/>

*src: <https://cdn.ttgtmedia.com/rms/onlineImages/security-aes_design.jpg>*

{% include "git+http://github.com/clarentcelsia/data-encryption.git/Info.md" %}
