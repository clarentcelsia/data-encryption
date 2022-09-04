Data Encryption
================
- [RSA (Rivest-Shamir-Adleman)](#rsa-encryption)
- [AES (Advanced Encryption Standard)](#aes-encryption)
- [DES (Data Encryption Standard)](#des-encryption)
- [OTP (One Time Password)](#otp-authentication)

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

<br/>

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

<br>

DES-Encryption
================
DES is a symmetric block cipher that encrypts data in blocks of size of 64 bits each (8 bytes), which means 64 bits of plain text go as the input to DES, which produces 64 bits of ciphertext. The same algorithm and key are used for encryption and decryption, with minor differences as figure shown below. 

Meanwhile, 3DES  or Triple-DES is a key-algorithm which applies DES algorithm 3 times to each data block.

<img src="https://media.geeksforgeeks.org/wp-content/uploads/20200306122641/DES-11.png" width=450>

*src: <https://media.geeksforgeeks.org/wp-content/uploads/20200306122641/DES-11.png>*

<br>

OTP-Authentication
==============
Google authenticator is a software-based authenticator implements 2 step verification services (commonly called as 2 Factor Authentication) to help identifying user's identity. This authenticator uses Time-based One Time Password (OTP) and HMAC-based OTP algorithm.

One of the advantages using 2FA over SMS-based verification is user don't need to worry about not getting the password/token/else because of their provider's issue or sim card gone.
To solve the issue is to eliminate the dependency on the network provider.

TOTP (Time-based One Time Password) is an algorithm that computes OTP from a source of uniqueness (which I'm using here is a shared secret key), and current time.

HOTP (HMAC-based One Time Password) is an algorithm which uses hmac algorithm to generate OTP (n-digits deliver to user).

<img src="https://user-images.githubusercontent.com/66846357/188294418-63146965-74ca-4f72-bff2-67c93d4d75c6.png" width=200>
