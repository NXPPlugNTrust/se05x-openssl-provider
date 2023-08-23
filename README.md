# OpenSSL Provider for EdgeLock SE05x Secure Elements

A provider, in OpenSSL terms, is a unit of code that provides one or more
implementations for various operations for diverse algorithms that one might
want to perform.

Depending on the capabilities of the attached secure element (e.g. SE050_C, SE051E, ...)
the following functionality can be made available over the OpenSSL provider here (sss provider).

- EC crypto
  - EC key generation
  - EC sign/verify
  - ECDH compute key
  - CSR
- RSA crypto
  - RSA sign/verify
- Random generator

The OpenSSL provider is compatible with OpenSSL versions 3.0.x

OpenSSL provider is tested on i.MX (imx8mqevk, with yocto), Raspberry Pi (Raspberry Pi 4 Model B, Ubuntu 22.04.2 LTS)


## Getting Started on Raspberry Pi

### Prerequisite

- Raspberry pi with Ubuntu 22.04.2 LTS installed
- cmake installed - sudo apt-get install cmake
- OpenSSL 3.0.x installed
- SE05x secure element connected to Raspberry Pi on i2c-0 port

<p align=left>
<img src="scripts/tmp/se05x-rpi.jpg" alt="drawing" width="500"/>
</p>

Enable pin configuration for SE05X - connect GPIO22 (P1_15) to ENA pin of SE05X as indicated in the image above.


### Build
Run the commands below to build OpenSSL provider for SE05x secure element

```console
git clone --recurse-submodules git@github.com:NXPPlugNTrust/se05x-openssl-provider.git
cd se05x-openssl-provider
mkdir build
cd build
cmake ../
cmake -DPTMW_HostCrypto=OPENSSL .
cmake --build .
cmake --install .
```

Above commands will build the OpenSSL provider and copy in ``se05x-openssl-provider/bin`` folder

Refer ``CMAKE Options section`` in ``simw_lib\README.rst`` to build OpenSSL provider with different session authentication.


## Testing OpenSSL Provider

### Random Number Generation

```console
openssl rand --provider /usr/local/lib/libsssProvider.so -hex 32

```

### ECC (Nist256) Key Generation

```console
openssl ecparam --provider /usr/local/lib/libsssProvider.so --provider default -name prime256v1:0xEF000000 -genkey -out se05x_prime256v1_ref.pem

```

``NOTE: If the key id is not appended to the curve name key will be created at location 0xEF000001 by overwriting (delete key and create new key) it.``

The above command will generate the key in secure element and the output ``(se05x_prime256v1_ref.pem)`` is the reference to the key location of secure element. Refer [Reference key](#reference-keys) section for more details.

The reference key can also be used to perform further crypto operation with secure element.

Supported curves
  - prime192v1 (secp192r1)
  - secp224r1
  - prime256v1 (secp256r1)
  - secp384r1
  - secp521r1
  - secp160k1
  - secp192k1
  - secp224k1
  - secp256k1
  - brainpoolP160r1
  - brainpoolP192r1
  - brainpoolP224r1
  - brainpoolP256r1
  - brainpoolP320r1
  - brainpoolP384r1


### ECDSA - Sign Operation

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0xEF000000 -sign -rawin -in input.txt -out signature.txt -digest sha256

```


### ECDSA - Verify Operation

```console
openssl pkeyutl -verify --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0xEF000000 -verify -rawin -in input.txt -sigfile signature.txt -digest sha256

```

### ECDH Operation

```console
openssl ecparam -name prime256v1 -genkey -out peer_key.pem

openssl ec -in peer_key.pem -pubout -out peer_public_key.pem

openssl pkeyutl -derive --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0xEF000000 -peerkey peer_public_key.pem -hexdump -out ecdh_key.bin

```


### ECC Certificate Sign Request (CSR) / Certificate Generation

```console
openssl req -new --provider /usr/local/lib/libsssProvider.so --provider default -key nxp:0xEF000000 -out out.csr -subj "/C=AA/ST=BBB/L=CCC/O=NXP/OU=NXP/CN=example.com"

openssl x509 -req -in out.csr -CAcreateserial -out out.crt -days 5000 -CA rootca.cer -CAkey rootca_key.pem

```


### RSA (2048) Key Generation

```console
openssl genrsa --provider /usr/local/lib/libsssProvider.so --provider default -out se05x_rsa2048_ref.pem 2048

```

The above command will generate the key in secure element at location 0xEF000011 and the output ``(se05x_rsa2048_ref.pem)`` is the reference to the key location of secure element. Refer [Reference key](#reference-keys) section for more details.

``NOTE: Key id cannot be passed via command line. Every time the generate key command will overwrite the RSA key created at location 0xEF000011``

Supported RSA bits - 1024, 2048, 3072, 4096


### RSA - Sign Operation

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -inkey se05x_rsa2048_ref.pem -sign -rawin -in input.txt -out signature.txt -digest sha256

```


### RSA - Verify Operation

```console
openssl pkeyutl -verify --provider /usr/local/lib/libsssProvider.so --provider default -inkey se05x_rsa2048_ref.pem -verify -rawin -in input.txt -sigfile signature.txt -digest sha256

```


## Reference Keys

The cryptographic functionality offered by the OpenSSL provider requires a reference to a key stored inside the secure element (exception is random generation).

OpenSSL requires a key pair, consisting of a private and a public key, to be loaded before the cryptographic operations can be executed. This creates a challenge when OpenSSL is used in combination with a secure element as the private key cannot be extracted out from the secure element.

The solution is to populate the OpenSSL Key data structure with only a reference to the private key inside the secure element instead of the actual private key. The public key as read from the secure element can still be inserted into the key structure.

OpenSSL crypto APIs are then invoked with these data structure objects as parameters. When the crypto API is routed to the provider, the Se05x OpenSSL provider implementation decodes these key references and invokes the secure element APIs with correct key references for a cryptographic operation. If the input key is not a reference key, execution will roll back to OpenSSL software implementation.


### EC Reference Key Format

The following provides an example of an EC reference key. The value reserved
for the private key has been used to contain:

-  a pattern of ``0x10..00`` to fill up the datastructure MSB side to the
   desired key length
-  a 32 bit key identifier (in the example below ``0x7DCCBBAA``)
-  a 64 bit magic number (always ``0xA5A6B5B6A5A6B5B6``)
-  a byte to describe the key class (``0x10`` for Key pair and ``0x20`` for
   Public key)
-  a byte to describe the key index (use a reserved value ``0x00``)

```console
Private-Key: (256 bit)
priv:
   10:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
   00:00:00:7D:CC:BB:AA:A5:A6:B5:B6:A5:A6:B5:B6:
   kk:ii
pub:
   04:1C:93:08:8B:26:27:BA:EA:03:D1:BE:DB:1B:DF:
   8E:CC:87:EF:95:D2:9D:FC:FC:3A:82:6F:C6:E1:70:
   A0:50:D4:B7:1F:F2:A3:EC:F8:92:17:41:60:48:74:
   F2:DB:3D:B4:BC:2B:F8:FA:E8:54:72:F6:72:74:8C:
   9E:5F:D3:D6:D4
ASN1 OID: prime256v1
```

---
- The key identifier ``0x7DCCBBAA`` (stored in big-endian convention) is in
  front of the magic number ``0xA5A6B5B6A5A6B5B6``
- The padding of the private key value and the magic number make it
  unlikely a normal private key value matches a reference key.
- Ensure the value reserved for public key and ASN1 OID contain the values
  matching the stored key.
---

### RSA Reference Key Format

The following provides an example of an RSA reference key.

-  The value reserved for 'p' (aka 'prime1') is used as a magic number and is
   set to '1'
-  The value reserved for 'q' (aka 'prime2') is used to store the 32 bit key
   identifier (in the example below 0x6DCCBB11)
-  The value reserved for '(inverse of q) mod p' (aka 'IQMP' or 'coefficient')
   is used to store the magic number 0xA5A6B5B6

```console
 Private-Key: (2048 bit)
 modulus:
     00:b5:48:67:f8:84:ca:51:ac:a0:fb:d8:e0:c9:a7:
     72:2a:bc:cb:bc:93:3a:18:6a:0f:a1:ae:d4:73:e6:
     ...
 publicExponent: 65537 (0x10001)
 privateExponent:
     58:7a:24:39:90:f4:13:ff:bf:2c:00:11:eb:f5:38:
     b1:77:dd:3a:54:3c:f0:d5:27:35:0b:ab:8d:94:93:
     ...
 prime1: 1 (0x1)
 prime2: 1842133777(0x6DCCBB11)
 exponent1:
     00:c1:c9:0a:cc:9f:1a:c5:1c:53:e6:c1:3f:ab:09:
     db:fb:20:04:38:2a:26:d5:71:33:cd:17:a0:94:bd:
     ...
 exponent2:
     24:95:f0:0b:b0:78:a9:d9:f6:5c:4c:e0:67:d8:89:
     c1:eb:df:43:54:74:a0:1c:43:e3:6f:d5:97:88:55:
     ...
 coefficient: 2779166134 (0xA5A6B5B6)
 ```

---
- Ensure keylength, the value reserved for (private key) modulus and
  public exponent match the stored key.
- The mathematical relation between the different key components is not
  preserved.
- Setting prime1 to '1' makes it impossible that a normal private key
  matches a reference key.
---


## Example Scripts for OpenSSL Provider

The directory ``<root>/scripts`` contains a set of python scripts.
These scripts use the SE05x OpenSSL provider in the context of standard
OpenSSL utilities. They illustrate using the OpenSSL provider for fetching
random data, EC or RSA crypto operations.
The scripts assume the secure element is connected via I2C to the host.

```console
# Random number generation
python openssl_rnd.py

# ECC Key generation
python openssl_EccGenKey.py

# ECDSA Operations
python openssl_EccSign.py

# ECC CSR and certificate creation
python openssl_EccCSR.py

# ECDH Key generation
python openssl_Ecdh.py

# RSA Key generation
python openssl_RsaGenKey.py

# RSA Sign and Verify
python openssl_RSA.py

```