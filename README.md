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
  - RSA key generation
  - RSA sign/verify
  - RSA encrypt/decrypt
  - CSR
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


```console
NOTE: It is recommended to use access manager to establish PlatformSCP03 session to secure element.

To establish platformSCP03 from sss provider, we have to load the default provider (required for crypto operations of SCP03) during sss provider initialisation code.
Uncomment the below code in `sssProvider_main.c`.

    //Load default provider to use random generation during SCP03 connection
    //if (NULL == OSSL_PROVIDER_load(NULL, "default")) {
    //    sssProv_Print(LOG_FLOW_ON, "error in OSSL_PROVIDER_load \n");
    //}

With this change, random number generation will not be offloaded to secure element.

```


## Testing OpenSSL Provider

### Random Number Generation

```console
openssl rand --provider /usr/local/lib/libsssProvider.so -hex 32

```

### ECC (Nist256) Key Generation

```console
openssl ecparam --provider /usr/local/lib/libsssProvider.so --provider default -name prime256v1:0xEF000000 -genkey -out se05x_prime256v1_ref.pem

```

The above command will generate the key in secure element and the output ``(se05x_prime256v1_ref.pem)`` is the reference to the key location of secure element. Refer [Referencing keys in the secure element](#Referencing-keys-in-the-secure-element) section for more details.

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

Note: Key generation on secure element using nxp provider can be done only by loading nxp provider with highest priority.

### ECDSA - Sign Operation

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0xEF000000 -sign -rawin -in input.txt -out signature.txt -digest sha256

```

In case the default provider is loaded first, ensure to pass the correct property query. Example -

```console
openssl pkeyutl --provider default --provider /usr/local/lib/libsssProvider.so -inkey nxp:0xEF000000 -sign -rawin -in input.txt -out signature.txt -digest sha256 -propquery "?nxp_prov.signature.ecdsa=yes"

```

Refer - 'OSSL Algorithms property definitions' section for more details.


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

The above command will generate the key in secure element at location 0xEF000011 and the output ``(se05x_rsa2048_ref.pem)`` is the reference to the key location of secure element. Refer [Referencing keys in the secure element](#Referencing-keys-in-the-secure-element) section for more details.

``NOTE:
1. Key id can be passed from application using 'OSSL_PKEY_PARAM_RSA_FACTOR2' parameter as uint32.
2. Key id cannot be passed via command line. Every time the genrsa command will overwrite the RSA key created at location 0xEF000011. (the key id can be changed in file sssProvider_key_mgmt_rsa.c (SSS_DEFAULT_RSA_KEY_ID))``

Supported RSA bits - 1024, 2048, 3072, 4096


### RSA - Sign Operation

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -inkey se05x_rsa2048_ref.pem -sign -rawin -in input.txt -out signature.txt -digest sha256

```


### RSA - Verify Operation

```console
openssl pkeyutl -verify --provider /usr/local/lib/libsssProvider.so --provider default -inkey se05x_rsa2048_ref.pem -verify -rawin -in input.txt -sigfile signature.txt -digest sha256

```

### RSA - Encrypt Operation

Supported RSA Padding Modes - oaep, pkcs1

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -encrypt -inkey se05x_rsa2048_ref.pem -in input.txt -out encrypt.txt -pkeyopt rsa_padding_mode:oaep

```

### RSA - Decrypt Operation

Supported RSA Padding Modes - oaep, pkcs1

```console
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -decrypt -inkey se05x_rsa2048_ref.pem -in encrypt.txt -out decrypt.txt -pkeyopt rsa_padding_mode:oaep

```

### RSA Certificate Sign Request (CSR) / Certificate Generation

```console
openssl req -new --provider /usr/local/lib/libsssProvider.so --provider default -key se05x_rsa2048_ref.pem -subj "/C=AA/ST=BBB/L=CCC/O=NXP/OU=NXP/CN=example.com" -out out.csr
openssl x509 -req --provider /usr/local/lib/libsssProvider.so --provider default -in out.csr -CAcreateserial -out out.cer -days 5000 -CA rootca.cer -CAkey rootca_key.pem

```


## Referencing keys in the secure element

The keys created inside secure element can be referenced in 3 different ways

1. Reference Keys in file format
2. Labels with reference key. Example - nxp:"path to reference key file"
3. Labels with key id. Example - nxp:0x12345678

### 1. Reference Keys in file format

The cryptographic functionality offered by the OpenSSL provider requires a reference to a key stored inside the secure element (exception is random generation).

OpenSSL requires a key pair, consisting of a private and a public key, to be loaded before the cryptographic operations can be executed. This creates a challenge when OpenSSL is used in combination with a secure element as the private key cannot be extracted out from the secure element.

The solution is to populate the OpenSSL Key data structure with only a reference to the private key inside the secure element instead of the actual private key. The public key as read from the secure element can still be inserted into the key structure.

OpenSSL crypto APIs are then invoked with these data structure objects as parameters. When the crypto API is routed to the provider, the Se05x OpenSSL provider implementation decodes these key references and invokes the secure element APIs with correct key references for a cryptographic operation. If the input key is not a reference key, execution will roll back to OpenSSL software implementation.

``NOTE: When using this method, the sss provider has to be loaded first. This will ensure that the sss provider can decode the key id information present in the reference key.``


#### EC Reference Key Format

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

#### RSA Reference Key Format

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
- Ensure key length, the value reserved for (private key) modulus and
  public exponent match the stored key.
- The mathematical relation between the different key components is not
  preserved.
- Setting prime1 to '1' makes it impossible that a normal private key
  matches a reference key.
---

### 2. Labels with reference key.

In this method, the reference key file (described in previous section) with full path can be passed in string format with "nxp:" as prefix.
Example - nxp:"path to reference key file".

``NOTE: When using this approach, there is no need to load the sss provider first. Default provider can have the higher priority.``


### 3. Labels with key id.

In this method, the 4 byte key id of the Key created / stored in secure element is passed as is in string format with "nxp:" as prefix.
Example - nxp:0x12345678

``NOTE: When using this approach, there is no need to load the sss provider first. Default provider can have the higher priority.``


## OSSL Algorithms property definitions

Following properties definitions are added in nxp provider,

  - Random number generation - `nxp_prov.rand=yes`

  - Key management - `nxp_prov.keymgmt=yes` (Required to offload the ECC / RSA keys operations to nxp provider when the keys are stored in SE05x Secure element).
    - For ECC - `nxp_prov.keymgmt.ec=yes`
    - For RSA - `nxp_prov.keymgmt.rsa=yes`

  - Signature - `nxp_prov.signature=yes`  (Required to offload the ECC / RSA Sign / Verify operations to nxp provider when the keys are stored in SE05x Secure element).
    - For ECDSA - `nxp_prov.signature.ecdsa=yes`
    - For RSA - `nxp_prov.signature.rsa=yes`

  - Asymmetric Cipher - `nxp_prov.asym_cipher=yes`  (Required to offload the RSA Encrypt / Decrypt to nxp provider when the keys are stored in SE05x Secure element).

  - ECDH - `nxp_prov.keyexch=yes` (Required only when the ephemeral keys are generated on SE05x).

  - Key Store - `nxp_prov.store=yes`  (Required when the keys are referenced using label (nxp:) or reference keys).
    - For keys passed with nxp: prefix - `nxp_prov.store.nxp=yes`
    - For keys passed with reference key format - `nxp_prov.store.file=yes`


IMPORTANT: 'fips=yes' algorithm property is added for all algorithms supported in nxp provider.
This is to support the FIPS certified SE05X secure element family.



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

# RSA Encrypt and Decrypt
python openssl_RsaEnc.py

# RSA CSR and certificate creation
python openssl_RsaCSR.py

```


## TLS Client example using provider

This section explains how to set-up a TLS link using the SE05x OpenSSL Provider on the client side.
The TLS demo demonstrates setting up a mutually authenticated and encrypted link between a client and a server system.

The keypair used to identify the client is created / stored in the Secure Element.

The keypair used to identify the server is simply available as a pem file.

The public keys associated with the respective key pairs are contained in respectively a client and a server certificate.

The CA is a self-signed certificate. The same CA is used to sign client and server certificate.

### TLS1.2 / TLS1.3 client example using EC keys

Create client and server credentials as shown below

```console
openssl ecparam -name prime256v1 -out prime256v1.pem


# Create Root CA key pair and certificate
openssl ecparam -in prime256v1.pem -genkey -noout -out tls_rootca_key.pem
openssl req -x509 -new -nodes -key tls_rootca_key.pem -subj /OU="NXP Plug Trust CA/CN=NXP RootCAvRxxx" -days 4380 -out tls_rootca.cer


# Create client key inside secure element
openssl ecparam --provider /usr/local/lib/libsssProvider.so --provider default -name prime256v1:0xEF000002 -genkey -out tls_client_key_ref_0xEF000002.pem


# Create Client key CSR. Use the provider to access the client key created in the previous file.
openssl req --provider /usr/local/lib/libsssProvider.so --provider default -new -key tls_client_key_ref_0xEF000002.pem -subj "/CN=NXP_SE050_TLS_CLIENT_ECC" -out tls_client.csr


# Create Client certificate
openssl x509 -req -sha256 -days 4380 -in tls_client.csr -CAcreateserial -CA tls_rootca.cer -CAkey tls_rootca_key.pem -out tls_client.cer


# Create Server key pair and certificate
openssl ecparam -in prime256v1.pem -genkey -noout -out tls_server_key.pem
openssl req -new -key tls_server_key.pem -subj "/CN=NXP_SE050_TLS_SERVER_ECC" -out tls_server.csr
openssl x509 -req -sha256 -days 4380 -in tls_server.csr -CAcreateserial -CA tls_rootca.cer -CAkey tls_rootca_key.pem -out tls_server.cer

```

Run Server as

```console
openssl s_server -accept 8080 -no_ssl3 -named_curve prime256v1  -CAfile tls_rootca.cer  -cert tls_server.cer -key tls_server_key.pem -cipher ECDHE-ECDSA-AES128-SHA256 -Verify 2 -state -msg
```

Run Client as

```console
openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_2 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0xEF000002.pem -cipher ECDHE-ECDSA-AES128-SHA256 -state -msg

OR

openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_3 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0xEF000002.pem -state -msg
```

### TLS1.2 / TLS1.3 client example using RSA keys

Create client and server credentials as shown below

```console
# Create Root CA key pair and certificate
openssl genrsa -out tls_rootca_key.pem 2048
openssl req -x509 -new -nodes -key tls_rootca_key.pem -subj "/OU=NXP Plug Trust CA/CN=NXP RootCAvExxx" -days 4380 -out tls_rootca.cer


# Create client key inside secure element
openssl genrsa --provider /usr/local/lib/libsssProvider.so --provider default -out tls_client_key_ref_0xEF000011.pem 2048

# Create Client key CSR. Use the provider to access the client key created in the previous file.
openssl req -new --provider /usr/local/lib/libsssProvider.so --provider default -key tls_client_key_ref_0xEF000011.pem -subj "/CN=NXP_SE050_TLS_CLIENT_RSA" -out tls_client.csr

# Create Client certificate
openssl x509 -req --provider default -in tls_client.csr -CAcreateserial -out tls_client.cer -days 5000 -CA tls_rootca.cer -CAkey tls_rootca_key.pem


# Create Server key pair and certificate
openssl genrsa -out tls_server_key.pem 2048
openssl req -new -key tls_server_key.pem -subj "/CN=NXP_SE050_TLS_SERVER_RSA" -out tls_server.csr
openssl x509 -req -sha256 -days 4380 -in tls_server.csr -CAcreateserial -CA tls_rootca.cer -CAkey tls_rootca_key.pem -out tls_server.cer

```

Run Server as

```console
openssl s_server -accept 8080 -no_ssl3 -CAfile tls_rootca.cer -cert tls_server.cer -key tls_server_key.pem -Verify 2 -state -msg
```

Run Client as

```console
openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_2 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0xEF000011.pem -state -msg

OR

openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_3 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0xEF000011.pem -state -msg
```


## OpenSSL Configuration file

The provider can be loaded via OpenSSL configuration file also.
Changes required in configuration file to load provider is shown below,

```console
...

openssl_conf = openssl_init
config_diagnostics = 1

[openssl_init]
providers = provider_sect

[provider_sect]
nxp_prov = nxp_sect
default = default_sect

[nxp_sect]
identity = nxp_prov
module = <provider lib path>
activate = 1

[default_sect]
activate = 1

...
```

The order in which the providers are written in [provider_sect] section, defines the priority of the providers loaded.
The one included first, will have the higher priority.


``NOTE: It is not recommended to modify the default OpenSSL config file. Create a new config file to load custom providers and set the OPENSSL_CONF env variable to config file path. Example -
  export OPENSSSL_CONF=<CONFIG_FILE_PATH>
``
