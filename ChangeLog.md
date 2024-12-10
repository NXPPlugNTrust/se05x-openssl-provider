# Changelog

## [1.1.1]

- Bug fix: Signature length calculation fixed in ECDSA functions.

## [1.1.0]

- CSR generation extended for all SHA algorithms now. (Get context functions - 'sss_rsa_signature_get_ctx_params' and 'sss_ecdsa_signature_get_ctx_params' updated to handle all SHA algorithms).

- TLS use case : Ephemeral key is generated on host by default. (Enable 'SSS_ENABLE_SE05X_EC_KEY_GEN_WITH_NO_KEYID' in sssProvider_key_mgmt_ec.c file to generate on secure element).

- Performance improvement : Provider is updated to store the client / server public key on host to avoid multiple secure element reads during TLS connection.

- Bug fix - Correct RSA encrypt algorithm is set in function sss_rsa_enc_set_ctx_params, when 'OSSL_ASYM_CIPHER_PARAM_PAD_MODE' parameter data is integer type.

- OSSL algorithms are updated with algorithm properties. Refer - 'OSSL Algorithms property definitions' section in readme.

- Enable / Disable random number generation in nxp provider using compile time option - 'SSS_PROV_DISABLE_SE05X_RNG'. (Disabled by default)

- Key id for RSA key generation can be passed to provider via 'OSSL_PKEY_PARAM_RSA_FACTOR2' parameter.

- ECC / RSA key management import functions added - to handle reference keys. If the input key is not reference key, the function returns error to roll back on other available providers.

- ECC key management - match and duplicate functions added.

- ECDSA digest verify support added (function - sss_ecdsa_signature_digest_verify).

- RSA digest verify support added (function - sss_rsa_signature_digest_verify).

- RSA generate Key feature will generate RSA-CRT type keys by default. (Use compile time define `SSS_PROV_GENERATE_RSA_PLAIN` to change the RSA key type to plain.)




## [1.0.3]

- ECC and RSA TLS use case extended for reference keys in file format also.


## [1.0.2]

- TLS support extended for RSA keys.

- RSA encrypt and decrypt feature added in provider.


## [1.0.1]

- EC key mgmt export function updated to send private key in utf8 string format


## [1.0.0] Openssl provider for se05x

- Features supported - Random number generation, ECC / RSA key generation, ECDSA sign/verify, RSA sign/verify, ECC CSR
