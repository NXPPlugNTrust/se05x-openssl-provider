#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    for key_type in SUPPORTED_RSA_KEY_TYPES:
        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        if key_type == "rsa1024":
            key_type_bits = "1024"
        elif key_type == "rsa2048":
            key_type_bits = "2048"
        elif key_type == "rsa3072":
            key_type_bits = "3072"
        elif key_type == "rsa4096":
            key_type_bits = "4096"
        else:
            key_type_bits = "0"

        keyid_label = "nxp:0xEF000011"
        ref_rsa_key_default = output_keys_dir + os.sep + "rsa_ref_key_default.pem"
        TO_ENCRYPT_0 = cur_dir + os.sep + "input_data" + os.sep + "input_data_32_bytes.txt"
        ENCRYPT_0 = output_keys_dir + os.sep + "RSA_ENCRYPT_0.bin"
        DECRYPT_0 = output_keys_dir + os.sep + "RSA_DECRYPT_0.bin"
        ENCRYPT_1 = output_keys_dir + os.sep + "RSA_ENCRYPT_1.bin"
        DECRYPT_1 = output_keys_dir + os.sep + "RSA_DECRYPT_1.bin"
        ENCRYPT_2 = output_keys_dir + os.sep + "RSA_ENCRYPT_2.bin"
        DECRYPT_2 = output_keys_dir + os.sep + "RSA_DECRYPT_2.bin"

        log.info("\n########### Generate RSA Keys Using Openssl Provider at default location ###############")
        run("%s genrsa --provider %s --provider default -out %s %s" %(openssl_bin, provider, ref_rsa_key_default, key_type_bits))

        log.info("\n########### Encrypt data using Provider (Using key labels)  ###############")
        run("%s pkeyutl --provider %s --provider default -encrypt -inkey nxp:0xEF000011 -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,TO_ENCRYPT_0,ENCRYPT_0))

        log.info("\n########### Decrypt Data using Provider (Using key labels) ###############")
        run("%s pkeyutl --provider %s --provider default -decrypt -inkey nxp:0xEF000011 -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,ENCRYPT_0,DECRYPT_0))

        log.info("\n########### Encrypt data using Provider (Using key labels)  ###############")
        run("%s pkeyutl --provider %s --provider default -encrypt -inkey nxp:0xEF000011 -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, provider,TO_ENCRYPT_0,ENCRYPT_1))

        log.info("\n########### Decrypt Data using Provider (Using key labels) ###############")
        run("%s pkeyutl --provider %s --provider default -decrypt -inkey nxp:0xEF000011 -in %s -out %s -pkeyopt rsa_padding_mode:pkcs1" %(openssl_bin, provider,ENCRYPT_1,DECRYPT_1))

        log.info("\n########### Encrypt data using Provider (Using reference keys)  ###############")
        run("%s pkeyutl --provider %s --provider default -encrypt -inkey nxp:%s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,ref_rsa_key_default,TO_ENCRYPT_0,ENCRYPT_2))

        log.info("\n########### Decrypt Data using Provider (Using reference keys) ###############")
        run("%s pkeyutl --provider %s --provider default -decrypt -inkey nxp:%s -in %s -out %s -pkeyopt rsa_padding_mode:oaep" %(openssl_bin, provider,ref_rsa_key_default,ENCRYPT_2,DECRYPT_2))

        log.info("##############################################################")
        log.info("#                                                            #")
        log.info("#     Program completed successfully                         #")
        log.info("#                                                            #")
        log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()

