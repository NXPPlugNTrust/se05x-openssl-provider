#
# Copyright 2022 NXP
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

        sha_types = ["sha1",  "sha224",  "sha256",  "sha384",  "sha512"]
        sha_type = "sha256"

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
        ref_rsa_key_0xEF000011 = output_keys_dir + os.sep + "rsa_ref_key_0xEF000011.pem"
        input_data = cur_dir + os.sep + ".." + os.sep + "SCR.txt"
        signature = output_keys_dir + os.sep + "signature.bin"


        log.info("\n########### Generate RSA Keys Using Openssl Provider at 0xEF000011 location ###############")
        run("%s genrsa --provider %s --provider default -out %s %s" %(openssl_bin, provider, ref_rsa_key_0xEF000011, key_type_bits))

        log.info("\nSign using Provider (Using key labels) ")
        run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, keyid_label, input_data, signature, sha_type))
        log.info("###################################################")
        log.info("\nVerify signature using Provider  ")
        run("%s pkeyutl --provider %s --provider default -verify -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, provider, ref_rsa_key_0xEF000011, signature, input_data, sha_type))
        log.info("#################################################### \n")

        log.info("\nSign using Provider (Using reference keys) ")
        run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, ref_rsa_key_0xEF000011, input_data, signature, sha_type))
        log.info("###################################################")
        log.info("\nVerify signature using Provider  ")
        run("%s pkeyutl --provider %s --provider default -verify -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, provider, ref_rsa_key_0xEF000011, signature, input_data, sha_type))
        log.info("#################################################### \n")


    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
