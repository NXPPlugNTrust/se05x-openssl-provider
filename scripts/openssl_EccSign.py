#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    for key_type in SUPPORTED_EC_KEY_TYPES:
        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        sha_types = ["sha1",  "sha224",  "sha256",  "sha384",  "sha512"]
        sha_type = "sha256"

        keyid_label = "nxp:0xEF000003"
        key_type_keyid = key_type+":0xEF000003"
        ref_ec_key_0xEF000003 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000003.pem"
        input_data = cur_dir + os.sep + ".." + os.sep + "README.md"
        signature = output_keys_dir + os.sep + "signature.bin"


        log.info("\n########### Generate EC Keys Using Openssl Provider at 0xEF000003 location ###############")
        run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type_keyid, ref_ec_key_0xEF000003))

        log.info("\nSign using Provider (Using key labels) ")
        run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, keyid_label, input_data, signature, sha_type))
        log.info("###################################################")
        log.info("\nVerify signature using host  ")
        run("%s pkeyutl -verify -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, ref_ec_key_0xEF000003, signature, input_data, sha_type))
        log.info("#################################################### \n")

        log.info("\nSign using Provider (Using reference keys) ")
        run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest %s" % (openssl_bin, provider, ref_ec_key_0xEF000003, input_data, signature, sha_type))
        log.info("###################################################")
        log.info("\nVerify signature using host  ")
        run("%s pkeyutl -verify -inkey %s -sigfile %s -in %s -rawin -digest %s"%(openssl_bin, ref_ec_key_0xEF000003, signature, input_data, sha_type))
        log.info("#################################################### \n")


    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
