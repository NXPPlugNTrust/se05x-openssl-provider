#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    for key_type in SUPPORTED_RSA_KEY_TYPES:

        log.info("##############################################################")
        log.info("#  Testing RSA key genration - %s ###", key_type)
        log.info("##############################################################")

        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

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

        key_type_bits_keyid = key_type_bits+":0xEF000012"

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        ref_rsa_key_0xEF000011 = output_keys_dir + os.sep + "rsa_ref_key_0xEF000011.pem"
        ref_rsa_key_0xEF000012 = output_keys_dir + os.sep + "rsa_ref_key_0xEF000012.pem"

        log.info("\n########### Generate RSA Keys Using Openssl Provider at default location ###############")
        run("%s genrsa --provider %s --provider default -out %s %s" %(openssl_bin, provider, ref_rsa_key_0xEF000011, key_type_bits))

        #log.info("\n########### Generate RSA Keys Using Openssl Provider at 0xEF000012 location ###############")
        #run("%s genrsa --provider %s --provider default -out %s %s" %(openssl_bin, provider, ref_rsa_key_0xEF000012, key_type_bits_keyid))

        log.info("\n\n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()

