#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    for key_type in SUPPORTED_EC_KEY_TYPES:

        log.info("##############################################################")
        log.info("#  Testing ECC key genration - %s ###", key_type)
        log.info("##############################################################")

        key_type_keyid = key_type+":0xEF000002"
        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        ref_ec_key_0xEF000001 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000001.pem"
        ref_ec_key_0xEF000002 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000002.pem"

        log.info("\n########### Generate EC Keys Using Openssl Provider at default location ###############")
        run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type, ref_ec_key_0xEF000001))

        log.info("\n########### Generate EC Keys Using Openssl Provider at 0xEF000002 location ###############")
        run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type_keyid, ref_ec_key_0xEF000002))

        log.info("\n\n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
