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
        log.info("#  Testing ECDH - %s ###", key_type)
        log.info("##############################################################")

        key_type_keyid = key_type+":0xEF000003"
        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type
        ref_ec_key_0xEF000003 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000003.pem"
        peer_keyPair = output_keys_dir + os.sep + "peer_keyPair.pem"
        peer_pubKey = output_keys_dir + os.sep + "peer_pubKey.pem"
        ecdh_out = output_keys_dir + os.sep + "ecdh_out.bin"

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        log.info("\n########### Generate EC Keys Using Openssl Provider at default location ###############")
        run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type_keyid, ref_ec_key_0xEF000003))

        log.info("\n########### Create Peer key and extract public key ###############")
        run("%s ecparam -name %s -genkey -out %s" %(openssl_bin, key_type, peer_keyPair))
        run("%s ec -in %s -pubout -out %s" %(openssl_bin, peer_keyPair, peer_pubKey))


        log.info("############## Do ECDH with provider (using key labels) ##########")
        run("%s pkeyutl -derive --provider %s --provider default -inkey nxp:0xEF000003 -peerkey %s -hexdump -out %s" %(openssl_bin, provider, peer_pubKey, ecdh_out))

        log.info("############## Do ECDH with provider (using reference keys) ##########")
        run("%s pkeyutl -derive --provider %s --provider default -inkey %s -peerkey %s -hexdump -out %s" %(openssl_bin, provider, ref_ec_key_0xEF000003, peer_pubKey, ecdh_out))

        log.info("\n\n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
