#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    subject = "-subj \"/C=11/ST=111/L=111/O=NXP/OU=NXP/CN=example.com\""

    for key_type in SUPPORTED_EC_KEY_TYPES:

        log.info("##############################################################")
        log.info("#  Testing ECC key genration - %s ###", key_type)
        log.info("##############################################################")

        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        rootca_type = output_keys_dir + os.sep + key_type + ".pem"
        rootca_key = output_keys_dir + os.sep + "rootca_key.pem"
        rootca_cer = output_keys_dir + os.sep + "rootca.cer"

        output_csr = output_keys_dir + os.sep + "0xEF000003.csr"
        output_crt = output_keys_dir + os.sep + "0xEF000003.crt"
        ref_ec_key_0xEF000003 = output_keys_dir + os.sep + "ecc_ref_key_0xEF000002.pem"

        log.info("\n########### Create CA root key and certificates using openssl ###############")
        run("%s ecparam -name %s -out %s" %(openssl_bin, key_type, rootca_type))
        run("%s ecparam -in %s -genkey -noout -out %s" %(openssl_bin, rootca_type, rootca_key))
        run("%s req -x509 -new -nodes -key %s -subj \"/OU=NXP Plug Trust CA/CN=NXP RootCAvExxx\" -days 4380 -out %s " %(openssl_bin, rootca_key, rootca_cer))

        log.info("\n########### Generate EC Keys Using Openssl Provider at 0xEF000003 location ###############")
        run("%s ecparam --provider %s --provider default -name %s -genkey -out %s" %(openssl_bin, provider, key_type, ref_ec_key_0xEF000003))

        log.info("\n########### Create CSR and Certificate for ket at location 0xEF000003 using openssl provider ###############")
        run("%s req -new --provider %s --provider default -key %s -out %s %s" %(openssl_bin, provider, ref_ec_key_0xEF000003, output_csr, subject))
        run("%s x509 -req --provider %s --provider default -in %s -CAcreateserial -out %s -days 5000 -CA %s -CAkey %s" %(openssl_bin, provider, output_csr, output_crt, rootca_cer, rootca_key))
        run("%s x509 -in %s -text -noout" %(openssl_bin, output_crt))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
