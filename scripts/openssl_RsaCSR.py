#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

def main():

    subject = "-subj \"/C=11/ST=111/L=111/O=NXP/OU=NXP/CN=example.com\""

    for key_type in SUPPORTED_RSA_KEY_TYPES:

        log.info("##############################################################")
        log.info("#  Testing rsa key genration - %s ###", key_type)
        log.info("##############################################################")

        output_dir = cur_dir + os.sep + "output"
        output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(output_keys_dir):
            os.mkdir(output_keys_dir)

        sha_types = ["sha1",  "sha224",  "sha256",  "sha384",  "sha512"]

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

        rootca_key = output_keys_dir + os.sep + "rootca_key.pem"
        rootca_cer = output_keys_dir + os.sep + "rootca.cer"

        output_csr = output_keys_dir + os.sep + "0xEF000011.csr"
        output_crt = output_keys_dir + os.sep + "0xEF000011.crt"
        ref_rsa_key_0xEF000011 = output_keys_dir + os.sep + "ref_rsa_key_0xEF000011.pem"

        log.info("\n########### Create CA root key and certificates using openssl ###############")
        run("%s genrsa -out %s %s" %(openssl_bin, rootca_key, key_type_bits))
        run("%s req -x509 -new -nodes -key %s -subj \"/OU=NXP Plug Trust CA/CN=NXP RootCAvExxx\" -days 4380 -out %s " %(openssl_bin, rootca_key, rootca_cer))

        log.info("\n########### Generate RSA Keys Using Openssl Provider at 0xEF000011 location ###############")
        run("%s genrsa --provider %s --provider default -out %s %s" %(openssl_bin, provider, ref_rsa_key_0xEF000011, key_type_bits))

        for sha_type in sha_types:
            log.info("\n########### Create CSR and Certificate for ket at location 0xEF000011 using openssl provider ###############")
            run("%s req -new --provider %s --provider default -key %s %s -out %s -%s" %(openssl_bin, provider, ref_rsa_key_0xEF000011, subject, output_csr, sha_type))
            run("%s x509 -req --provider %s --provider default -in %s -CAcreateserial -out %s -days 5000 -CA %s -CAkey %s -%s" %(openssl_bin, provider, output_csr, output_crt, rootca_cer, rootca_key, sha_type))
            run("%s x509 -in %s -text -noout" %(openssl_bin, output_crt))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()

