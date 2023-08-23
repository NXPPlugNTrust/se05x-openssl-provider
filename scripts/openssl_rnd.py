#
# Copyright 2022 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generate few random numbers from the attached secure element.

"""

import argparse

from openssl_util import *

def main():

    run("%s rand --provider %s --provider default -hex 8" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 16" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 32" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 64" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 128" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 256" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 384 " % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 512" % (openssl_bin, provider))
    run("%s rand --provider %s --provider default -hex 748" % (openssl_bin, provider))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
