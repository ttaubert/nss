cd /c/projects/nss; USE_64=1 NSS_ENABLE_TLS_1_3=1 make nss_build_all
cd /c/projects/nss; BUILD_OPT=1 USE_64=1 NSS_ENABLE_TLS_1_3=1 make nss_build_all
cd /c/projects/nss/tests/; USE_64=1 HOST=localhost DOMSUF=localdomain NSS_ENABLE_TLS_1_3=1 NSS_TESTS="ssl_gtests pk11_gtests der_gtests util_gtests" NSS_CYCLES=standard ./all.sh
cd /c/projects/nss/tests/; BUILD_OPT=1 USE_64=1 HOST=localhost DOMSUF=localdomain NSS_ENABLE_TLS_1_3=1 NSS_TESTS="ssl_gtests pk11_gtests der_gtests util_gtests" NSS_CYCLES=standard ./all.sh
exit
