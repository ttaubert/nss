cd /c/projects/nss; USE_64=1 make nss_build_all
cd /c/projects/nss/tests/; USE_64=1 NSS_TESTS="ssl_gtests pk11_gtests der_gtests util_gtests" NSS_CYCLES=standard ./all.sh
exit
