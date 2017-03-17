#!/bin/sh

set -e

dir=$(dirname $0)
root=$(cd $dir/../..; pwd -P)
bin="$root/../dist/Debug/bin"

targets=( \
  certDN mpi-add mpi-addmod mpi-div mpi-expmod mpi-invmod mpi-mod mpi-mulmod \
  mpi-sqr mpi-sqrmod mpi-sub mpi-submod quickder tls-client tls-server \
  dtls-client dtls-server \
)

# Targets we're fuzzing in two different modes.
declare -A tls_targets=([tls-client]=1 [tls-server]=1 [dtls-client]=1 [dtls-server]=1)

get_max_len()
{
  grep max_len "$root/fuzz/options/$1.options" | cut -d "=" -f 2 | xargs
}

git_sparse_checkout()
{
  local tmp=$(mktemp -d)
  git clone -q -n --depth=1 $1 "$tmp"
  git -C "$tmp" checkout HEAD $2
  echo $tmp
}

merge_corpora()
{
  local mode_arg=""
  local fuzzing_mode=$1
  [ "$fuzzing_mode" = 1 ] && mode_arg="=tls"

  # Build NSS.
  $root/build.sh -c --fuzz${mode_arg} --disable-tests

  # Create a temp dir for ClusterFuzz corpora.
  local cfdir=$(mktemp -d)
  trap 'rm -fr $cfdir' exit

  # Iterate and merge all targets.
  for target in ${targets[@]}; do
    local binary="$bin/nssfuzz-$target"
    rm -fr $cfdir && mkdir $cfdir

    # When in fuzzing mode, ignore all non-TLS targets.
    if [ "$fuzzing_mode" = 1 ] && [ -z "${tls_targets[$target]:-}" ]; then
      continue
    fi

    # When NOT in fuzzing mode, append "no_fuzzer_mode" to TLS targets.
    if [ "$fuzzing_mode" = 0 ] && [ -n "${tls_targets[$target]:-}" ]; then
      target="${target}-no_fuzzer_mode"
    fi

    printf "\nSyncing OSS-Fuzz corpus for target '$target'\n"
    gsutil -mq rsync gs://nss-corpus.clusterfuzz-external.appspot.com/libFuzzer/nss_${target}/ $cfdir

    # Create the target directory for the merge.
    local corpus="$root/fuzz/corpus_new/$target"
    mkdir -p $corpus

    # Run the fuzzing target and minimise/merge all corpora.
    printf "Merging corpora for target '$target'\n\n"
    $binary -merge=1 -max_len=$(get_max_len $target)          \
      "$corpus"                                               \
      "$cfdir"                                                \
      "$nss/"*                                                \
      "$boringssl/fuzz/"*_corpus "$boringssl/fuzz/"*_corpus_* \
      "$openssl/fuzz/corpora/"*
  done
}

if [ "$(uname)" != "Linux" ]; then
  echo "Merging fuzzing corpora only works on Linux, sorry."
  exit
fi

echo "Cloning NSS fuzzing corpus ..."
nss=$(git_sparse_checkout https://github.com/mozilla/nss-fuzzing-corpus .)
trap 'rm -fr $nss' exit

echo "Cloning BoringSSL fuzzing corpus ..."
boringssl=$(git_sparse_checkout https://boringssl.googlesource.com/boringssl/ fuzz)
trap 'rm -fr $boringssl' exit

echo "Cloning OpenSSL fuzzing corpus ..."
openssl=$(git_sparse_checkout https://github.com/openssl/openssl/ fuzz/corpora)
trap 'rm -fr $openssl' exit

# Clear the target directory.
rm -fr "$root/fuzz/corpus_new"

# Merge in non-fuzzing mode.
merge_corpora 0
# Merge in fuzzing mode.
merge_corpora 1
