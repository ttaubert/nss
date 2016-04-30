#!/bin/sh

STATUS=0
for i in $(find $1 -type f -name '*.[ch]' -print); do
  if ! clang-format-3.8 $i | diff $i - > tmpDiff; then
    echo "Sorry, $i is not formatted properly. Please use clang-format 3.8 on your patch before landing."
    cat tmpDiff
    STATUS=1
  fi
done
exit $STATUS
