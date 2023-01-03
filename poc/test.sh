#!/bin/bash

folder="$(dirname $0)/../"

test -z "$1" && echo "usage: $0 module_name [fixed]"

mod=$1
poc=${mod/_v[1-9]*}
poc=${poc/_fixed}
poc=${poc/rust_}
poc=poc_$poc

trap "trap - SIGINT; rmmod $mod; exit" SIGINT

insmod $folder/$mod.ko
$folder/poc/$poc
rmmod $mod
