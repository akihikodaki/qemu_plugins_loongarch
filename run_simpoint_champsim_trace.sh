#!/bin/bash

set -e

output=$1
# cmd="~/coremark/coremark-aarch64-linux-gnu.exe 0 0 0 10000 > /dev/null"
cmd="${@:2}"
bb_interval=100000000

CMD_GETBBV="~/qemu/build/qemu-loongarch64 -D log.txt -d plugin -plugin ~/qemu_plugins/build/libbbv.so,outfile=${output}/out,interval=${bb_interval} -- $cmd"

echo ${CMD_GETBBV}
eval ${CMD_GETBBV}

CMD_GETSIMPOINT="/ht/320/btracer/SimPoint.3.2/bin/simpoint -maxK 5 -loadFVFile ${output}/out.0.bb -saveSimpoints ${output}/simpoints -saveSimpointWeights ${output}/weights >/dev/null"
echo ${CMD_GETSIMPOINT}
eval ${CMD_GETSIMPOINT}

CMD_GETTRACE="env TRACE_FILENAME=${output}/champsim.trace SIMPOINT_FILE=${output}/simpoints BB_INTERVAL=${bb_interval} ~/qemu/build/qemu-loongarch64 -D log.txt -d plugin -plugin ~/qemu_plugins/build/libchampsim_la_with_reg_simpoint.so -- ${cmd}"
echo ${CMD_GETTRACE}
eval ${CMD_GETTRACE}
