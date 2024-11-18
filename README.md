## Get champsim like traces for [Loongarch](https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html)

1. Download QEMU v9.2.0-rc0.
2. compile your QEMU with `mkdir build && cd build/ && ../configure --target-list=loongarch64-linux-user --disable-werror --enable-plugins && ninja`
3. `make -j CHAMPSIM_DIR=your_champsim_path QEMU_DIR=your_qemu_path`
4. run qemu-loongarch64 with plugins, example in run_simpoint_champsim_trace.sh









