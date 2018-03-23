Building and Running libs2e
===========================

1. Build S2E as usual 
   
   make -f ../s2e/Makefile all-release all-debug

2. Build libs2e

   make -f ../s2e/Makefile stamps/libs2e-release-make stamps/libs2e-debug-make

3. Run libs2e in non-S2E mode

   LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6:${S2E_BUILD}/libs2e-release/x86_64-softmmu/libs2e.so \
       ${S2E_BUILD}/qemu-release/x86_64-softmmu/qemu-system-x86_64 -drive file=windows7.raw.s2e,cache=writeback,format=s2e -m 2G -enable-kvm

4. Run libs2e in S2E mode

   export S2E_CONFIG=s2e-config.lua
   export S2E_SHARED_DIR=${S2E_BUILD}/libs2e-release/x86_64-s2e-softmmu/

   LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6:${S2E_BUILD}/libs2e-release/x86_64-s2e-softmmu/libs2e.so \
       ${S2E_BUILD}/qemu-release/x86_64-softmmu/qemu-system-x86_64 -drive file=windows7.raw.s2e,cache=writeback,format=s2e -m 2G -enable-kvm
   
