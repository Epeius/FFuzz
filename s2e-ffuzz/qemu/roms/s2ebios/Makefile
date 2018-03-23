all: build-all

-include ../../config-host.mak
-include $(SRC_PATH)/rules.mak

S2EBIOS=$(SRC_PATH)/roms/s2ebios
VPATH=$(S2EBIOS)
INCLUDES=$(SRC_PATH)/../guest/include

BIOS_CFLAGS := -std=c99 -O0 -g -ffreestanding  -nostdlib -fno-omit-frame-pointer -mno-red-zone -I$(INCLUDES) -I../../ -I$(S2EBIOS)
BIOS_CFLAGS += -fno-exceptions -fno-asynchronous-unwind-tables
BIOS_CFLAGS32 := $(BIOS_CFLAGS) -m32
BIOS_CFLAGS64 := $(BIOS_CFLAGS) -m64

S2E_BIOS_SOURCE=s2e-inst.asm s2e-bios-low-asm.asm s2e-bios-up.asm s2e-test.asm init.asm
S2E_BIOS_C_SOURCE=s2e-bios-low.c main.c test_symbhw.c pci.c test_range.c test_selfmod.c string.c

S2E_BIOS_SOURCE64=s2e-bios-64.asm

-include $(S2E_PLUGIN_DIR)/Makefile.bios

S2E_BIOS_C_OBJ=$(S2E_BIOS_C_SOURCE:.c=.o)
S2E_BIOS_C_OBJ64=$(S2E_BIOS_C_SOURCE:.c=-64.o)

.PHONY : all clean build-all

build-all: s2e-bios.bin s2e-bios-64.bin

%.o: %.c
	$(call quiet-command,$(CC) $(BIOS_CFLAGS32) -c -o $@ $^,"  Building $(TARGET_DIR)$@")

%-64.o: %.c
	$(call quiet-command,$(CC) $(BIOS_CFLAGS64) -c -o $@ $^,"  Building $(TARGET_DIR)$@")

#################
s2e-bios-up.bin : $(S2E_BIOS_SOURCE)
	$(call quiet-command,$(ASM) -O1 -i$(S2EBIOS)/ -f bin -o $@ $(S2EBIOS)/s2e-bios-up.asm,"  Building $(TARGET_DIR)$@")

s2e-bios-low-c: $(S2E_BIOS_C_OBJ)
	$(LD) -T $(S2EBIOS)/bios.ld  -o $@ $^

s2e-bios-low-c.bin: s2e-bios-low-c
	objcopy -O binary --rename-section .data=.rodata,alloc,load,data,contents,readonly $^ $@


s2e-bios.bin: s2e-bios-up.bin s2e-bios-low-c.bin
	dd if=s2e-bios-low-c.bin of=$@ bs=65536 count=1
	dd if=s2e-bios-up.bin of=$@ bs=65536 count=1 seek=1

#################
s2e-bios-up-64.bin: $(S2E_BIOS_SOURCE64)
	$(call quiet-command,$(ASM) -O1 -i$(S2EBIOS)/ -f bin -o $@ $(S2EBIOS)/s2e-bios-64.asm,"  Building $(TARGET_DIR)$@")

s2e-bios-low-c-64: $(S2E_BIOS_C_OBJ64)
	$(LD) -T $(S2EBIOS)/bios64.ld  -o $@ $^

s2e-bios-low-c-64.bin: s2e-bios-low-c-64
	objcopy -O binary --rename-section .data=.rodata,alloc,load,data,contents,readonly $^ $@

s2e-bios-64.bin: s2e-bios-up-64.bin s2e-bios-low-c-64.bin
	dd if=s2e-bios-low-c-64.bin of=$@ bs=65536 count=1
	dd if=s2e-bios-up-64.bin of=$@ bs=65536 count=1 seek=1

clean:
	rm -f *.o *.d *.raw *.img *.bin *~
