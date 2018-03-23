OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH("i386:x86-64")
ENTRY(_start)
SECTIONS
{
        . = 0xe0000;
        _start = .;
        .text : {
            _text_start = .;
            *(.text)
            _text_end = .;
        }

        .data :
        {
            _data_start = .;
            *(.rodata);
            *(.data);
            *(.bss);
            *(COMMON);
            _data_end = .;
        }
        _end = .;
}
