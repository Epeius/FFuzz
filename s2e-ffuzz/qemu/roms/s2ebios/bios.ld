OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH("i386:i386")
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
