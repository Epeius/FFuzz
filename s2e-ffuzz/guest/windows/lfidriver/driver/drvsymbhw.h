#ifndef S2E_SYMBHW_H
#pragma warning(disable:4201)

#define S2E_SYMBHW_H

BOOLEAN SymbHwIsPciConfigInited(VOID);
BOOLEAN SymbHwPciDevPresent(VOID);
BOOLEAN SymbHwInitializePciConfig(PCI_COMMON_CONFIG *Config);
ULONG SymbHwAccessPciConfig(ULONG Offset, PVOID Buffer, ULONG Length, BOOLEAN IsWrite);
BOOLEAN SymbHwPointsToSymbolic(ULONG Offset, ULONG Size);

#endif