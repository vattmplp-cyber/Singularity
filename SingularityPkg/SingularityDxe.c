#include <Uefi.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>

#include <Protocol/LoadedImage.h>

#include <Guid/EventGroup.h>

#include "SingularityDxe.h"
#include "util.h"

#define SINGULARITY_TITLE1 "\r\n███████╗██╗███╗   ██╗ ██████╗ ██╗   ██╗██╗      █████╗ ██████╗ ██╗████████╗██╗   ██╗" \
                           "\r\n██╔════╝██║████╗  ██║██╔════╝ ██║   ██║██║     ██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝" \
                           "\r\n███████╗██║██╔██╗ ██║██║  ███╗██║   ██║██║     ███████║██████╔╝██║   ██║    ╚████╔╝" \
                           "\r\n╚════██║██║██║╚██╗██║██║   ██║██║   ██║██║     ██╔══██║██╔══██╗██║   ██║     ╚██╔╝" \
                           "\r\n███████║██║██║ ╚████║╚██████╔╝╚██████╔╝███████╗██║  ██║██║  ██║██║   ██║      ██║" \
                           "\r\n╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝"

#define SINGULARITY_TITLE2 "\r\n                                                                                 " \
                           "\r\n                                                                                 " \
                           "\r\n                     Made by GlitchedPanda (UEFI pure reader)                     \r\n\n"

// ============================================================
//  GUIDs
// ============================================================
EFI_GUID gSingularityDriverProtocolGuid = {
  0xdeadfade, 0x0601, 0x47C6, { 0x84, 0xE7, 0x2E, 0xBC, 0x93, 0x7D, 0x1B, 0x11 }
};

EFI_GUID gSingularityVersionProtocolGuid = {
  0xdeadfade, 0xDB2B, 0x42D2, { 0xBF, 0x5F, 0xBA, 0xF9, 0xC5, 0x51, 0x71, 0x54 }
};

EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL gSingularitySupportedEfiVersion = { 0x00020000 };
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *gTextInputEx = NULL;
DummyProtocolData gSingularityDriverProtocol = { 0 };

// ============================================================
//  Globals
// ============================================================
static EFI_SET_VARIABLE oSetVariable = NULL;
static EFI_GET_VARIABLE oGetVariable = NULL;

static EFI_EVENT NotifyEvent = NULL;
static EFI_EVENT ExitEvent   = NULL;
static volatile BOOLEAN Virtual = FALSE;
static volatile BOOLEAN Runtime = FALSE;

static UINTN DriverBuffer = 0;

#define VARIABLE_NAME L"Singularity42"
#define COMMAND_MAGIC 0xDEADFADE
#define DRIVER_SIZE   0x2000000

#define OP_INIT       1
#define OP_WRITE_TEST 2
#define OP_READ_TEST  3
#define OP_CLEAR_TEST 4
#define OP_FIND_PROC  0x10

#define WINDOWS_DIRECT_MAP_BASE 0xFFFF800000000000ULL
#define CR4_SMEP (1ULL << 20)
#define CR4_SMAP (1ULL << 21)

// ============================================================
//  EPROCESS layouts
// ============================================================
typedef struct {
    UINT32 PidOff;
    UINT32 DtbOff;
    UINT32 NameOff;
} EPROCESS_LAYOUT;

STATIC CONST EPROCESS_LAYOUT KnownLayouts[] = {
    { 0x440, 0x28, 0x5a8 },   // Win10 2004-22H2 (19041-19045)
    { 0x440, 0x28, 0x5a8 },   // Win10 20H2-21H2 (дубль)
    { 0x2e0, 0x28, 0x450 },   // Win10 1809 (17763)
    { 0x2e8, 0x28, 0x450 },   // Win10 1903/1909 (18362/18363)
    { 0x4b8, 0x28, 0x620 },   // Win11 22H2 (22621)
};
#define NUM_LAYOUTS (sizeof(KnownLayouts)/sizeof(KnownLayouts[0]))

typedef struct _MemoryCommand {
    int magic;
    int operation;
    unsigned long long data[10];
    int size;
} MemoryCommand;

static UINT64 CachedCr3 = 0;
static UINT32 CachedPid = 0;

// RAM ranges
#define MAX_RAM_RANGES 64
typedef struct { UINT64 Start; UINT64 End; } RAM_RANGE;
static RAM_RANGE RamRanges[MAX_RAM_RANGES];
static UINTN     RamRangeCount = 0;

// ============================================================
//  SMAP / SMEP (з правильною SaveAndDisableInterrupts)
// ============================================================
STATIC VOID SmepSmapOff(OUT UINTN *Saved, OUT BOOLEAN *IfSaved) {
    *IfSaved = SaveAndDisableInterrupts();
    *Saved   = AsmReadCr4();
    AsmWriteCr4(*Saved & ~(CR4_SMEP | CR4_SMAP));
}

STATIC VOID SmepSmapOn(IN UINTN Saved, IN BOOLEAN IfSaved) {
    AsmWriteCr4(Saved);
    if (IfSaved) EnableInterrupts();
}

// ============================================================
//  Physical memory + VA→PA
// ============================================================
STATIC UINT64 ReadPhysicalU64(IN UINT64 Pa) {
    return *(volatile UINT64 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Pa);
}

STATIC UINT64 VirtualToPhysical(IN UINT64 Cr3, IN UINT64 Va) {
    if (Cr3 == 0) return 0;

    UINT64 i4 = (Va >> 39) & 0x1FF;
    UINT64 i3 = (Va >> 30) & 0x1FF;
    UINT64 i2 = (Va >> 21) & 0x1FF;
    UINT64 i1 = (Va >> 12) & 0x1FF;
    UINT64 off = Va & 0xFFF;

    UINT64 e4 = ReadPhysicalU64(Cr3 + i4 * 8);
    if (!(e4 & 1)) return 0;

    UINT64 e3 = ReadPhysicalU64((e4 & 0x000FFFFFFFFFF000ULL) + i3 * 8);
    if (!(e3 & 1)) return 0;
    if (e3 & (1ULL << 7)) return (e3 & 0x000FFFFFC0000000ULL) + (Va & 0x3FFFFFFF);

    UINT64 e2 = ReadPhysicalU64((e3 & 0x000FFFFFFFFFF000ULL) + i2 * 8);
    if (!(e2 & 1)) return 0;
    if (e2 & (1ULL << 7)) return (e2 & 0x000FFFFFFFE00000ULL) + (Va & 0x1FFFFF);

    UINT64 e1 = ReadPhysicalU64((e2 & 0x000FFFFFFFFFF000ULL) + i1 * 8);
    if (!(e1 & 1)) return 0;

    return (e1 & 0x000FFFFFFFFFF000ULL) + off;
}

// ============================================================
//  Сканування EPROCESS
// ============================================================
STATIC UINT64 ScanForProcessCr3(IN UINT32 TargetPid) {
    if (RamRangeCount == 0) {
        SerialPrintSafe("SingularityDxe: no RAM ranges, abort\r\n");
        return 0;
    }

    SerialPrintSafe("SingularityDxe: scanning for PID %d across %d ranges...\r\n",
                    TargetPid, (UINT32)RamRangeCount);

    for (UINTN L = 0; L < NUM_LAYOUTS; L++) {
        UINT32 PidOff  = KnownLayouts[L].PidOff;
        UINT32 DtbOff  = KnownLayouts[L].DtbOff;
        UINT32 NameOff = KnownLayouts[L].NameOff;

        for (UINTN r = 0; r < RamRangeCount; r++) {
            UINT64 Start = RamRanges[r].Start;
            UINT64 End   = RamRanges[r].End;
            if (Start < 0x100000) Start = 0x100000;
            if (End > 0x400000000ULL) End = 0x400000000ULL;

            for (UINT64 Pa = Start; Pa + 8 < End; Pa += 16) {
                UINT64 V = *(volatile UINT64 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Pa);
                if ((UINT32)V != TargetPid) continue;
                if ((V >> 32) != 0) continue;

                if (Pa < PidOff) continue;
                UINT64 Ep = Pa - PidOff;
                if (Ep & 0xF) continue;

                UINT64 Dtb = *(volatile UINT64 *)(UINTN)
                    (WINDOWS_DIRECT_MAP_BASE + Ep + DtbOff);
                if (Dtb == 0 || (Dtb & 0xFFF) != 0) continue;
                if (Dtb > 0x10000000000ULL) continue;

                UINT8 c0 = *(volatile UINT8 *)(UINTN)
                    (WINDOWS_DIRECT_MAP_BASE + Ep + NameOff);
                if (c0 < 0x20 || c0 > 0x7E) continue;

                SerialPrintSafe("SingularityDxe: EPROCESS @ PA 0x%lx DTB=0x%lx name='%a' layout=%d\r\n",
                                Ep, Dtb,
                                (CHAR8 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Ep + NameOff),
                                (UINT32)L);
                return Dtb;
            }
        }
    }

    SerialPrintSafe("SingularityDxe: PID %d not found in any layout\r\n", TargetPid);
    return 0;
}

// ============================================================
//  RunCommand
// ============================================================
EFI_STATUS RunCommand(MemoryCommand *cmd) {
    if (cmd->magic != COMMAND_MAGIC) {
        SerialPrintSafe("SingularityDxe: bad magic 0x%x\r\n", cmd->magic);
        return EFI_ACCESS_DENIED;
    }

    SerialPrintSafe("SingularityDxe: op=0x%x size=%d d0=0x%lx d1=0x%lx\r\n",
                    cmd->operation, cmd->size, cmd->data[0], cmd->data[1]);

    // ---------- OP_FIND_PROC ----------
    if (cmd->operation == OP_FIND_PROC) {
        UINT32 Pid = (UINT32)cmd->data[0];
        if (Pid == 0) return EFI_INVALID_PARAMETER;

        UINTN Saved; BOOLEAN If;
        SmepSmapOff(&Saved, &If);
        UINT64 Cr3 = ScanForProcessCr3(Pid);
        SmepSmapOn(Saved, If);

        if (Cr3 == 0) return EFI_NOT_FOUND;
        CachedPid = Pid;
        CachedCr3 = Cr3;
        SerialPrintSafe("SingularityDxe: cached PID=%d CR3=0x%lx\r\n", Pid, Cr3);
        return EFI_SUCCESS;
    }

    // ---------- op=0: READ CS2 ----------
    if (cmd->operation == 0) {
        if (CachedCr3 == 0) {
            SerialPrintSafe("SingularityDxe: op0 no CR3 (call op=0x10 first)\r\n");
            return EFI_NOT_READY;
        }
        if (cmd->size <= 0 || cmd->size > 0x100000) {
            SerialPrintSafe("SingularityDxe: op0 bad size %d\r\n", cmd->size);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[0] == 0 || cmd->data[1] == 0) {
            SerialPrintSafe("SingularityDxe: op0 null dst/src\r\n");
            return EFI_INVALID_PARAMETER;
        }

        UINT64 DstVa = cmd->data[0];
        UINT64 SrcVa = cmd->data[1];
        UINTN  Size  = (UINTN)cmd->size;
        UINTN  Done  = 0;

        UINTN Saved; BOOLEAN If;
        SmepSmapOff(&Saved, &If);

        while (Done < Size) {
            UINT64 CurVa = SrcVa + Done;
            UINT64 Pa = VirtualToPhysical(CachedCr3, CurVa);
            if (Pa == 0) {
                SmepSmapOn(Saved, If);
                SerialPrintSafe("SingularityDxe: op0 VA 0x%lx -> PA failed\r\n", CurVa);
                return EFI_NOT_FOUND;
            }

            UINTN PageOff = (UINTN)(CurVa & 0xFFF);
            UINTN ToCopy  = 0x1000 - PageOff;
            if (ToCopy > (Size - Done)) ToCopy = Size - Done;

            volatile UINT8 *SrcP = (volatile UINT8 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Pa);
            volatile UINT8 *DstP = (volatile UINT8 *)(UINTN)(DstVa + Done);
            for (UINTN i = 0; i < ToCopy; i++) DstP[i] = SrcP[i];

            Done += ToCopy;
        }

        SmepSmapOn(Saved, If);
        SerialPrintSafe("SingularityDxe: op0 read %d bytes from VA 0x%lx OK\r\n",
                        (UINT32)Size, SrcVa);
        return EFI_SUCCESS;
    }

    if (DriverBuffer == 0) return EFI_NOT_READY;

    // ---------- Тестові ----------
    if (cmd->operation == OP_INIT) {
        cmd->size = DRIVER_SIZE;
        return EFI_SUCCESS;
    }
    if (cmd->operation == OP_WRITE_TEST) {
        if (cmd->size <= 0 || cmd->size > (int)sizeof(cmd->data)) return EFI_INVALID_PARAMETER;
        CopyMem((VOID *)DriverBuffer, (VOID *)&cmd->data[0], cmd->size);
        return EFI_SUCCESS;
    }
    if (cmd->operation == OP_READ_TEST) {
        if (cmd->size <= 0 || cmd->size > (int)sizeof(cmd->data)) return EFI_INVALID_PARAMETER;
        CopyMem((VOID *)&cmd->data[0], (VOID *)DriverBuffer, cmd->size);
        return EFI_SUCCESS;
    }
    if (cmd->operation == OP_CLEAR_TEST) {
        ZeroMem((VOID *)DriverBuffer, DRIVER_SIZE);
        return EFI_SUCCESS;
    }

    // ---------- op=1: DriverBuffer address ----------
    if (cmd->operation == 1) {
        if (cmd->data[3] != 0) {
            UINTN Saved; BOOLEAN If;
            SmepSmapOff(&Saved, &If);
            *(UINTN *)(UINTN)cmd->data[3] = DriverBuffer;
            SmepSmapOn(Saved, If);
        }
        return EFI_SUCCESS;
    }

    // ---------- op=5: DriverEntry ----------
    if (cmd->operation == 5) {
        UINTN Tgt = (UINTN)cmd->data[0];
        if (Tgt < DriverBuffer || Tgt >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        unsigned long St = ((unsigned long (*)(void *, void *))Tgt)(0, 0);
        if (cmd->data[1] != 0) {
            UINTN Saved; BOOLEAN If;
            SmepSmapOff(&Saved, &If);
            *(unsigned long *)(UINTN)cmd->data[1] = St;
            SmepSmapOn(Saved, If);
        }
        return EFI_SUCCESS;
    }

    SerialPrintSafe("SingularityDxe: unknown op 0x%x\r\n", cmd->operation);
    return EFI_UNSUPPORTED;
}

// ============================================================
//  Variable matching
// ============================================================
STATIC BOOLEAN IsOurVariable(IN CHAR16 *Name, IN EFI_GUID *Guid) {
    if (Name == NULL || Guid == NULL) return FALSE;
    if (StrnCmp(Name, VARIABLE_NAME, (sizeof(VARIABLE_NAME)/sizeof(CHAR16))-1) != 0)
        return FALSE;
    if (!CompareGuid(Guid, &gSingularityDriverProtocolGuid)) return FALSE;
    return TRUE;
}

// ============================================================
//  Hooks
// ============================================================
EFI_STATUS EFIAPI HookedGetVariable(
    IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid,
    OUT UINT32 *Attributes OPTIONAL,
    IN OUT UINTN *DataSize, OUT VOID *Data)
{
    if (Virtual && Runtime) {
        UINTN Saved; BOOLEAN If;
        BOOLEAN Match;

        SmepSmapOff(&Saved, &If);
        Match = IsOurVariable(VariableName, VendorGuid);
        SmepSmapOn(Saved, If);

        if (Match) {
            if (Data == NULL || DataSize == NULL) {
                if (DataSize != NULL) *DataSize = sizeof(MemoryCommand);
                return EFI_BUFFER_TOO_SMALL;
            }
            if (*DataSize >= sizeof(MemoryCommand)) {
                MemoryCommand Local;

                SmepSmapOff(&Saved, &If);
                CopyMem(&Local, Data, sizeof(MemoryCommand));
                SmepSmapOn(Saved, If);

                EFI_STATUS R = RunCommand(&Local);

                SmepSmapOff(&Saved, &If);
                CopyMem(Data, &Local, sizeof(MemoryCommand));
                SmepSmapOn(Saved, If);

                return R;
            }
        }
    }
    return oGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

EFI_STATUS EFIAPI HookedSetVariable(
    IN CHAR16 *VariableName, IN EFI_GUID *VendorGuid,
    IN UINT32 Attributes, IN UINTN DataSize, IN VOID *Data)
{
    if (Virtual && Runtime) {
        UINTN Saved; BOOLEAN If;
        BOOLEAN Match;

        SmepSmapOff(&Saved, &If);
        Match = IsOurVariable(VariableName, VendorGuid);
        SmepSmapOn(Saved, If);

        if (Match) {
            if (DataSize == 0 && Data == NULL) return EFI_SUCCESS;
            if (DataSize == sizeof(MemoryCommand) && Data != NULL) {
                MemoryCommand Local;

                SmepSmapOff(&Saved, &If);
                CopyMem(&Local, Data, sizeof(MemoryCommand));
                SmepSmapOn(Saved, If);

                EFI_STATUS R = RunCommand(&Local);

                SmepSmapOff(&Saved, &If);
                CopyMem(Data, &Local, sizeof(MemoryCommand));
                SmepSmapOn(Saved, If);

                return R;
            }
        }
    }
    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// ============================================================
//  Events
// ============================================================
VOID EFIAPI SetVirtualAddressMapEvent(IN EFI_EVENT Event, IN VOID *Context) {
    SerialPrint("SingularityDxe: VirtualAddressChange\r\n");
    if (oSetVariable) gRT->ConvertPointer(0, (VOID **)&oSetVariable);
    if (oGetVariable) gRT->ConvertPointer(0, (VOID **)&oGetVariable);
    if (DriverBuffer) {
        VOID *T = (VOID *)DriverBuffer;
        gRT->ConvertPointer(0, &T);
        DriverBuffer = (UINTN)T;
        SerialPrintSafe("SingularityDxe: DriverBuffer -> 0x%lx\r\n", (UINT64)DriverBuffer);
    }
    NotifyEvent = NULL;
    Virtual = TRUE;
}

VOID EFIAPI ExitBootServicesEvent(IN EFI_EVENT Event, IN VOID *Context) {
    SerialPrint("SingularityDxe: ExitBootServices\r\n");
    ExitEvent = NULL;
    Runtime = TRUE;
}

VOID* SetServicePointer(EFI_TABLE_HEADER *H, VOID **Fn, VOID *New) {
    if (!Fn || !New || !*Fn) return NULL;
    EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
    VOID *Orig = *Fn;
    *Fn = New;
    H->CRC32 = 0;
    gBS->CalculateCrc32((UINT8 *)H, H->HeaderSize, &H->CRC32);
    gBS->RestoreTPL(Tpl);
    return Orig;
}

EFI_STATUS EFIAPI DxeDriverUnload(IN EFI_HANDLE ImageHandle) { return EFI_ACCESS_DENIED; }

// ============================================================
//  Entry Point
// ============================================================
EFI_STATUS EFIAPI DxeDriverEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *ST) {
    EFI_STATUS Status;
    DummyProtocolData *Existing = NULL;
    EFI_LOADED_IMAGE *LoadedImage = NULL;
    VOID *Buf = NULL;
    INT32 OrigAttr;
    CHAR8 Ascii[256];

    OrigAttr = SetConsoleTextColour(EFI_GREEN, TRUE);
    SingularityDebugPrint("\r\n\r\n");
    SingularityPrintBanner(SINGULARITY_TITLE1);
    SingularityDebugPrint(SINGULARITY_TITLE2);
    gST->ConOut->SetAttribute(gST->ConOut, OrigAttr);

    Status = gBS->OpenProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID **)&LoadedImage, ImageHandle, NULL,
                               EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) return Status;

    Status = gBS->LocateProtocol(&gSingularityDriverProtocolGuid, NULL, (VOID **)&Existing);
    if (Status != EFI_NOT_FOUND) return EFI_ALREADY_STARTED;

    Status = gBS->InstallMultipleProtocolInterfaces(&ImageHandle,
        &gSingularityVersionProtocolGuid, &gSingularitySupportedEfiVersion, NULL);
    if (EFI_ERROR(Status)) return Status;

    gBS->HandleProtocol(gST->ConsoleInHandle, &gEfiSimpleTextInputExProtocolGuid,
                        (VOID **)&gTextInputEx);

    Status = gBS->InstallProtocolInterface(&ImageHandle, &gSingularityDriverProtocolGuid,
                                           EFI_NATIVE_INTERFACE, &gSingularityDriverProtocol);
    if (EFI_ERROR(Status)) return Status;

    LoadedImage->Unload = DxeDriverUnload;

    // ---------- Capture RAM ranges ДО ExitBootServices ----------
    {
        UINTN  MapSize = 0, MapKey = 0, DescSize = 0;
        UINT32 DescVer = 0;

        gBS->GetMemoryMap(&MapSize, NULL, &MapKey, &DescSize, &DescVer);
        MapSize += 4 * DescSize;

        EFI_MEMORY_DESCRIPTOR *Map = NULL;
        Status = gBS->AllocatePool(EfiBootServicesData, MapSize, (VOID **)&Map);
        if (!EFI_ERROR(Status) && Map != NULL) {
            Status = gBS->GetMemoryMap(&MapSize, Map, &MapKey, &DescSize, &DescVer);
            if (!EFI_ERROR(Status)) {
                UINTN Count = MapSize / DescSize;
                for (UINTN i = 0; i < Count && RamRangeCount < MAX_RAM_RANGES; i++) {
                    EFI_MEMORY_DESCRIPTOR *D =
                        (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + i * DescSize);
                    if (D->Type == EfiConventionalMemory && D->NumberOfPages >= 0x100) {
                        RamRanges[RamRangeCount].Start = D->PhysicalStart;
                        RamRanges[RamRangeCount].End =
                            D->PhysicalStart + (D->NumberOfPages * 0x1000);
                        RamRangeCount++;
                    }
                }
            }
            gBS->FreePool(Map);
        }
        AsciiSPrint(Ascii, sizeof(Ascii),
                    "SingularityDxe: %d RAM ranges cached\r\n", (UINT32)RamRangeCount);
        SingularityDebugPrint(Ascii);
    }

    // ---------- DriverBuffer ----------
    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (!EFI_ERROR(Status) && Buf != NULL) {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
        AsciiSPrint(Ascii, sizeof(Ascii),
                    "SingularityDxe: DriverBuffer @ 0x%llx\r\n", (UINT64)DriverBuffer);
        SingularityDebugPrint(Ascii);
    } else {
        DriverBuffer = 0;
        SingularityDebugPrint("SingularityDxe: DriverBuffer NOT allocated\r\n");
    }

    // ---------- Hooks ----------
    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER *)gRT,
                                                       (VOID **)&gRT->SetVariable,
                                                       (VOID *)HookedSetVariable);
    if (!oSetVariable) return EFI_DEVICE_ERROR;

    oGetVariable = (EFI_GET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER *)gRT,
                                                       (VOID **)&gRT->GetVariable,
                                                       (VOID *)HookedGetVariable);
    if (!oGetVariable) {
        SetServicePointer((EFI_TABLE_HEADER *)gRT,
                          (VOID **)&gRT->SetVariable, (VOID *)oSetVariable);
        return EFI_DEVICE_ERROR;
    }

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                SetVirtualAddressMapEvent, NULL,
                                &gEfiEventVirtualAddressChangeGuid, &NotifyEvent);
    if (EFI_ERROR(Status)) {
        SetServicePointer((EFI_TABLE_HEADER *)gRT, (VOID **)&gRT->GetVariable, (VOID *)oGetVariable);
        SetServicePointer((EFI_TABLE_HEADER *)gRT, (VOID **)&gRT->SetVariable, (VOID *)oSetVariable);
        return Status;
    }

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                ExitBootServicesEvent, NULL,
                                &gEfiEventExitBootServicesGuid, &ExitEvent);
    if (EFI_ERROR(Status)) return Status;

    SingularityDebugPrint("SingularityDxe: loaded\r\n");
    return EFI_SUCCESS;
}
