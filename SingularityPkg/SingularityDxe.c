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
                           "\r\n                              Made by GlitchedPanda                              \r\n\n"

EFI_GUID  gSingularityDriverProtocolGuid = {
  0xdeadfade, 0x0601, 0x47C6, { 0x84, 0xE7, 0x2E, 0xBC, 0x93, 0x7D, 0x1B, 0x11 }
};

EFI_GUID  gEfiDriverSupportedEfiVersionProtocolGuid = {
  0xdeadfade, 0xDB2B, 0x42D2, { 0xBF, 0x5F, 0xBA, 0xF9, 0xC5, 0x51, 0x71, 0x54 }
};

EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL  gSingularitySupportedEfiVersion = { 0 };
EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL          *gTextInputEx = NULL;
DummyProtocolData                          gSingularityDriverProtocol = { 0 };

static EFI_SET_VARIABLE oSetVariable = NULL;
static EFI_GET_VARIABLE oGetVariable = NULL;

static EFI_EVENT NotifyEvent = NULL;
static EFI_EVENT ExitEvent   = NULL;
static BOOLEAN   Virtual     = FALSE;
static BOOLEAN   Runtime     = FALSE;

static UINTN DriverBuffer = 0;

#define VARIABLE_NAME L"Singularity42"
#define COMMAND_MAGIC 0xDEADFADE
#define DRIVER_SIZE   0x2000000

// === Mode 4 extensions ===
#define OP_FIND_PROC  0x10
#define OP_READ_CR3   0x11

#define WINDOWS_DIRECT_MAP_BASE 0xFFFF800000000000ULL
#define CR4_SMEP (1ULL << 20)
#define CR4_SMAP (1ULL << 21)

typedef struct _MemoryCommand
{
    int magic;
    int operation;
    unsigned long long data[10];
    int size;
} MemoryCommand;

typedef UINTN (__stdcall *ExAllocatePool)(int type, UINTN size);
typedef void  (__stdcall *ExFreePool)(UINTN address);
typedef void  (__stdcall *StandardFuncStd)(void);
typedef void  (__fastcall *StandardFuncFast)(void);
typedef unsigned long (__stdcall *DriverEntry)(void* driver, void* registry);

// ============================================================
//  Mode 4 helpers
// ============================================================
#define MAX_RAM_RANGES 64
typedef struct { UINT64 Start; UINT64 End; } RAM_RANGE;
static RAM_RANGE RamRanges[MAX_RAM_RANGES];
static UINTN     RamRangeCount = 0;

static UINT64 CachedCr3 = 0;
static UINT32 CachedPid = 0;

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

STATIC UINT64 ScanForProcessCr3(IN UINT32 TargetPid) {
    if (RamRangeCount == 0) return 0;

    CONST UINT64 Pattern = 0x006578652E327363ULL;  // "cs2.exe\0"

    for (UINTN r = 0; r < RamRangeCount; r++) {
        UINT64 Start = RamRanges[r].Start;
        UINT64 End   = RamRanges[r].End;
        if (Start < 0x100000) Start = 0x100000;
        if (End > 0x800000000ULL) End = 0x800000000ULL;
        Start &= ~7ULL;
        End   &= ~7ULL;

        for (UINT64 Pa = Start; Pa + 8 <= End; Pa += 8) {
            UINT64 V = *(volatile UINT64 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Pa);
            if (V != Pattern) continue;

            if (Pa < 0x5a8) continue;
            UINT64 Ep = Pa - 0x5a8;
            if (Ep & 0xF) continue;

            UINT32 Pid = *(volatile UINT32 *)(UINTN)
                (WINDOWS_DIRECT_MAP_BASE + Ep + 0x440);
            if (Pid != TargetPid) continue;

            UINT64 Dtb = *(volatile UINT64 *)(UINTN)
                (WINDOWS_DIRECT_MAP_BASE + Ep + 0x28);
            if (Dtb == 0 || (Dtb & 0xFFF) != 0) continue;
            if (Dtb > 0x10000000000ULL) continue;

            SerialPrintSafe("SingularityDxe: EPROCESS @ PA 0x%lx PID=%d DTB=0x%lx\r\n",
                            Ep, Pid, Dtb);
            return Dtb;
        }
    }
    SerialPrintSafe("SingularityDxe: cs2.exe not found\r\n");
    return 0;
}

STATIC VOID SmepSmapOff(OUT UINTN *Saved) {
    *Saved = AsmReadCr4();
    AsmWriteCr4(*Saved & ~(CR4_SMEP | CR4_SMAP));
}

STATIC VOID SmepSmapOn(IN UINTN Saved) {
    AsmWriteCr4(Saved);
}

// ============================================================
//  RunCommand — ORIHINAL op=0/1/3/4/5 + нові op=0x10/0x11
// ============================================================
EFI_STATUS
RunCommand(MemoryCommand* cmd)
{
    if (cmd->magic != COMMAND_MAGIC) {
        SerialPrintSafe("SingularityDxe: RunCommand bad magic 0x%x (expected 0x%x)\r\n",
                  cmd->magic, COMMAND_MAGIC);
        return EFI_ACCESS_DENIED;
    }

    SerialPrintSafe("SingularityDxe: RunCommand op=%d size=%d data[0]=0x%lx data[1]=0x%lx\r\n",
              cmd->operation, cmd->size,
              (UINT64)cmd->data[0], (UINT64)cmd->data[1]);

    // 0: memcpy(dst, src, size)
    if (cmd->operation == 0) {
        if (cmd->size <= 0 || cmd->size > 0x1000000) {
            SerialPrintSafe("SingularityDxe: op0 invalid size %d\r\n", cmd->size);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[0] == 0 || cmd->data[1] == 0) {
            SerialPrintSafe("SingularityDxe: op0 null src/dst\r\n");
            return EFI_INVALID_PARAMETER;
        }
        CopyMem((VOID*)(UINTN)cmd->data[0], (VOID*)(UINTN)cmd->data[1], cmd->size);
        SerialPrintSafe("SingularityDxe: op0 copy ok\r\n");
        return EFI_SUCCESS;
    }

    // 1: report DriverBuffer address back to caller via cmd->data[3]
    if (cmd->operation == 1) {
        if (cmd->data[2] == 0 || cmd->data[2] > DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op1 invalid request size %lu\r\n",
                      (UINT64)cmd->data[2]);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[3] != 0) {
            *(UINTN*)(UINTN)cmd->data[3] = DriverBuffer;
            SerialPrintSafe("SingularityDxe: op1 wrote DriverBuffer=0x%lx to 0x%lx\r\n",
                      (UINT64)DriverBuffer, (UINT64)cmd->data[3]);
        } else {
            SerialPrintSafe("SingularityDxe: op1 no output slot provided\r\n");
        }
        return EFI_SUCCESS;
    }

    // 3: call __stdcall void() inside DriverBuffer
    if (cmd->operation == 3) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op3 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op3 calling stdcall@0x%lx\r\n", (UINT64)target);
        ((StandardFuncStd)target)();
        SerialPrintSafe("SingularityDxe: op3 returned\r\n");
        return EFI_SUCCESS;
    }

    // 4: call __fastcall void() inside DriverBuffer
    if (cmd->operation == 4) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op4 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op4 calling fastcall@0x%lx\r\n", (UINT64)target);
        ((StandardFuncFast)target)();
        SerialPrintSafe("SingularityDxe: op4 returned\r\n");
        return EFI_SUCCESS;
    }

    // 5: invoke a Windows-style DriverEntry inside DriverBuffer, return its status
    if (cmd->operation == 5) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op5 target 0x%lx outside DriverBuffer\r\n",
                      (UINT64)target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op5 calling DriverEntry@0x%lx\r\n", (UINT64)target);
        unsigned long status = ((DriverEntry)target)(0, 0);
        SerialPrintSafe("SingularityDxe: op5 returned status=0x%x\r\n", (UINT32)status);
        if (cmd->data[1] != 0) {
            *(unsigned long*)(UINTN)cmd->data[1] = status;
        }
        return EFI_SUCCESS;
    }

    // ==== Mode 4 extensions ====

    // 0x10: find process by PID, cache CR3
    if (cmd->operation == OP_FIND_PROC) {
        UINT32 Pid = (UINT32)cmd->data[0];
        if (Pid == 0) return EFI_INVALID_PARAMETER;
        UINT64 Cr3 = ScanForProcessCr3(Pid);
        if (Cr3 == 0) return EFI_NOT_FOUND;
        CachedPid = Pid;
        CachedCr3 = Cr3;
        SerialPrintSafe("SingularityDxe: cached PID=%d CR3=0x%lx\r\n", Pid, Cr3);
        return EFI_SUCCESS;
    }

    // 0x11: read memory via cached CR3 (VA -> PA -> direct map)
    if (cmd->operation == OP_READ_CR3) {
        if (CachedCr3 == 0) {
            SerialPrintSafe("SingularityDxe: op11 no CR3\r\n");
            return EFI_NOT_READY;
        }
        if (cmd->size <= 0 || cmd->size > 0x100000) {
            SerialPrintSafe("SingularityDxe: op11 bad size %d\r\n", cmd->size);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[0] == 0 || cmd->data[1] == 0) {
            SerialPrintSafe("SingularityDxe: op11 null ptr\r\n");
            return EFI_INVALID_PARAMETER;
        }

        UINT64 DstVa = cmd->data[0];
        UINT64 SrcVa = cmd->data[1];
        UINTN  Size  = (UINTN)cmd->size;
        UINTN  Done  = 0;

        UINTN Saved;
        SmepSmapOff(&Saved);

        while (Done < Size) {
            UINT64 CurVa = SrcVa + Done;
            UINT64 Pa = VirtualToPhysical(CachedCr3, CurVa);
            if (Pa == 0) {
                SmepSmapOn(Saved);
                SerialPrintSafe("SingularityDxe: op11 VA 0x%lx -> PA failed\r\n", CurVa);
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
        SmepSmapOn(Saved);
        SerialPrintSafe("SingularityDxe: op11 read %d bytes from VA 0x%lx OK\r\n",
                        (UINT32)Size, SrcVa);
        return EFI_SUCCESS;
    }

    SerialPrintSafe("SingularityDxe: unknown op %d\r\n", cmd->operation);
    return EFI_UNSUPPORTED;
}

// ============================================================
//  SetVariable hook — ОРИГІНАЛ (тільки ім'я, без GUID)
// ============================================================
EFI_STATUS
EFIAPI
HookedSetVariable(
    IN CHAR16    *VariableName,
    IN EFI_GUID  *VendorGuid,
    IN UINT32    Attributes,
    IN UINTN     DataSize,
    IN VOID      *Data
    )
{
    if (Virtual && Runtime) {
        if (VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL) {
            if (StrnCmp(VariableName, VARIABLE_NAME,
                        (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
                SerialPrintSafe("SingularityDxe: hook matched (DataSize=%lu)\r\n",
                          (UINT64)DataSize);
                if (DataSize == 0 && Data == NULL) {
                    SerialPrintSafe("SingularityDxe: empty payload, ack\r\n");
                    return EFI_SUCCESS;
                }
                if (DataSize == sizeof(MemoryCommand) && Data != NULL) {
                    EFI_STATUS Result = RunCommand((MemoryCommand*)Data);
                    SerialPrintSafe("SingularityDxe: RunCommand returned %r (0x%lx)\r\n",
                              Result, (UINT64)Result);
                    return Result;
                }
                SerialPrintSafe("SingularityDxe: hook matched but bad payload (DataSize=%lu, expected=%lu)\r\n",
                          (UINT64)DataSize, (UINT64)sizeof(MemoryCommand));
            }
        }
    }
    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// ============================================================
//  GetVariable hook — новий, для mode 4
//  Той самий принцип: тільки ім'я, без GUID.
// ============================================================
EFI_STATUS
EFIAPI
HookedGetVariable(
    IN CHAR16    *VariableName,
    IN EFI_GUID  *VendorGuid,
    OUT UINT32   *Attributes, OPTIONAL
    IN OUT UINTN *DataSize,
    OUT VOID     *Data
    )
{
    if (Virtual && Runtime) {
        if (VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL) {
            if (StrnCmp(VariableName, VARIABLE_NAME,
                        (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {

                if (Data == NULL || DataSize == NULL) {
                    if (DataSize != NULL) *DataSize = sizeof(MemoryCommand);
                    return EFI_BUFFER_TOO_SMALL;
                }
                if (*DataSize >= sizeof(MemoryCommand)) {
                    EFI_STATUS Result = RunCommand((MemoryCommand*)Data);
                    return Result;
                }
            }
        }
    }
    return oGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// ============================================================
//  Events (оригінал + ConvertPointer для oGetVariable)
// ============================================================
VOID
EFIAPI
SetVirtualAddressMapEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
    SerialPrint("SingularityDxe: VirtualAddressChange event fired\r\n");

    if (oSetVariable != NULL) {
        gRT->ConvertPointer(0, (VOID**)&oSetVariable);
    }
    if (oGetVariable != NULL) {
        gRT->ConvertPointer(0, (VOID**)&oGetVariable);
    }
    if (DriverBuffer != 0) {
        VOID *Tmp = (VOID*)DriverBuffer;
        gRT->ConvertPointer(0, &Tmp);
        DriverBuffer = (UINTN)Tmp;
        SerialPrintSafe("SingularityDxe: DriverBuffer converted -> 0x%lx\r\n",
                  (UINT64)DriverBuffer);
    }

    NotifyEvent = NULL;
    Virtual = TRUE;
    SerialPrint("SingularityDxe: now in virtual address space\r\n");
}

VOID
EFIAPI
ExitBootServicesEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
    SerialPrint("SingularityDxe: ExitBootServices event fired, OS taking over\r\n");
    ExitEvent = NULL;
    Runtime = TRUE;
}

VOID*
SetServicePointer(
    IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
    IN OUT VOID **ServiceTableFunction,
    IN VOID *NewFunction
    )
{
    if (ServiceTableFunction == NULL || NewFunction == NULL || *ServiceTableFunction == NULL) {
        return NULL;
    }
    ASSERT(gBS != NULL);
    ASSERT(gBS->CalculateCrc32 != NULL);
    CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
    VOID* OriginalFunction = *ServiceTableFunction;
    *ServiceTableFunction = NewFunction;
    ServiceTableHeader->CRC32 = 0;
    gBS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);
    gBS->RestoreTPL(Tpl);
    return OriginalFunction;
}

EFI_STATUS
EFIAPI
DxeDriverUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  return EFI_ACCESS_DENIED;
}

// ============================================================
//  Entry Point — оригінал + RAM ranges capture
// ============================================================
EFI_STATUS
EFIAPI
DxeDriverEntry(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    EFI_STATUS          Status;
    DummyProtocolData   *ExistingProtocol = NULL;
    EFI_LOADED_IMAGE    *LoadedImage      = NULL;
    VOID                *Buf              = NULL;
    INT32               OriginalAttribute = 0;
    CHAR8               AsciiBuffer[256];

    OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
    SingularityDebugPrint("\r\n\r\n");
    SingularityPrintBanner(SINGULARITY_TITLE1);
    SingularityDebugPrint(SINGULARITY_TITLE2);
    gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

    SingularityDebugPrint("SingularityDxe: DxeDriverEntry begin\r\n");

    Status = gBS->OpenProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID**)&LoadedImage, ImageHandle,
                               NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: OpenProtocol(LoadedImage) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 1/7 LoadedImage opened\r\n");

    Status = gBS->LocateProtocol(&gSingularityDriverProtocolGuid, NULL, (VOID**)&ExistingProtocol);
    if (Status != EFI_NOT_FOUND) {
        SingularityDebugPrint("SingularityDxe: already loaded\r\n");
        return EFI_ALREADY_STARTED;
    }
    SingularityDebugPrint("SingularityDxe:   step 2/7 no prior instance found\r\n");

    Status = gBS->InstallMultipleProtocolInterfaces(&ImageHandle,
                                                   &gEfiDriverSupportedEfiVersionProtocolGuid,
                                                   &gSingularitySupportedEfiVersion,
                                                   NULL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: install supported-version protocol failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 3/7 supported-version protocol installed\r\n");

    gBS->HandleProtocol(gST->ConsoleInHandle,
                        &gEfiSimpleTextInputExProtocolGuid,
                        (VOID**)&gTextInputEx);

    Status = gBS->InstallProtocolInterface(&ImageHandle,
                                           &gSingularityDriverProtocolGuid,
                                           EFI_NATIVE_INTERFACE,
                                           &gSingularityDriverProtocol);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: install driver protocol failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 4/7 driver protocol installed\r\n");

    LoadedImage->Unload = DxeDriverUnload;

    // ---- Capture RAM ranges ДО ExitBootServices (для mode 4) ----
    {
        UINTN  MapSize = 0, MapKey = 0, DescSize = 0;
        UINT32 DescVer = 0;
        gBS->GetMemoryMap(&MapSize, NULL, &MapKey, &DescSize, &DescVer);
        MapSize += 4 * DescSize;

        EFI_MEMORY_DESCRIPTOR *Map = NULL;
        Status = gBS->AllocatePool(EfiBootServicesData, MapSize, (VOID**)&Map);
        if (!EFI_ERROR(Status) && Map != NULL) {
            Status = gBS->GetMemoryMap(&MapSize, Map, &MapKey, &DescSize, &DescVer);
            if (!EFI_ERROR(Status)) {
                UINTN Count = MapSize / DescSize;
                for (UINTN i = 0; i < Count && RamRangeCount < MAX_RAM_RANGES; i++) {
                    EFI_MEMORY_DESCRIPTOR *D =
                        (EFI_MEMORY_DESCRIPTOR*)((UINT8*)Map + i * DescSize);
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
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: %d RAM ranges cached\r\n", (UINT32)RamRangeCount);
        SingularityDebugPrint(AsciiBuffer);
    }

    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (EFI_ERROR(Status) || Buf == NULL) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: AllocatePool failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        DriverBuffer = 0;
    } else {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: DriverBuffer @ 0x%llx\r\n", (UINT64)DriverBuffer);
        SingularityDebugPrint(AsciiBuffer);
    }

    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT,
                                                      (VOID**)&gRT->SetVariable,
                                                      (VOID*)HookedSetVariable);
    if (oSetVariable == NULL) {
        SingularityDebugPrint("SingularityDxe: failed to hook SetVariable\r\n");
        return EFI_DEVICE_ERROR;
    }
    AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                "SingularityDxe:   step 5/7 SetVariable hooked (original @ 0x%llx, hook @ 0x%llx)\r\n",
                (UINT64)(UINTN)oSetVariable, (UINT64)(UINTN)HookedSetVariable);
    SingularityDebugPrint(AsciiBuffer);

    oGetVariable = (EFI_GET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT,
                                                      (VOID**)&gRT->GetVariable,
                                                      (VOID*)HookedGetVariable);
    if (oGetVariable == NULL) {
        SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)oSetVariable);
        SingularityDebugPrint("SingularityDxe: failed to hook GetVariable\r\n");
        return EFI_DEVICE_ERROR;
    }
    SingularityDebugPrint("SingularityDxe:   step 5b GetVariable hooked\r\n");

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                SetVirtualAddressMapEvent, NULL,
                                &gEfiEventVirtualAddressChangeGuid, &NotifyEvent);
    if (EFI_ERROR(Status)) {
        SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->GetVariable, (VOID*)oGetVariable);
        SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)oSetVariable);
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: CreateEventEx(VirtualAddressChange) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 6/7 VirtualAddressChange event registered\r\n");

    Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                                ExitBootServicesEvent, NULL,
                                &gEfiEventExitBootServicesGuid, &ExitEvent);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: CreateEventEx(ExitBootServices) failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }
    SingularityDebugPrint("SingularityDxe:   step 7/7 ExitBootServices event registered\r\n");

    SingularityDebugPrint("SingularityDxe: loaded\r\n");
    return EFI_SUCCESS;
}
