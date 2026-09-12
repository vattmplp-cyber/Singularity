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
                           "\r\n                     Made by GlitchedPanda (GetVariable Fix)                     \r\n\n"

// ============================================================
//  GUIDs
// ============================================================
EFI_GUID gSingularityDriverProtocolGuid = {
  0xdeadfade, 0x0601, 0x47C6, { 0x84, 0xE7, 0x2E, 0xBC, 0x93, 0x7D, 0x1B, 0x11 }
};

// ВИПРАВЛЕНО: власна назва, не конфліктує зі стандартним GUID з MdePkg
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
static BOOLEAN   Virtual     = FALSE;
static BOOLEAN   Runtime     = FALSE;

static UINTN DriverBuffer = 0;

#define VARIABLE_NAME L"Singularity42"
#define COMMAND_MAGIC 0xDEADFADE
#define DRIVER_SIZE   0x2000000

// Маркерні операції (твої, залишені як є)
#define OP_INIT       1
#define OP_WRITE_TEST 2
#define OP_READ_TEST  3
#define OP_CLEAR_TEST 4

// База direct-map фізичної пам'яті у Windows 10/11 x64
#define WINDOWS_DIRECT_MAP_BASE 0xFFFF800000000000ULL

// CR4 біти
#define CR4_SMEP (1ULL << 20)
#define CR4_SMAP (1ULL << 21)

typedef struct _MemoryCommand {
    int magic;
    int operation;
    unsigned long long data[10];  // data[9] = CR3 (DirectoryTableBase) для VA→PA
    int size;
} MemoryCommand;

// ============================================================
//  SMAP / SMEP bypass
// ============================================================
STATIC
VOID
SmepSmapOff (
    OUT UINTN *Saved
    )
{
    *Saved = AsmReadCr4();
    AsmWriteCr4(*Saved & ~(CR4_SMEP | CR4_SMAP));
}

STATIC
VOID
SmepSmapOn (
    IN UINTN Saved
    )
{
    AsmWriteCr4(Saved);
}

// ============================================================
//  Physical memory access (VA→PA)
// ============================================================
STATIC
UINT64
ReadPhysicalU64 (
    IN UINT64 PhysicalAddress
    )
{
    volatile UINT64 *Ptr =
        (volatile UINT64 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + PhysicalAddress);
    return *Ptr;
}

STATIC
UINT64
VirtualToPhysical (
    IN UINT64 Cr3,
    IN UINT64 VirtualAddress
    )
{
    if (Cr3 == 0) return 0;

    UINT64 Pml4Index = (VirtualAddress >> 39) & 0x1FF;
    UINT64 PdptIndex = (VirtualAddress >> 30) & 0x1FF;
    UINT64 PdIndex   = (VirtualAddress >> 21) & 0x1FF;
    UINT64 PtIndex   = (VirtualAddress >> 12) & 0x1FF;
    UINT64 Offset    = VirtualAddress & 0xFFF;

    UINT64 Pml4Entry = ReadPhysicalU64(Cr3 + Pml4Index * 8);
    if (!(Pml4Entry & 1)) return 0;

    UINT64 PdptEntry = ReadPhysicalU64((Pml4Entry & 0x000FFFFFFFFFF000ULL) + PdptIndex * 8);
    if (!(PdptEntry & 1)) return 0;
    if (PdptEntry & (1ULL << 7)) {
        return (PdptEntry & 0x000FFFFFC0000000ULL) + (VirtualAddress & 0x3FFFFFFF);
    }

    UINT64 PdEntry = ReadPhysicalU64((PdptEntry & 0x000FFFFFFFFFF000ULL) + PdIndex * 8);
    if (!(PdEntry & 1)) return 0;
    if (PdEntry & (1ULL << 7)) {
        return (PdEntry & 0x000FFFFFFFE00000ULL) + (VirtualAddress & 0x1FFFFF);
    }

    UINT64 PtEntry = ReadPhysicalU64((PdEntry & 0x000FFFFFFFFFF000ULL) + PtIndex * 8);
    if (!(PtEntry & 1)) return 0;

    return (PtEntry & 0x000FFFFFFFFFF000ULL) + Offset;
}

// ============================================================
//  RunCommand — cmd завжди вказує на СТЕКОВУ копію, не на user-VA
// ============================================================
EFI_STATUS
RunCommand (
    MemoryCommand *cmd
    )
{
    if (cmd->magic != COMMAND_MAGIC) {
        SerialPrintSafe("SingularityDxe: RunCommand bad magic 0x%x (expected 0x%x)\r\n",
                        cmd->magic, COMMAND_MAGIC);
        return EFI_ACCESS_DENIED;
    }

    SerialPrintSafe("SingularityDxe: op=%d size=%d cr3=0x%lx dst=0x%lx src=0x%lx\r\n",
                    cmd->operation, cmd->size, cmd->data[9], cmd->data[0], cmd->data[1]);

    if (DriverBuffer == 0) return EFI_NOT_READY;

    // ============================================================
    //  OP_INIT / OP_WRITE_TEST / OP_READ_TEST / OP_CLEAR_TEST
    //  (працюють тільки з DriverBuffer — жодних user-VA)
    // ============================================================
    if (cmd->operation == OP_INIT) {
        cmd->size = DRIVER_SIZE;
        SerialPrintSafe("SingularityDxe: OP_INIT verified. DriverBuffer size: %d\r\n", cmd->size);
        return EFI_SUCCESS;
    }

    if (cmd->operation == OP_WRITE_TEST) {
        if (cmd->size <= 0 || cmd->size > sizeof(cmd->data)) return EFI_INVALID_PARAMETER;
        CopyMem((VOID *)DriverBuffer, (VOID *)&cmd->data[0], cmd->size);
        SerialPrintSafe("SingularityDxe: OP_WRITE_TEST executed.\r\n");
        return EFI_SUCCESS;
    }

    if (cmd->operation == OP_READ_TEST) {
        if (cmd->size <= 0 || cmd->size > sizeof(cmd->data)) return EFI_INVALID_PARAMETER;
        CopyMem((VOID *)&cmd->data[0], (VOID *)DriverBuffer, cmd->size);
        SerialPrintSafe("SingularityDxe: OP_READ_TEST executed.\r\n");
        return EFI_SUCCESS;
    }

    if (cmd->operation == OP_CLEAR_TEST) {
        ZeroMem((VOID *)DriverBuffer, DRIVER_SIZE);
        SerialPrintSafe("SingularityDxe: OP_CLEAR_TEST executed.\r\n");
        return EFI_SUCCESS;
    }

    // ============================================================
    //  op=0: read memory (з опційною VA→PA трансляцією через CR3)
    // ============================================================
    if (cmd->operation == 0) {
        if (cmd->size <= 0 || cmd->size > 0x1000000) {
            SerialPrintSafe("SingularityDxe: op0 invalid size %d\r\n", cmd->size);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[0] == 0 || cmd->data[1] == 0) {
            SerialPrintSafe("SingularityDxe: op0 null src/dst\r\n");
            return EFI_INVALID_PARAMETER;
        }

        UINT8 *Dst = (UINT8 *)(UINTN)cmd->data[0];
        UINTN Saved;
        SmepSmapOff(&Saved);

        if (cmd->data[9] != 0) {
            // --- Чужий процес: VA→PA через CR3, читання з direct-map ---
            UINT64 Pa = VirtualToPhysical(cmd->data[9], cmd->data[1]);
            if (Pa == 0) {
                SmepSmapOn(Saved);
                SerialPrintSafe("SingularityDxe: op0 VA->PA failed for 0x%lx\r\n",
                                cmd->data[1]);
                return EFI_NOT_FOUND;
            }
            volatile UINT8 *Psrc = (volatile UINT8 *)(UINTN)(WINDOWS_DIRECT_MAP_BASE + Pa);
            for (UINTN i = 0; i < (UINTN)cmd->size; i++) {
                Dst[i] = Psrc[i];
            }
            SerialPrintSafe("SingularityDxe: op0 VA=0x%lx -> PA=0x%lx copied %d\r\n",
                            cmd->data[1], Pa, cmd->size);
        } else {
            // --- Свій процес: пряма копія ---
            volatile UINT8 *Src = (volatile UINT8 *)(UINTN)cmd->data[1];
            for (UINTN i = 0; i < (UINTN)cmd->size; i++) {
                Dst[i] = Src[i];
            }
            SerialPrintSafe("SingularityDxe: op0 direct copy %d\r\n", cmd->size);
        }

        SmepSmapOn(Saved);
        return EFI_SUCCESS;
    }

    // ============================================================
    //  op=1: report DriverBuffer address back via data[3]
    // ============================================================
    if (cmd->operation == 1) {
        if (cmd->data[2] == 0 || cmd->data[2] > DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op1 invalid request size %lu\r\n", cmd->data[2]);
            return EFI_INVALID_PARAMETER;
        }
        if (cmd->data[3] != 0) {
            UINTN Saved;
            SmepSmapOff(&Saved);
            *(UINTN *)(UINTN)cmd->data[3] = DriverBuffer;
            SmepSmapOn(Saved);
            SerialPrintSafe("SingularityDxe: op1 wrote DriverBuffer=0x%lx\r\n", DriverBuffer);
        }
        return EFI_SUCCESS;
    }

    // ============================================================
    //  op=3: call __stdcall void() inside DriverBuffer
    // ============================================================
    if (cmd->operation == 3) {
        UINTN target = (UINTN)cmd->data[0];
        if (target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op3 target outside DriverBuffer\r\n");
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op3 calling stdcall@0x%lx\r\n", target);
        ((void (*)(void))target)();
        SerialPrintSafe("SingularityDxe: op3 returned\r\n");
        return EFI_SUCCESS;
    }

    // ============================================================
    //  op=4: call __fastcall void() inside DriverBuffer
    // ============================================================
    if (cmd->operation == 4) {
        UINTN target = (UINTN)cmd->data[0];
        if (target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op4 target outside DriverBuffer\r\n");
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op4 calling fastcall@0x%lx\r\n", target);
        ((void (*)(void))target)();
        SerialPrintSafe("SingularityDxe: op4 returned\r\n");
        return EFI_SUCCESS;
    }

    // ============================================================
    //  op=5: invoke DriverEntry inside DriverBuffer
    // ============================================================
    if (cmd->operation == 5) {
        UINTN target = (UINTN)cmd->data[0];
        if (target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) {
            SerialPrintSafe("SingularityDxe: op5 target 0x%lx outside DriverBuffer\r\n", target);
            return EFI_ACCESS_DENIED;
        }
        SerialPrintSafe("SingularityDxe: op5 calling DriverEntry@0x%lx\r\n", target);
        unsigned long status = ((unsigned long (*)(void *, void *))target)(0, 0);
        SerialPrintSafe("SingularityDxe: op5 returned status=0x%x\r\n", (UINT32)status);
        if (cmd->data[1] != 0) {
            UINTN Saved;
            SmepSmapOff(&Saved);
            *(unsigned long *)(UINTN)cmd->data[1] = status;
            SmepSmapOn(Saved);
        }
        return EFI_SUCCESS;
    }

    SerialPrintSafe("SingularityDxe: unknown op %d\r\n", cmd->operation);
    return EFI_UNSUPPORTED;
}

// ============================================================
//  HookedGetVariable
// ============================================================
EFI_STATUS
EFIAPI
HookedGetVariable (
    IN CHAR16        *VariableName,
    IN EFI_GUID      *VendorGuid,
    OUT UINT32       *Attributes, OPTIONAL
    IN OUT UINTN     *DataSize,
    OUT VOID         *Data
    )
{
    if (Virtual && Runtime && VariableName != NULL && VendorGuid != NULL) {
        UINTN Saved;
        BOOLEAN Match = FALSE;

        SmepSmapOff(&Saved);
        if (StrnCmp(VariableName, VARIABLE_NAME,
                    (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
            Match = TRUE;
        }
        SmepSmapOn(Saved);

        if (Match) {
            // Коректний QuerySize-контракт
            if (Data == NULL || DataSize == NULL) {
                if (DataSize != NULL) *DataSize = sizeof(MemoryCommand);
                return EFI_BUFFER_TOO_SMALL;
            }
            if (*DataSize >= sizeof(MemoryCommand)) {
                MemoryCommand Local;

                SmepSmapOff(&Saved);
                CopyMem(&Local, Data, sizeof(MemoryCommand));
                SmepSmapOn(Saved);

                EFI_STATUS Result = RunCommand(&Local);

                SmepSmapOff(&Saved);
                CopyMem(Data, &Local, sizeof(MemoryCommand));
                SmepSmapOn(Saved);

                return Result;
            }
        }
    }
    return oGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// ============================================================
//  HookedSetVariable
// ============================================================
EFI_STATUS
EFIAPI
HookedSetVariable (
    IN CHAR16    *VariableName,
    IN EFI_GUID  *VendorGuid,
    IN UINT32     Attributes,
    IN UINTN      DataSize,
    IN VOID      *Data
    )
{
    if (Virtual && Runtime && VariableName != NULL && VendorGuid != NULL) {
        UINTN Saved;
        BOOLEAN Match = FALSE;

        SmepSmapOff(&Saved);
        if (StrnCmp(VariableName, VARIABLE_NAME,
                    (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
            Match = TRUE;
        }
        SmepSmapOn(Saved);

        if (Match) {
            if (DataSize == 0 && Data == NULL) {
                return EFI_SUCCESS;
            }
            if (DataSize == sizeof(MemoryCommand) && Data != NULL) {
                MemoryCommand Local;

                SmepSmapOff(&Saved);
                CopyMem(&Local, Data, sizeof(MemoryCommand));
                SmepSmapOn(Saved);

                EFI_STATUS Result = RunCommand(&Local);

                // Повертаємо клієнту модифікований cmd (напр. оновлений size)
                SmepSmapOff(&Saved);
                CopyMem(Data, &Local, sizeof(MemoryCommand));
                SmepSmapOn(Saved);

                return Result;
            }
            SerialPrintSafe("SingularityDxe: SetVariable size mismatch (%lu != %lu)\r\n",
                            (UINT64)DataSize, (UINT64)sizeof(MemoryCommand));
        }
    }
    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

// ============================================================
//  Events
// ============================================================
VOID
EFIAPI
SetVirtualAddressMapEvent (
    IN EFI_EVENT Event,
    IN VOID     *Context
    )
{
    SerialPrint("SingularityDxe: VirtualAddressChange event fired\r\n");

    if (oSetVariable != NULL) {
        gRT->ConvertPointer(0, (VOID **)&oSetVariable);
    }
    if (oGetVariable != NULL) {
        gRT->ConvertPointer(0, (VOID **)&oGetVariable);
    }
    if (DriverBuffer != 0) {
        VOID *Tmp = (VOID *)DriverBuffer;
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
ExitBootServicesEvent (
    IN EFI_EVENT Event,
    IN VOID     *Context
    )
{
    SerialPrint("SingularityDxe: ExitBootServices event fired, OS taking over\r\n");
    ExitEvent = NULL;
    Runtime = TRUE;
}

// ============================================================
//  SetServicePointer
// ============================================================
VOID *
SetServicePointer (
    IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
    IN OUT VOID            **ServiceTableFunction,
    IN VOID                 *NewFunction
    )
{
    if (ServiceTableFunction == NULL || NewFunction == NULL || *ServiceTableFunction == NULL) {
        return NULL;
    }

    ASSERT(gBS != NULL);
    ASSERT(gBS->CalculateCrc32 != NULL);

    CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

    VOID *OriginalFunction = *ServiceTableFunction;
    *ServiceTableFunction = NewFunction;

    ServiceTableHeader->CRC32 = 0;
    gBS->CalculateCrc32((UINT8 *)ServiceTableHeader,
                        ServiceTableHeader->HeaderSize,
                        &ServiceTableHeader->CRC32);

    gBS->RestoreTPL(Tpl);
    return OriginalFunction;
}

EFI_STATUS
EFIAPI
DxeDriverUnload (
    IN EFI_HANDLE ImageHandle
    )
{
    return EFI_ACCESS_DENIED;
}

// ============================================================
//  Entry Point
// ============================================================
EFI_STATUS
EFIAPI
DxeDriverEntry (
    IN EFI_HANDLE       ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS         Status;
    DummyProtocolData *ExistingProtocol = NULL;
    EFI_LOADED_IMAGE  *LoadedImage      = NULL;
    VOID              *Buf              = NULL;
    INT32              OriginalAttribute = 0;
    CHAR8              AsciiBuffer[256];

    OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
    SingularityDebugPrint("\r\n\r\n");
    SingularityPrintBanner(SINGULARITY_TITLE1);
    SingularityDebugPrint(SINGULARITY_TITLE2);
    gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
    SingularityDebugPrint("SingularityDxe: DxeDriverEntry begin\r\n");

    Status = gBS->OpenProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID **)&LoadedImage, ImageHandle,
                               NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: OpenProtocol failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }

    Status = gBS->LocateProtocol(&gSingularityDriverProtocolGuid, NULL,
                                 (VOID **)&ExistingProtocol);
    if (Status != EFI_NOT_FOUND) {
        SingularityDebugPrint("SingularityDxe: already loaded\r\n");
        return EFI_ALREADY_STARTED;
    }

    // ВИПРАВЛЕНО: використовуємо gSingularityVersionProtocolGuid
    Status = gBS->InstallMultipleProtocolInterfaces(&ImageHandle,
                                                    &gSingularityVersionProtocolGuid,
                                                    &gSingularitySupportedEfiVersion,
                                                    NULL);
    if (EFI_ERROR(Status)) {
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: install version proto failed (%r)\r\n", Status);
        SingularityDebugPrint(AsciiBuffer);
        return Status;
    }

    gBS->HandleProtocol(gST->ConsoleInHandle,
                        &gEfiSimpleTextInputExProtocolGuid,
                        (VOID **)&gTextInputEx);

    Status = gBS->InstallProtocolInterface(&ImageHandle,
                                           &gSingularityDriverProtocolGuid,
                                           EFI_NATIVE_INTERFACE,
                                           &gSingularityDriverProtocol);
    if (EFI_ERROR(Status)) return Status;

    LoadedImage->Unload = DxeDriverUnload;

    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (EFI_ERROR(Status) || Buf == NULL) {
        SingularityDebugPrint("SingularityDxe: AllocatePool failed\r\n");
        DriverBuffer = 0;
    } else {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
        AsciiSPrint(AsciiBuffer, sizeof(AsciiBuffer),
                    "SingularityDxe: DriverBuffer @ 0x%llx\r\n", (UINT64)DriverBuffer);
        SingularityDebugPrint(AsciiBuffer);
    }

    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER *)gRT,
                                                       (VOID **)&gRT->SetVariable,
                                                       (VOID *)HookedSetVariable);
    if (oSetVariable == NULL) return EFI_DEVICE_ERROR;

    oGetVariable = (EFI_GET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER *)gRT,
                                                       (VOID **)&gRT->GetVariable,
                                                       (VOID *)HookedGetVariable);
    if (oGetVariable == NULL) {
        // Rollback SetVariable
        SetServicePointer((EFI_TABLE_HEADER *)gRT,
                          (VOID **)&gRT->SetVariable,
                          (VOID *)oSetVariable);
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
    if (EFI_ERROR(Status)) {
        return Status;
    }

    SingularityDebugPrint("SingularityDxe: loaded\r\n");
    return EFI_SUCCESS;
}
