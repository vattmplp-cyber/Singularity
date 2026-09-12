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

// === Операції ===
#define OP_SET_CR3    0x10
#define OP_READ_CR3   0x11

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

static UINT64 CachedCr3 = 0;

// ---- Читання фізичної пам'яті ----
STATIC UINT64 ReadPhysicalU64(IN UINT64 Pa) {
    return *(volatile UINT64 *)(UINTN)Pa;
}

// ---- Чесна трансляція сторінок (Page Table Walk) ----
STATIC UINT64 VirtualToPhysical(IN UINT64 Cr3, IN UINT64 Va) {
    if (Cr3 == 0) return 0;

    UINT64 i4 = (Va >> 39) & 0x1FF;
    UINT64 i3 = (Va >> 30) & 0x1FF;
    UINT64 i2 = (Va >> 21) & 0x1FF;
    UINT64 i1 = (Va >> 12) & 0x1FF;
    UINT64 off = Va & 0xFFF;

    UINT64 e4 = ReadPhysicalU64((Cr3 & 0x000FFFFFFFFFF000ULL) + i4 * 8);
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

STATIC VOID SmepSmapOff(OUT UINTN *Saved) {
    *Saved = AsmReadCr4();
    AsmWriteCr4(*Saved & ~(CR4_SMEP | CR4_SMAP));
}

STATIC VOID SmepSmapOn(IN UINTN Saved) {
    AsmWriteCr4(Saved);
}

// ============================================================
//  RunCommand — Твоя основна логіка
// ============================================================
EFI_STATUS
RunCommand(MemoryCommand* cmd)
{
    if (cmd->magic != COMMAND_MAGIC) {
        SerialPrintSafe("SingularityDxe: RunCommand bad magic 0x%x\r\n", cmd->magic);
        return EFI_ACCESS_DENIED;
    }

    // 0: memcpy(dst, src, size)
    if (cmd->operation == 0) {
        if (cmd->size <= 0 || cmd->size > 0x1000000) return EFI_INVALID_PARAMETER;
        if (cmd->data[0] == 0 || cmd->data[1] == 0) return EFI_INVALID_PARAMETER;
        CopyMem((VOID*)(UINTN)cmd->data[0], (VOID*)(UINTN)cmd->data[1], cmd->size);
        return EFI_SUCCESS;
    }

    // 1: report DriverBuffer
    if (cmd->operation == 1) {
        if (cmd->data[2] == 0 || cmd->data[2] > DRIVER_SIZE) return EFI_INVALID_PARAMETER;
        if (cmd->data[3] != 0) {
            *(UINTN*)(UINTN)cmd->data[3] = DriverBuffer;
        }
        return EFI_SUCCESS;
    }

    // 3: call __stdcall
    if (cmd->operation == 3) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        ((StandardFuncStd)target)();
        return EFI_SUCCESS;
    }

    // 4: call __fastcall
    if (cmd->operation == 4) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        ((StandardFuncFast)target)();
        return EFI_SUCCESS;
    }

    // 5: invoke DriverEntry
    if (cmd->operation == 5) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        unsigned long status = ((DriverEntry)target)(0, 0);
        if (cmd->data[1] != 0) {
            *(unsigned long*)(UINTN)cmd->data[1] = status;
        }
        return EFI_SUCCESS;
    }

    // 0x10 — Передати CR3 цільового процесу (cmd->data[0] = CR3)
    if (cmd->operation == OP_SET_CR3) {
        CachedCr3 = cmd->data[0];
        SerialPrintSafe("SingularityDxe: CR3 set to 0x%lx\r\n", CachedCr3);
        return EFI_SUCCESS;
    }

    // 0x11 — Читання віртуальної пам'яті через CR3
    if (cmd->operation == OP_READ_CR3) {
        if (CachedCr3 == 0) return EFI_NOT_READY;
        if (cmd->size <= 0 || cmd->size > 0x100000) return EFI_INVALID_PARAMETER;
        if (cmd->data[0] == 0 || cmd->data[1] == 0) return EFI_INVALID_PARAMETER;

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
                return EFI_NOT_FOUND;
            }
            UINTN PageOff = (UINTN)(CurVa & 0xFFF);
            UINTN ToCopy  = 0x1000 - PageOff;
            if (ToCopy > (Size - Done)) ToCopy = Size - Done;
            
            volatile UINT8 *SrcP = (volatile UINT8 *)(UINTN)Pa;
            volatile UINT8 *DstP = (volatile UINT8 *)(UINTN)(DstVa + Done);
            for (UINTN i = 0; i < ToCopy; i++) DstP[i] = SrcP[i];
            Done += ToCopy;
        }
        SmepSmapOn(Saved);
        return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
}

// ============================================================
//  Хуки SetVariable та GetVariable
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
            if (StrnCmp(VariableName, VARIABLE_NAME, (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
                if (DataSize == 0 && Data == NULL) return EFI_SUCCESS;
                if (DataSize == sizeof(MemoryCommand) && Data != NULL) {
                    return RunCommand((MemoryCommand*)Data);
                }
            }
        }
    }
    return oSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

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
            if (StrnCmp(VariableName, VARIABLE_NAME, (sizeof(VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0) {
                if (Data == NULL || DataSize == NULL) {
                    if (DataSize != NULL) *DataSize = sizeof(MemoryCommand);
                    return EFI_BUFFER_TOO_SMALL;
                }
                if (*DataSize >= sizeof(MemoryCommand)) {
                    return RunCommand((MemoryCommand*)Data);
                }
            }
        }
    }
    return oGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

VOID
EFIAPI
SetVirtualAddressMapEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
    if (oSetVariable != NULL) gRT->ConvertPointer(0, (VOID**)&oSetVariable);
    if (oGetVariable != NULL) gRT->ConvertPointer(0, (VOID**)&oGetVariable);
    if (DriverBuffer != 0) {
        VOID *Tmp = (VOID*)DriverBuffer;
        gRT->ConvertPointer(0, &Tmp);
        DriverBuffer = (UINTN)Tmp;
    }

    NotifyEvent = NULL;
    Virtual = TRUE;
}

VOID
EFIAPI
ExitBootServicesEvent(
    IN EFI_EVENT Event,
    IN VOID*     Context
    )
{
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
    if (ServiceTableFunction == NULL || NewFunction == NULL || *ServiceTableFunction == NULL) return NULL;

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
DxeDriverUnload (IN EFI_HANDLE ImageHandle) {
  return EFI_ACCESS_DENIED;
}

// ============================================================
//  Точка входу
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

    OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
    SingularityDebugPrint("\r\n\r\n");
    SingularityPrintBanner(SINGULARITY_TITLE1);
    SingularityDebugPrint(SINGULARITY_TITLE2);
    gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

    Status = gBS->OpenProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage, ImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) return Status;

    Status = gBS->LocateProtocol(&gSingularityDriverProtocolGuid, NULL, (VOID**)&ExistingProtocol);
    if (Status != EFI_NOT_FOUND) return EFI_ALREADY_STARTED;

    gBS->InstallMultipleProtocolInterfaces(&ImageHandle, &gEfiDriverSupportedEfiVersionProtocolGuid, &gSingularitySupportedEfiVersion, NULL);
    gBS->HandleProtocol(gST->ConsoleInHandle, &gEfiSimpleTextInputExProtocolGuid, (VOID**)&gTextInputEx);
    gBS->InstallProtocolInterface(&ImageHandle, &gSingularityDriverProtocolGuid, EFI_NATIVE_INTERFACE, &gSingularityDriverProtocol);

    LoadedImage->Unload = DxeDriverUnload;

    // Виділяємо буфер
    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (!EFI_ERROR(Status) && Buf != NULL) {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
    }

    // Ставимо хуки
    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)HookedSetVariable);
    if (oSetVariable == NULL) return EFI_DEVICE_ERROR;

    oGetVariable = (EFI_GET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->GetVariable, (VOID*)HookedGetVariable);
    if (oGetVariable == NULL) {
        SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)oSetVariable);
        return EFI_DEVICE_ERROR;
    }

    // Реєструємо івенти
    gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, SetVirtualAddressMapEvent, NULL, &gEfiEventVirtualAddressChangeGuid, &NotifyEvent);
    gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, ExitBootServicesEvent, NULL, &gEfiEventExitBootServicesGuid, &ExitEvent);

    return EFI_SUCCESS;
}
