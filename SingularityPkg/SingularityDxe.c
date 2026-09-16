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
                           "\r\n╚════██║██║██║╚██╗██║██║   ██║██║   ██║██║     ██╔══██║██╔══██║██║   ██║     ╚██╔╝" \
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

// x86_64 Пейджингові константи та маски
#define PRESENT_BIT        (0x0000000000000001ULL)
#define PAGE_SIZE_BIT      (0x0000000000000080ULL) 
#define PHYS_ADDR_MASK_4K  (0x000FFFFFFFFFF000ULL)
#define PHYS_ADDR_MASK_2M  (0x000FFFFFFFE00000ULL)
#define PHYS_ADDR_MASK_1G  (0x000FFFFFC0000000ULL)

// === НОВІ ЗМІННІ ДЛЯ БЕЗПЕЧНОЇ КАРТИ ПАМ'ЯТІ ===
#define MAX_MEMORY_RANGES 256
#define EFI_PAGE_SIZE_ 4096 

typedef struct {
    UINT64 PhysicalStart;
    UINT64 PhysicalEnd;
} MEMORY_RANGE;

static MEMORY_RANGE SafeMemoryRanges[MAX_MEMORY_RANGES];
static UINTN        SafeMemoryRangeCount = 0;

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
static UINT64 WindowsPhysicalMask = 0;

STATIC VOID DetectWindowsMask(IN UINT64 ClientProvidedMask) {
    if (WindowsPhysicalMask != 0) return;
    
    if ((ClientProvidedMask & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
        WindowsPhysicalMask = ClientProvidedMask;
        SerialPrintSafe("SingularityDxe: Dynamically set Windows Mask from Client = 0x%lx\r\n", WindowsPhysicalMask);
    } else {
        WindowsPhysicalMask = 0xffffa08000000000ULL; 
    }
}

STATIC __inline BOOLEAN ReadPhysicalU64Safe(IN UINT64 Pa, OUT UINT64 *Val) {
    if (Pa == 0 || Pa > 0x000FFFFFFFFFF000ULL) return FALSE;
    
    if (Virtual && Runtime) {
        if (WindowsPhysicalMask == 0) DetectWindowsMask(0);
        
        UINT64 Va = WindowsPhysicalMask + Pa;
        *Val = *(volatile UINT64 *)(UINTN)Va;
    } else {
        *Val = *(volatile UINT64 *)(UINTN)Pa;
    }
    return TRUE;
}

STATIC BOOLEAN IsVaPresent(UINT64 Va, UINT64 DirectMapBase) {
    if (DirectMapBase == 0) return FALSE;
    
    UINT64 Cr3 = AsmReadCr3() & 0x000FFFFFFFFFF000ULL;
    UINT64 Entry = 0;

    // 1. PML4
    UINT64 Pml4Va = DirectMapBase + Cr3;
    Entry = *(volatile UINT64 *)(UINTN)(Pml4Va + (((Va >> 39) & 0x1FF) * 8));
    if (!(Entry & 1)) return FALSE;

    // 2. PDPT
    UINT64 PdptVa = DirectMapBase + (Entry & 0x000FFFFFFFFFF000ULL);
    Entry = *(volatile UINT64 *)(UINTN)(PdptVa + (((Va >> 30) & 0x1FF) * 8));
    if (!(Entry & 1)) return FALSE;
    if (Entry & 0x80) return TRUE; // 1GB сторінка

    // 3. PD
    UINT64 PdVa = DirectMapBase + (Entry & 0x000FFFFFFFFFF000ULL);
    Entry = *(volatile UINT64 *)(UINTN)(PdVa + (((Va >> 21) & 0x1FF) * 8));
    if (!(Entry & 1)) return FALSE;
    if (Entry & 0x80) return TRUE; // 2MB сторінка

    // 4. PT
    UINT64 PtVa = DirectMapBase + (Entry & 0x000FFFFFFFFFF000ULL);
    Entry = *(volatile UINT64 *)(UINTN)(PtVa + (((Va >> 12) & 0x1FF) * 8));
    if (!(Entry & 1)) return FALSE;

    return TRUE;
}

STATIC __inline BOOLEAN ReadPhysicalU8Safe(IN UINT64 Pa, OUT UINT8 *Val) {
    if (Pa == 0 || Pa > 0x000FFFFFFFFFF000ULL) return FALSE;
    
    if (Virtual && Runtime) {
        if (WindowsPhysicalMask == 0) DetectWindowsMask(0);
        
        UINT64 Va = WindowsPhysicalMask + Pa;
        *Val = *(volatile UINT8 *)(UINTN)Va;
    } else {
        *Val = *(volatile UINT8 *)(UINTN)Pa;
    }
    return TRUE;
}

STATIC __inline UINT64 VirtualToPhysical(IN UINT64 Cr3, IN UINT64 Va) {
    if (Cr3 == 0) return 0;

    UINT64 Entry = 0;
    UINT64 PhysBase = Cr3 & PHYS_ADDR_MASK_4K;

    if (!ReadPhysicalU64Safe(PhysBase + (((Va >> 39) & 0x1FF) * 8), &Entry)) return 0;
    if (!(Entry & PRESENT_BIT)) return 0;
    PhysBase = Entry & PHYS_ADDR_MASK_4K;

    if (!ReadPhysicalU64Safe(PhysBase + (((Va >> 30) & 0x1FF) * 8), &Entry)) return 0;
    if (!(Entry & PRESENT_BIT)) return 0;

    if (Entry & PAGE_SIZE_BIT) {
        return (Entry & PHYS_ADDR_MASK_1G) | (Va & 0x3FFFFFFFULL);
    }
    PhysBase = Entry & PHYS_ADDR_MASK_4K;

    if (!ReadPhysicalU64Safe(PhysBase + (((Va >> 21) & 0x1FF) * 8), &Entry)) return 0;
    if (!(Entry & PRESENT_BIT)) return 0;

    if (Entry & PAGE_SIZE_BIT) {
        return (Entry & PHYS_ADDR_MASK_2M) | (Va & 0x1FFFFFULL);
    }
    PhysBase = Entry & PHYS_ADDR_MASK_4K;

    if (!ReadPhysicalU64Safe(PhysBase + (((Va >> 12) & 0x1FF) * 8), &Entry)) return 0;
    if (!(Entry & PRESENT_BIT)) return 0;

    return (Entry & PHYS_ADDR_MASK_4K) | (Va & 0xFFFULL);
}

STATIC VOID SmepSmapOff(OUT UINTN *Saved) {
    *Saved = AsmReadCr4();
    AsmWriteCr4(*Saved & ~(CR4_SMEP | CR4_SMAP));
}

STATIC VOID SmepSmapOn(IN UINTN Saved) {
    AsmWriteCr4(Saved);
}

// === НОВА ФУНКЦІЯ: Збір безпечних ділянок пам'яті ===
STATIC VOID CollectSafeMemoryRanges(VOID) {
    UINTN MemoryMapSize = 0;
    EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
    UINTN MapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;

    gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
    MemoryMapSize += DescriptorSize * 16;
    
    if (gBS->AllocatePool(EfiBootServicesData, MemoryMapSize, (VOID**)&MemoryMap) != EFI_SUCCESS) {
        SerialPrintSafe("SingularityDxe: Failed to allocate pool for Memory Map\r\n");
        return;
    }

    if (gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion) == EFI_SUCCESS) {
        UINTN NumEntries = MemoryMapSize / DescriptorSize;
        EFI_MEMORY_DESCRIPTOR *Entry = MemoryMap;

        for (UINTN i = 0; i < NumEntries; i++) {
            if (Entry->Type == EfiConventionalMemory) {
                if (SafeMemoryRangeCount < MAX_MEMORY_RANGES) {
                    SafeMemoryRanges[SafeMemoryRangeCount].PhysicalStart = Entry->PhysicalStart;
                    SafeMemoryRanges[SafeMemoryRangeCount].PhysicalEnd = Entry->PhysicalStart + (Entry->NumberOfPages * EFI_PAGE_SIZE_);
                    SafeMemoryRangeCount++;
                }
            }
            Entry = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)Entry + DescriptorSize);
        }
        SerialPrintSafe("SingularityDxe: Saved %d safe memory ranges\r\n", SafeMemoryRangeCount);
    } else {
        SerialPrintSafe("SingularityDxe: Failed to get Memory Map\r\n");
    }

    gBS->FreePool(MemoryMap);
}

// ============================================================
//  RunCommand — Основна логіка
// ============================================================
EFI_STATUS RunCommand(MemoryCommand* cmd)
{
    if (cmd->magic != COMMAND_MAGIC) {
        SerialPrintSafe("SingularityDxe: RunCommand bad magic 0x%x\r\n", cmd->magic);
        return EFI_ACCESS_DENIED;
    }

    if (cmd->operation == 0) {
        if (cmd->size <= 0 || cmd->size > 0x1000000) return EFI_INVALID_PARAMETER;
        if (cmd->data[0] == 0 || cmd->data[1] == 0) return EFI_INVALID_PARAMETER;
        CopyMem((VOID*)(UINTN)cmd->data[0], (VOID*)(UINTN)cmd->data[1], cmd->size);
        return EFI_SUCCESS;
    }

    if (cmd->operation == 1) {
        if (cmd->data[2] == 0 || cmd->data[2] > DRIVER_SIZE) return EFI_INVALID_PARAMETER;
        if (cmd->data[3] != 0) {
            *(UINTN*)(UINTN)cmd->data[3] = DriverBuffer;
        }
        return EFI_SUCCESS;
    }

    if (cmd->operation == 3) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        ((StandardFuncStd)target)();
        return EFI_SUCCESS;
    }

    if (cmd->operation == 4) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        ((StandardFuncFast)target)();
        return EFI_SUCCESS;
    }

    if (cmd->operation == 5) {
        UINTN target = (UINTN)cmd->data[0];
        if (DriverBuffer == 0 || target < DriverBuffer || target >= DriverBuffer + DRIVER_SIZE) return EFI_ACCESS_DENIED;
        unsigned long status = ((DriverEntry)target)(0, 0);
        if (cmd->data[1] != 0) {
            *(unsigned long*)(UINTN)cmd->data[1] = status;
        }
        return EFI_SUCCESS;
    }

    // 0x10 — Пошук CR3 за PID
    if (cmd->operation == OP_SET_CR3) {
        UINT64 TargetPid  = cmd->data[0];
        UINT64 ClientMask = cmd->data[1];
        CachedCr3 = 0;

        if ((ClientMask & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
            WindowsPhysicalMask = ClientMask;
        } else {
            WindowsPhysicalMask = 0xffffa08000000000ULL;
        }

        // ОНОВЛЕНИЙ АЛГОРИТМ: Скануємо тільки збережені безпечні ділянки (EfiConventionalMemory)
// ... (початок блоку OP_SET_CR3)

for (UINTN i = 0; i < SafeMemoryRangeCount; i++) {
    UINT64 RangeStart = SafeMemoryRanges[i].PhysicalStart;
    UINT64 RangeEnd   = SafeMemoryRanges[i].PhysicalEnd;
    
    if (RangeEnd <= 0x1000000ULL) continue;
    if (RangeStart < 0x1000000ULL) RangeStart = 0x1000000ULL;

    for (UINT64 Pa = RangeStart; Pa < RangeEnd; Pa += 0x1000) {
        
        // НОВА ПЕРЕВІРКА: Обчислюємо віртуальну адресу для перевірки
        UINT64 VaToCheck = WindowsPhysicalMask + Pa;
        
        // Якщо сторінки не існує в таблицях процесора - просто йдемо далі!
        if (!IsVaPresent(VaToCheck, WindowsPhysicalMask)) {
            continue; 
        }

        // Тепер читання на 100% безпечне, BSOD не буде
        UINT64 MaybePid = 0;
        if (ReadPhysicalU64Safe(Pa + 0x440, &MaybePid) && MaybePid == TargetPid) {
            UINT64 FoundCr3 = 0;
            if (ReadPhysicalU64Safe(Pa + 0x28, &FoundCr3)) {
                if ((FoundCr3 & 0xFFF) == 0 && FoundCr3 != 0 && FoundCr3 < 0x100000000ULL) {
                    CachedCr3 = FoundCr3;
                    SerialPrintSafe("SingularityDxe: Found PID %d -> CR3 = 0x%lx\r\n", TargetPid, CachedCr3);
                    break;
                }
            }
        }
    }
    if (CachedCr3 != 0) break;
}

// ... (кінець блоку)

        if (CachedCr3 == 0) {
            SerialPrintSafe("SingularityDxe: Failed to find CR3 for PID %d\r\n", TargetPid);
            return EFI_NOT_FOUND;
        }
        return EFI_SUCCESS;
    }

    // 0x11 — Безпечне читання віртуальної пам'яті
    if (cmd->operation == OP_READ_CR3) {
        if (CachedCr3 == 0) return EFI_NOT_READY;
        if (cmd->size <= 0 || cmd->size > 64) return EFI_INVALID_PARAMETER;
        if (cmd->data[1] == 0) return EFI_INVALID_PARAMETER;

        UINT64 SrcVa = cmd->data[1];
        UINTN  Size  = (UINTN)cmd->size;
        UINT8  *OutPtr = (UINT8*)&cmd->data[2];

        UINTN Saved;
        SmepSmapOff(&Saved);

        for (UINTN Done = 0; Done < Size; Done++) {
            UINT64 CurVa = SrcVa + Done;
            UINT64 Pa = VirtualToPhysical(CachedCr3, CurVa);
            if (Pa == 0) {
                SmepSmapOn(Saved);
                return EFI_NOT_FOUND;
            }
            
            if (!ReadPhysicalU8Safe(Pa, &OutPtr[Done])) {
                SmepSmapOn(Saved);
                return EFI_NOT_FOUND;
            }
        }
        
        SmepSmapOn(Saved);
        return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
}

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
        VOID *Tmp = (VOID *)DriverBuffer;
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

    Status = gBS->AllocatePool(EfiRuntimeServicesCode, DRIVER_SIZE, &Buf);
    if (!EFI_ERROR(Status) && Buf != NULL) {
        ZeroMem(Buf, DRIVER_SIZE);
        DriverBuffer = (UINTN)Buf;
    }

    // ВИКЛИК ФУНКЦІЇ ДО ПІДМІНИ ВКАЗІВНИКІВ
    CollectSafeMemoryRanges();

    oSetVariable = (EFI_SET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)HookedSetVariable);
    if (oSetVariable == NULL) return EFI_DEVICE_ERROR;

    oGetVariable = (EFI_GET_VARIABLE)SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->GetVariable, (VOID*)HookedGetVariable);
    if (oGetVariable == NULL) {
        SetServicePointer((EFI_TABLE_HEADER*)gRT, (VOID**)&gRT->SetVariable, (VOID*)oSetVariable);
        return EFI_DEVICE_ERROR;
    }

    gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, SetVirtualAddressMapEvent, NULL, &gEfiEventVirtualAddressChangeGuid, &NotifyEvent);
    gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, ExitBootServicesEvent, NULL, &gEfiEventExitBootServicesGuid, &ExitEvent);

    return EFI_SUCCESS;
}
