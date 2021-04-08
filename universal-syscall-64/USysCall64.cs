using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;

/*
 * Author: @winternl
 */

public unsafe class USysCall64
{
    #region PINVOKE

    [DllImport("ntdll")]
    private static extern long LdrGetDllHandle(IntPtr pwPath, IntPtr unused, ref UNICODE_STRING pszModule, ref UIntPtr ldrHandle);

    #endregion

    #region STRUCTS

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct IMAGE_DOS_HEADER
    {
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions;
        public UInt32 AddressOfNames;
        public UInt32 AddressOfNameOrdinals;
    }

    #endregion

    private static readonly Dictionary<string, uint> SysCallTable;

    // TODO: Stack alignment
    private static readonly byte[] SysCallStub =
    {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, sys_no
            0x0F, 0x05,                     // syscall
            0xC3                            // retn
        };

    static unsafe USysCall64()
    {
        UNICODE_STRING szNtdll = new UNICODE_STRING("ntdll");
        UIntPtr ptrNtdll = UIntPtr.Zero;

        long ntstatus = LdrGetDllHandle(IntPtr.Zero, IntPtr.Zero, ref szNtdll, ref ptrNtdll);

        if (ntstatus != 0)
        {
            Debugger.Break();
        }

        byte* lpNtdll = (byte*)ptrNtdll;
        IMAGE_DOS_HEADER* piDH = (IMAGE_DOS_HEADER*)lpNtdll;
        IMAGE_OPTIONAL_HEADER64* piOH = (IMAGE_OPTIONAL_HEADER64*)(lpNtdll + piDH->e_lfanew + 0x18);
        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(lpNtdll + piOH->ExportTable.VirtualAddress);

        uint* names = (uint*)(lpNtdll + exportDir->AddressOfNames);
        uint* functions = (uint*)(lpNtdll + exportDir->AddressOfFunctions);
        ushort* ordinals = (ushort*)(lpNtdll + exportDir->AddressOfNameOrdinals);

        var listOfNames = new List<string>();

        var dictOfZwFunctions = new Dictionary<string, ulong>();

        for (int i = 0; i < exportDir->NumberOfNames; i++)
        {
            var name = Marshal.PtrToStringAnsi(new IntPtr(lpNtdll + names[i]));

            if (!name.StartsWith("Zw"))
            {
                continue;
            }

            var fnAddr = new UIntPtr(lpNtdll + functions[ordinals[i]]);

            dictOfZwFunctions.Add(name, fnAddr.ToUInt64());
        }

        var sortedByAddr = dictOfZwFunctions
            .OrderBy(x => x.Value)
            .ToDictionary(x => "Nt" + x.Key.Substring(2, x.Key.Length - 2), x => x.Value);

        var sysCallLookup = new Dictionary<string, uint>();

        uint sysNo = 0;

        foreach (var entry in sortedByAddr)
        {
            sysCallLookup.Add(entry.Key, sysNo);
            sysNo++;
        }

        SysCallTable = sysCallLookup;
    }

    private static unsafe T AllocRWX<T>(byte[] lpBuffer) where T : class
    {
        try
        {
            var mapName = Guid.NewGuid().ToString();
            var mapFile = MemoryMappedFile.CreateNew(mapName, lpBuffer.Length, MemoryMappedFileAccess.ReadWriteExecute);
            var mapView = mapFile.CreateViewAccessor(0, lpBuffer.Length, MemoryMappedFileAccess.ReadWriteExecute);

            mapView.WriteArray(0, lpBuffer, 0, lpBuffer.Length);

            byte* ptrShellcode = (byte*)IntPtr.Zero;
            mapView.SafeMemoryMappedViewHandle.AcquirePointer(ref ptrShellcode);

            return (T)(object)Marshal.GetDelegateForFunctionPointer((IntPtr)ptrShellcode, typeof(T));
        }
        catch
        {
            return null;
        }
    }
    private static byte[] GetSysCallStub(uint sysNo)
    {
        byte[] locBuffer = new byte[SysCallStub.Length];
        byte[] no = BitConverter.GetBytes(sysNo);

        SysCallStub.CopyTo(locBuffer, 0);
        Buffer.BlockCopy(no, 0, locBuffer, 4, 4);
        return locBuffer;
    }

    #region NTAPI Delegates

    private delegate long NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    private delegate long NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint OldAccessProtection);

    private delegate long NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten);

    #endregion

    public static IntPtr AllocateMemory(IntPtr Address, uint Size, uint AllocType, uint Protect)
    {
        return AllocateMemoryEx((IntPtr)(-1), Address, Size, AllocType, Protect);
    }

    public static IntPtr AllocateMemoryEx(IntPtr ProcessHandle, IntPtr Address, uint Size, uint AllocType, uint Protect)
    {
        var sc = GetSysCallStub(SysCallTable["NtAllocateVirtualMemory"]);

        var AllocMem = AllocRWX<NtAllocateVirtualMemory>(sc);

        if (AllocMem == null)
        {
            return IntPtr.Zero;
        }

        IntPtr baseAddress = Address;
        IntPtr regionSize = (IntPtr)Size;

        long ntStatus = AllocMem(ProcessHandle, ref baseAddress, IntPtr.Zero, ref regionSize, AllocType, Protect);

        if (ntStatus != 0)
        {
            return IntPtr.Zero;
        }
        else
        {
            return baseAddress;
        }
    }

    public static bool ProtectMemory(IntPtr Address, uint ProtectSize, uint NewProtection, ref uint OldProtection)
    {
        return ProtectMemoryEx((IntPtr)(-1), Address, ProtectSize, NewProtection, ref OldProtection);
    }

    public static bool ProtectMemoryEx(IntPtr ProcessHandle, IntPtr Address, uint ProtectSize, uint NewProtection, ref uint OldProtection)
    {
        var sc = GetSysCallStub(SysCallTable["NtProtectVirtualMemory"]);
        var ProtectMem = AllocRWX<NtProtectVirtualMemory>(sc);

        if (ProtectMem == null)
        {
            return false;
        }

        IntPtr baseAddress = Address;
        uint protSize = ProtectSize;

        long ntStatus = ProtectMem((IntPtr)ProcessHandle, ref baseAddress, ref protSize, NewProtection, ref OldProtection);

        if (ntStatus != 0)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    public static bool ProtectMemory(IntPtr Address, IntPtr Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten)
    {
        return WriteMemoryEx((IntPtr)(-1), Address, Buffer, NumberOfBytesToWrite, ref NumberOfBytesWritten);
    }

    public static bool WriteMemoryEx(IntPtr ProcessHandle, IntPtr Address, IntPtr Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten)
    {
        var sc = GetSysCallStub(SysCallTable["NtWriteVirtualMemory"]);
        var WriteMem = AllocRWX<NtWriteVirtualMemory>(sc);

        if (WriteMem == null)
        {
            return false;
        }

        long ntStatus = WriteMem(ProcessHandle, Address, Buffer, NumberOfBytesToWrite, ref NumberOfBytesWritten);

        if (ntStatus != 0 || NumberOfBytesWritten != NumberOfBytesToWrite)
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}