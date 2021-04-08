using System;
using System.Diagnostics;

namespace winternl
{
    class Program
    {
        static void Main(string[] args)
        {
            if (IntPtr.Size == 4)
            {
                return;
            }

            uint dwOld = 0;
            IntPtr allocMem = USysCall64.AllocateMemory((IntPtr)0, 0x1000, 0x00001000, 0x40);
            bool bSuccess = USysCall64.ProtectMemory(allocMem, 0x1000, 0x10, ref dwOld);

            Debugger.Break();
        }
    }
}