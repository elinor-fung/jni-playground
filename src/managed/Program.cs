using System;
using System.Runtime.InteropServices;

namespace DotNetHost
{
    internal static class bridge
    {
        [DllImport(nameof(bridge), CallingConvention = CallingConvention.Cdecl)]
        public static extern byte create_jvm();

        [DllImport(nameof(bridge), CallingConvention = CallingConvention.Cdecl)]
        public static extern void destroy_jvm();

        [DllImport(nameof(bridge), CallingConvention = CallingConvention.Cdecl)]
        public static extern void print_version();
    }

    class Program
    {
        static void Main(string[] args)
        {
            bridge.create_jvm();
            try
            {
                bridge.print_version();
                Console.WriteLine();

                X509Test.Run();
            }
            finally
            {
                bridge.destroy_jvm();
            }
        }
    }
}
