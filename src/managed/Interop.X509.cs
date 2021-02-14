using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

using DotNetHost;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [StructLayout(LayoutKind.Sequential)]
        unsafe struct X509ExtensionEntry
        {
            IntPtr Oid;
            byte* Data;
            int DataLen;
            byte IsCritical;
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_DecodeX509")]
        internal static extern SafeX509Handle DecodeX509(ref byte buf, int len);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_EncodeX509")]
        private static extern int EncodeX509(SafeX509Handle x, [Out] byte[]? buf, int len);
        internal static byte[] EncodeX509(SafeX509Handle x)
        {
            return GetDynamicBuffer((ptr, buf, i) => EncodeX509(ptr, buf, i), x);
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509Destroy")]
        internal static extern void X509Destroy(IntPtr a);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509UpRef")]
        internal static extern SafeX509Handle X509UpRef(IntPtr handle);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509UpRef")]
        internal static extern SafeX509Handle X509UpRef(SafeX509Handle handle);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509GetSerialNumber")]
        private static extern int X509GetSerialNumber(SafeX509Handle x, [Out] byte[]? buf, int len);
        internal static byte[] X509GetSerialNumber(SafeX509Handle x)
        {
            return GetDynamicBuffer((ptr, buf, i) => X509GetSerialNumber(ptr, buf, i), x);
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509GetIssuerName")]
        internal static extern IntPtr X509GetIssuerName(SafeX509Handle x);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509GetSubjectName")]
        internal static extern IntPtr X509GetSubjectName(SafeX509Handle x);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509IssuerNameHash")]
        internal static extern ulong X509IssuerNameHash(SafeX509Handle x);

        [DllImport(nameof(bridge), EntryPoint = "AndroidCryptoNative_X509EnumExtensions")]
        internal static unsafe extern void X509EnumExtensions(
            SafeX509Handle x,
            delegate* unmanaged[Cdecl]<byte*, int, byte*, int, byte, void*, void> callback,
            void* callbackContext);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509FindExtensionData")]
        private static extern int X509FindExtensionData(SafeX509Handle x, string oid, [Out] byte[]? buf, int len);
        internal static byte[] X509FindExtensionData(SafeX509Handle x, string oid)
        {
            return GetDynamicBuffer((ptr, buf, i) => X509FindExtensionData(ptr, oid, buf, i), x);
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_DecodeX509Crl")]
        internal static extern SafeX509CrlHandle DecodeX509Crl(byte[] buf, int len);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_X509CrlDestroy")]
        internal static extern void X509CrlDestroy(IntPtr a);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509SubjectPublicKeyInfoDerSize")]
        internal static extern int GetX509SubjectPublicKeyInfoDerSize(SafeX509Handle x509);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_EncodeX509SubjectPublicKeyInfo")]
        internal static extern int EncodeX509SubjectPublicKeyInfo(SafeX509Handle x509, byte[] buf);
    }
}
