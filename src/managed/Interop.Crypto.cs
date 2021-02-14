using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

using DotNetHost;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509Thumbprint")]
        private static extern int GetX509Thumbprint(SafeX509Handle x509, byte[]? buf, int cBuf);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509NameRawBytes")]
        private static extern int GetX509NameRawBytes(IntPtr x509Name, byte[]? buf, int cBuf);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509NotBefore")]
        internal static extern ulong GetX509NotBefore(SafeX509Handle x509);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509NotAfter")]
        internal static extern ulong GetX509NotAfter(SafeX509Handle x509);

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509Version")]
        internal static extern int GetX509Version(SafeX509Handle x509);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509SignatureAlgorithm")]
        internal static extern int GetX509SignatureAlgorithm(SafeX509Handle x509, byte[]? buf, int cBuf);
        internal static string GetX509SignatureAlgorithm(SafeX509Handle x509)
        {
            // Null terminator is included in byte array.
            byte[] oidBytes = GetDynamicBuffer((handle, buf, i) => GetX509SignatureAlgorithm(handle, buf, i), x509);
            if (oidBytes.Length <= 1)
                throw new CryptographicException();

            return System.Text.Encoding.UTF8.GetString(oidBytes[..^1]);
        }

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509PublicKeyAlgorithm")]
        internal static extern int GetX509PublicKeyAlgorithm(SafeX509Handle x509, byte[]? buf, int cBuf);
        internal static string GetX509PublicKeyAlgorithm(SafeX509Handle x509)
        {
            // Null terminator is included in byte array.
            byte[] bytes = GetDynamicBuffer((handle, buf, i) => GetX509PublicKeyAlgorithm(handle, buf, i), x509);
            if (bytes.Length <= 1)
                throw new CryptographicException();

            return System.Text.Encoding.UTF8.GetString(bytes[..^1]);
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509PublicKeyParameterBytes")]
        private static extern int GetX509PublicKeyParameterBytes(SafeX509Handle x509, byte[]? buf, int cBuf);

        // [Sig Changed]
        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509PublicKeyBytes")]
        internal static extern int GetX509PublicKeyBytes(SafeX509Handle x509, byte[]? buf, int cBuf);
        internal static byte[] GetX509PublicKeyBytes(SafeX509Handle x509)
        {
            return GetDynamicBuffer((handle, buf, i) => GetX509PublicKeyBytes(handle, buf, i), x509);
        }

        internal static byte[] GetX509Thumbprint(SafeX509Handle x509)
        {
            return GetDynamicBuffer((handle, buf, i) => GetX509Thumbprint(handle, buf, i), x509);
        }

        internal static X500DistinguishedName LoadX500Name(IntPtr namePtr)
        {
            byte[] buf = GetDynamicBuffer((ptr, buf1, i) => GetX509NameRawBytes(ptr, buf1, i), namePtr);
            return new X500DistinguishedName(buf);
        }

        internal static byte[] GetX509PublicKeyParameterBytes(SafeX509Handle x509)
        {
            return GetDynamicBuffer((handle, buf, i) => GetX509PublicKeyParameterBytes(handle, buf, i), x509);
        }

        [DllImport(nameof(bridge), EntryPoint = "CryptoNative_GetX509CrlNextUpdate")]
        internal static extern IntPtr GetX509CrlNextUpdate(SafeX509CrlHandle crl);
    }
}
