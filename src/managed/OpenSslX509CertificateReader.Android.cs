using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed class OpenSslX509CertificateReader
    {
        private SafeX509Handle _cert;
        private X500DistinguishedName? _subjectName;
        private X500DistinguishedName? _issuerName;
        private string? _subject;
        private string? _issuer;

        public static OpenSslX509CertificateReader FromHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(nameof(handle));

            return new OpenSslX509CertificateReader(Interop.Crypto.X509UpRef(handle));
        }

        // [TODO] Pkcs7, Pkcs12
        public static OpenSslX509CertificateReader FromBlob(ReadOnlySpan<byte> rawData)
        {
            OpenSslX509CertificateReader? cert;
            if (TryReadX509(rawData, out cert))
            {
                if (cert == null)
                {
                    // Empty collection, most likely.
                    throw new CryptographicException();
                }

                return cert;
            }

            // Unsupported
            throw new CryptographicException();
        }

        // Handles both DER and PEM
        internal static bool TryReadX509(ReadOnlySpan<byte> rawData, [NotNullWhen(true)] out OpenSslX509CertificateReader? handle)
        {
            handle = null;
            SafeX509Handle certHandle = Interop.Crypto.DecodeX509(
                ref MemoryMarshal.GetReference(rawData),
                rawData.Length);

            if (certHandle.IsInvalid)
            {
                certHandle.Dispose();
                return false;
            }

            handle = new OpenSslX509CertificateReader(certHandle);
            return true;
        }

        internal OpenSslX509CertificateReader(SafeX509Handle handle)
        {
            _cert = handle;
        }

        public IntPtr Handle
        {
            get { return _cert == null ? IntPtr.Zero : _cert.DangerousGetHandle(); }
        }

        internal SafeX509Handle SafeHandle
        {
            get { return _cert; }
        }

        public string Issuer
        {
            get
            {
                if (_issuer == null)
                {
                    // IssuerName is mutable to callers in X509Certificate. We want to be
                    // able to get the issuer even if IssuerName has been mutated, so we
                    // don't use it here.
                    _issuer = Interop.Crypto.LoadX500Name(Interop.Crypto.X509GetIssuerName(_cert)).Name;
                }

                return _issuer;
            }
        }

        public string Subject
        {
            get
            {
                if (_subject == null)
                {
                    // SubjectName is mutable to callers in X509Certificate. We want to be
                    // able to get the subject even if SubjectName has been mutated, so we
                    // don't use it here.
                    _subject = Interop.Crypto.LoadX500Name(Interop.Crypto.X509GetSubjectName(_cert)).Name;
                }

                return _subject;
            }
        }

        public string LegacyIssuer => IssuerName.Decode(X500DistinguishedNameFlags.None);

        public string LegacySubject => SubjectName.Decode(X500DistinguishedNameFlags.None);

        public byte[] Thumbprint
        {
            get
            {
                return Interop.Crypto.GetX509Thumbprint(_cert);
            }
        }

        public string KeyAlgorithm
        {
            get
            {
                // Length - 1 for null terminator included in byte array.
                return new Oid(Interop.Crypto.GetX509PublicKeyAlgorithm(_cert)).FriendlyName;
            }
        }

        public byte[] KeyAlgorithmParameters
        {
            get
            {
                return Interop.Crypto.GetX509PublicKeyParameterBytes(_cert);
            }
        }

        public byte[] PublicKeyValue
        {
            get
            {
                return Interop.Crypto.GetX509PublicKeyBytes(_cert);
            }
        }

        public byte[] SerialNumber
        {
            get
            {
                return Interop.Crypto.X509GetSerialNumber(_cert);
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                return Interop.Crypto.GetX509SignatureAlgorithm(_cert);
            }
        }

        public DateTime NotAfter
        {
            get
            {
                ulong msFromUnixEpoch = Interop.Crypto.GetX509NotAfter(_cert);
                return DateTime.UnixEpoch.AddMilliseconds(msFromUnixEpoch).ToLocalTime();
            }
        }

        public DateTime NotBefore
        {
            get
            {
                ulong msFromUnixEpoch = Interop.Crypto.GetX509NotBefore(_cert);
                return DateTime.UnixEpoch.AddMilliseconds(msFromUnixEpoch).ToLocalTime();
            }
        }

        public byte[] RawData
        {
            get
            {
                return Interop.Crypto.EncodeX509(_cert);
            }
        }

        public int Version
        {
            get
            {
                int version = Interop.Crypto.GetX509Version(_cert);

                if (version < 0)
                {
                    throw new CryptographicException();
                }

                return version;
            }
        }

        public X500DistinguishedName SubjectName
        {
            get
            {
                if (_subjectName == null)
                {
                    _subjectName = Interop.Crypto.LoadX500Name(Interop.Crypto.X509GetSubjectName(_cert));
                }

                return _subjectName;
            }
        }

        public X500DistinguishedName IssuerName
        {
            get
            {
                if (_issuerName == null)
                {
                    _issuerName = Interop.Crypto.LoadX500Name(Interop.Crypto.X509GetIssuerName(_cert));
                }

                return _issuerName;
            }
        }

        private struct EnumExtensionsContext
        {
            public List<X509Extension> Results;
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static unsafe void EnumExtensionsCallback(byte* oid, int oidLen, byte* data, int dataLen, byte isCritical, void* context)
        {
            ref EnumExtensionsContext callbackContext = ref Unsafe.As<byte, EnumExtensionsContext>(ref *(byte*)context);
            string oidStr = Encoding.UTF8.GetString(oid, oidLen);
            byte[] rawData = new ReadOnlySpan<byte>(data, dataLen).ToArray();
            bool critical = isCritical != 0;
            callbackContext.Results.Add(new X509Extension(new Oid(oidStr), rawData, critical));
        }

        public IEnumerable<X509Extension> Extensions
        {
            get
            {
                EnumExtensionsContext context;
                context.Results = new List<X509Extension>();
                unsafe
                {
                    Interop.Crypto.X509EnumExtensions(_cert, &EnumExtensionsCallback, Unsafe.AsPointer(ref context));
                }

                return context.Results;
            }
        }

        internal static ArraySegment<byte> FindFirstExtension(SafeX509Handle cert, string oidValue)
        {
            return Interop.Crypto.X509FindExtensionData(cert, oidValue);
        }

        public void Dispose()
        {
            if (_cert != null)
            {
                _cert.Dispose();
                _cert = null!;
            }
        }

        internal OpenSslX509CertificateReader DuplicateHandles()
        {
            SafeX509Handle certHandle = Interop.Crypto.X509UpRef(_cert);
            OpenSslX509CertificateReader duplicate = new OpenSslX509CertificateReader(certHandle);
            return duplicate;
        }
    }
}
