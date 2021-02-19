// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    // TODO: [AndroidCrypto] Rename class to AndroidX509CertificateReader
    internal sealed class OpenSslX509CertificateReader
    {
        private SafeX509Handle _cert;
        private X500DistinguishedName? _subjectName;
        private X500DistinguishedName? _issuerName;
        private string? _subject;
        private string? _issuer;

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

        public static OpenSslX509CertificateReader FromFile(string fileName)
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);
            return FromBlob(fileBytes);
        }

        // Handles both DER and PEM
        internal static bool TryReadX509(ReadOnlySpan<byte> rawData, [NotNullWhen(true)] out OpenSslX509CertificateReader? handle)
        {
            handle = null;
            SafeX509Handle certHandle = Interop.AndroidCrypto.DecodeX509(
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

        internal static bool TryReadX509Der(ReadOnlySpan<byte> rawData, [NotNullWhen(true)] out OpenSslX509CertificateReader? certPal)
        {
            return TryReadX509(rawData, out certPal);
        }

        internal static bool TryReadX509Pem(ReadOnlySpan<byte> rawData, [NotNullWhen(true)] out OpenSslX509CertificateReader? certPal)
        {
            return TryReadX509(rawData, out certPal);
        }

        private OpenSslX509CertificateReader(SafeX509Handle handle)
        {
            _cert = handle;
        }

        public IntPtr Handle => _cert == null ? IntPtr.Zero : _cert.DangerousGetHandle();

        internal SafeX509Handle SafeHandle => _cert;

        public string Issuer
        {
            get
            {
                if (_issuer == null)
                {
                    // IssuerName is mutable to callers in X509Certificate. We want to be
                    // able to get the issuer even if IssuerName has been mutated, so we
                    // don't use it here.
                    _issuer = Interop.AndroidCrypto.X509GetIssuerName(_cert).Name;
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
                    _subject = Interop.AndroidCrypto.X509GetSubjectName(_cert).Name;
                }

                return _subject;
            }
        }

        public string LegacyIssuer => IssuerName.Decode(X500DistinguishedNameFlags.None);

        public string LegacySubject => SubjectName.Decode(X500DistinguishedNameFlags.None);

        public byte[] Thumbprint => Interop.AndroidCrypto.X509GetThumbprint(_cert);

        public string KeyAlgorithm => new Oid(Interop.AndroidCrypto.X509GetPublicKeyAlgorithm(_cert)).Value!;

        public byte[] KeyAlgorithmParameters => Interop.AndroidCrypto.X509GetPublicKeyParameterBytes(_cert);

        public byte[] PublicKeyValue
        {
            get
            {
                // AndroidCrypto returns the SubjectPublicKeyInfo - extract just the SubjectPublicKey
                byte[] bytes = Interop.AndroidCrypto.X509GetPublicKeyBytes(_cert);
                //return SubjectPublicKeyInfoAsn.Decode(bytes, AsnEncodingRules.DER).SubjectPublicKey.ToArray();
                return bytes;
            }
        }

        public byte[] SerialNumber => Interop.AndroidCrypto.X509GetSerialNumber(_cert);

        public string SignatureAlgorithm => Interop.AndroidCrypto.X509GetSignatureAlgorithm(_cert);

        public DateTime NotAfter
        {
            get
            {
                ulong msFromUnixEpoch = Interop.AndroidCrypto.X509GetNotAfter(_cert);
                return DateTime.UnixEpoch.AddMilliseconds(msFromUnixEpoch).ToLocalTime();
            }
        }

        public DateTime NotBefore
        {
            get
            {
                ulong msFromUnixEpoch = Interop.AndroidCrypto.X509GetNotBefore(_cert);
                return DateTime.UnixEpoch.AddMilliseconds(msFromUnixEpoch).ToLocalTime();
            }
        }

        public byte[] RawData => Interop.AndroidCrypto.EncodeX509(_cert);

        public int Version
        {
            get
            {
                int version = Interop.AndroidCrypto.X509GetVersion(_cert);
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
                    _subjectName = Interop.AndroidCrypto.X509GetSubjectName(_cert);
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
                    _issuerName = Interop.AndroidCrypto.X509GetIssuerName(_cert);
                }

                return _issuerName;
            }
        }

        private struct EnumExtensionsContext
        {
            public List<X509Extension> Results;
        }

        [UnmanagedCallersOnly]
        private static unsafe void EnumExtensionsCallback(byte* oid, int oidLen, byte* data, int dataLen, byte isCritical, void* context)
        {
            ref EnumExtensionsContext callbackContext = ref Unsafe.As<byte, EnumExtensionsContext>(ref *(byte*)context);
            string oidStr = Encoding.UTF8.GetString(oid, oidLen);
            byte[] rawData = AsnDecoder.ReadOctetString(new ReadOnlySpan<byte>(data, dataLen), AsnEncodingRules.DER, out _);
            bool critical = isCritical != 0;
            callbackContext.Results.Add(new X509Extension(new Oid(oidStr), rawData, critical));
        }

        public IEnumerable<X509Extension> Extensions
        {
            get
            {
                EnumExtensionsContext context = default;
                context.Results = new List<X509Extension>();
                unsafe
                {
                    Interop.AndroidCrypto.X509EnumExtensions(_cert, &EnumExtensionsCallback, Unsafe.AsPointer(ref context));
                }

                return context.Results;
            }
        }

        internal static ArraySegment<byte> FindFirstExtension(SafeX509Handle cert, string oidValue)
        {
            return Interop.AndroidCrypto.X509FindExtensionData(cert, oidValue);
        }

        public void Dispose()
        {
            if (_cert != null)
            {
                _cert.Dispose();
                _cert = null!;
            }
        }
    }
}
