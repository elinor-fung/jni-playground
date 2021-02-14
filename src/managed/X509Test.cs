using Internal.Cryptography.Pal;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DotNetHost
{
    public class X509Test
    {
        static void BasicProperties(string path)
        {
            Console.WriteLine($"=== {path} ===");
            var cert =  new X509Certificate2(path);
            Console.WriteLine(cert.ToString(true));

            var reader = OpenSslX509CertificateReader.FromBlob(File.ReadAllBytes(path));
            Console.WriteLine($@"
[Version]
  {reader.Version}
[Subject]
  {reader.Subject}
[Issuer]
  {reader.Issuer}
[Serial Number]
  {Convert.ToHexString(reader.SerialNumber)}
[Not Before]
  {reader.NotBefore}
[Not After]
  {reader.NotAfter}
[Thumbprint]
  {Convert.ToHexString(reader.Thumbprint)}
[Signature Algorithm]
  {reader.SignatureAlgorithm}
[Public Key]
  Algorithm: {reader.KeyAlgorithm}
  Length:
  Key Blob: {Convert.ToHexString(reader.PublicKeyValue)}
  Parameters:
[Extensions]
");
            foreach (var ext in reader.Extensions)
            {
                Console.WriteLine($"  * {ext.Oid!.FriendlyName}({ext.Oid!.Value})");
                Console.WriteLine($"    {ext.Format(true)}");
            }

            ValidateEqual(cert.Version, reader.Version, nameof(cert.Version));
            ValidateEqual(cert.Subject, reader.Subject, nameof(cert.Subject));
            ValidateEqual(cert.Issuer, reader.Issuer, nameof(cert.Issuer));
            ValidateEqual(cert.SerialNumber, Convert.ToHexString(reader.SerialNumber), nameof(cert.SerialNumber));
            ValidateEqual(cert.NotBefore, reader.NotBefore, nameof(cert.NotBefore));
            ValidateEqual(cert.NotAfter, reader.NotAfter, nameof(cert.NotAfter));
            ValidateEqual(cert.Thumbprint, Convert.ToHexString(reader.Thumbprint), nameof(cert.Thumbprint));
            ValidateEqual(cert.SignatureAlgorithm.FriendlyName, new Oid(reader.SignatureAlgorithm).FriendlyName, $"{nameof(cert.SignatureAlgorithm)}.{nameof(cert.SignatureAlgorithm.FriendlyName)}");
            ValidateEqual(cert.SignatureAlgorithm.Value, new Oid(reader.SignatureAlgorithm).Value, $"{nameof(cert.SignatureAlgorithm)}.{nameof(cert.SignatureAlgorithm.Value)}");
            ValidateEqual(cert.PublicKey.Oid.FriendlyName, reader.KeyAlgorithm, nameof(reader.KeyAlgorithm));
            ValidateEqual(cert.GetPublicKeyString(), Convert.ToHexString(reader.PublicKeyValue), nameof(reader.PublicKeyValue));
        }

        private static void ValidateEqual<T>(T? expected, T? actual, string message) where T : IComparable
        {
            if (System.Collections.Generic.EqualityComparer<T>.Default.Equals(expected, actual))
                return;

            Console.WriteLine($"{message}{Environment.NewLine}  Expected: {expected}{Environment.NewLine}  Actual: {actual}");
        }

        public static void Run()
        {
            string certPath = "[REPLACE]";
            BasicProperties(certPath);
        }
    }
}
