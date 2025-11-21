using System;
using System.Security.Cryptography;
using System.Text;

namespace ABHA_HIMS.Domain.Utils
{
    /// <summary>
    /// Helper to encrypt plaintext with ABHA public certificate.
    /// Supports algorithm hint like "RSA/ECB/OAEPWithSHA-1AndMGF1Padding".
    /// Expects a PEM string (-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----)
    /// or raw base64-encoded SubjectPublicKeyInfo.
    /// </summary>
    public static class AbhaEncryptionHelper
    {
        public static string EncryptWithPublicKey(string publicKeyPemOrBase64, string plainText, string? encryptionAlgorithmHint = null)
        {
            if (string.IsNullOrWhiteSpace(publicKeyPemOrBase64)) throw new ArgumentException("publicKey empty", nameof(publicKeyPemOrBase64));
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));

            // Extract base64 portion if PEM provided
            var pem = publicKeyPemOrBase64.Trim();
            string base64;
            const string header = "-----BEGIN PUBLIC KEY-----";
            const string footer = "-----END PUBLIC KEY-----";
            if (pem.StartsWith(header, StringComparison.OrdinalIgnoreCase))
            {
                var start = pem.IndexOf(header, StringComparison.OrdinalIgnoreCase) + header.Length;
                var end = pem.IndexOf(footer, start, StringComparison.OrdinalIgnoreCase);
                if (end <= start) throw new FormatException("Invalid PEM format for public key");
                base64 = pem.Substring(start, end - start).Replace("\r", "").Replace("\n", "").Trim();
            }
            else
            {
                base64 = pem; // assume raw base64
            }

            byte[] publicKeyBytes;
            try
            {
                publicKeyBytes = Convert.FromBase64String(base64);
            }
            catch (FormatException ex)
            {
                // Provide clearer message (common user error: passing algorithm string instead of PEM)
                throw new FormatException("Public key is not a valid base64-encoded key. Ensure you passed the PEM (-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----) or raw base64 of SubjectPublicKeyInfo.", ex);
            }

            return EncryptBytes(publicKeyBytes, plainText, encryptionAlgorithmHint);
        }

        private static string EncryptBytes(byte[] publicKeyBytes, string plainText, string? encryptionAlgorithmHint = null)
        {
            using var rsa = RSA.Create();
            // import SubjectPublicKeyInfo (X.509 / PKCS#8 public key)
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            var data = Encoding.UTF8.GetBytes(plainText);

            // Choose padding: ABHA/Keycloak commonly uses OAEP with SHA-1 (OAEPWithSHA-1AndMGF1Padding).
            // If hint contains "SHA-256", choose OaepSHA256; default to OaepSHA1 for compatibility.
            RSAEncryptionPadding padding = RSAEncryptionPadding.OaepSHA1;
            if (!string.IsNullOrWhiteSpace(encryptionAlgorithmHint))
            {
                var hint = encryptionAlgorithmHint.ToUpperInvariant();
                if (hint.Contains("SHA-256")) padding = RSAEncryptionPadding.OaepSHA256;
                else if (hint.Contains("SHA-384")) padding = RSAEncryptionPadding.OaepSHA384;
                else if (hint.Contains("SHA-512")) padding = RSAEncryptionPadding.OaepSHA512;
                else padding = RSAEncryptionPadding.OaepSHA1; // fallback
            }

            var encrypted = rsa.Encrypt(data, padding);
            return Convert.ToBase64String(encrypted);
        }
    }
}
