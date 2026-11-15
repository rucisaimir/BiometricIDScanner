using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BiometricIDScanner.Services
{
    public class BiometricDataResult
    {
        public bool IsSuccess { get; set; }
        public string StatusMessage { get; set; } = string.Empty;
        public string ChipUid { get; set; } = string.Empty;
        public string DocumentType { get; set; } = string.Empty;
        public string IssuingState { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string DocumentNumber { get; set; } = string.Empty;
        public string PersonalNumberNid { get; set; } = string.Empty;
        public string BirthDate { get; set; } = string.Empty;
        public string Gender { get; set; } = string.Empty;
        public string ExpiryDate { get; set; } = string.Empty;
        public string Nationality { get; set; } = string.Empty;
        public string RawMrz { get; set; } = string.Empty;
        public string ApduTraceLog { get; set; } = string.Empty;
    }

    public static class Icao9303BacEngine
    {
        public static char ComputeCheckDigit(string input)
        {
            int[] weights = { 7, 3, 1 };
            int sum = 0;
            for (int i = 0; i < input.Length; i++)
            {
                char c = char.ToUpperInvariant(input[i]);
                int val = 0;
                if (c >= '0' && c <= '9') val = c - '0';
                else if (c >= 'A' && c <= 'Z') val = c - 'A' + 10;
                else if (c == '<') val = 0;
                sum += val * weights[i % 3];
            }
            return (char)('0' + (sum % 10));
        }

        public static (byte[] KEnc, byte[] KMac) DeriveBacKeys(string docNumber, string birthDateYYMMDD, string expiryDateYYMMDD)
        {
            string cleanDoc = docNumber.Trim().ToUpperInvariant().PadRight(9, '<');
            char docCheck = ComputeCheckDigit(cleanDoc);
            char dobCheck = ComputeCheckDigit(birthDateYYMMDD);
            char expCheck = ComputeCheckDigit(expiryDateYYMMDD);

            string mrzInfo = $"{cleanDoc}{docCheck}{birthDateYYMMDD}{dobCheck}{expiryDateYYMMDD}{expCheck}";
            byte[] kSeed = new byte[16];
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(mrzInfo));
                Array.Copy(hash, 0, kSeed, 0, 16);
            }

            byte[] kEnc = Derive3DesKey(kSeed, 1);
            byte[] kMac = Derive3DesKey(kSeed, 2);
            return (kEnc, kMac);
        }

        public static (byte[] KsEnc, byte[] KsMac, byte[] Ssc) DeriveSessionKeys(byte[] kIfd, byte[] kIc, byte[] rndIc, byte[] rndIfd)
        {
            byte[] kSeed = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                kSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
            }

            byte[] ksEnc = Derive3DesKey(kSeed, 1);
            byte[] ksMac = Derive3DesKey(kSeed, 2);

            byte[] ssc = new byte[8];
            Array.Copy(rndIc, 4, ssc, 0, 4);
            Array.Copy(rndIfd, 4, ssc, 4, 4);

            return (ksEnc, ksMac, ssc);
        }

        public static void IncrementSsc(byte[] ssc)
        {
            for (int i = 7; i >= 0; i--)
            {
                if (++ssc[i] != 0)
                    break;
            }
        }

        public static byte[] WrapSecureMessagingApdu(byte ins, byte p1, byte p2, byte le, byte[] ksEnc, byte[] ksMac, byte[] ssc)
        {
            IncrementSsc(ssc);

            byte[] cmdHeaderPadded = { 0x0C, ins, p1, p2, 0x80, 0x00, 0x00, 0x00 };
            byte[] do97 = { 0x97, 0x01, le };

            byte[] m = new byte[8 + 8 + 3];
            Array.Copy(ssc, 0, m, 0, 8);
            Array.Copy(cmdHeaderPadded, 0, m, 8, 8);
            Array.Copy(do97, 0, m, 16, 3);

            byte[] mac = ComputeMac(m, ksMac);
            byte[] do8E = new byte[10];
            do8E[0] = 0x8E;
            do8E[1] = 0x08;
            Array.Copy(mac, 0, do8E, 2, 8);

            byte[] apdu = new byte[5 + do97.Length + do8E.Length + 1];
            apdu[0] = 0x0C;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;
            apdu[4] = (byte)(do97.Length + do8E.Length);
            Array.Copy(do97, 0, apdu, 5, do97.Length);
            Array.Copy(do8E, 0, apdu, 5 + do97.Length, do8E.Length);
            apdu[apdu.Length - 1] = 0x00;

            return apdu;
        }

        public static byte[] UnwrapSecureMessagingResponse(byte[] resp, byte[] ksEnc, byte[] ssc)
        {
            IncrementSsc(ssc);
            if (resp == null || resp.Length < 4) return Array.Empty<byte>();

            int idx = 0;
            if (resp[idx] == 0x87)
            {
                idx++;
                int len = resp[idx++];
                if (len == 0x81) len = resp[idx++];
                else if (len == 0x82) { len = (resp[idx] << 8) | resp[idx + 1]; idx += 2; }

                if (resp[idx] == 0x01)
                {
                    idx++;
                    len--;
                }

                byte[] encData = new byte[len];
                Array.Copy(resp, idx, encData, 0, len);
                byte[] decPadded = Decrypt3DesCbc(encData, ksEnc);

                int padIdx = decPadded.Length - 1;
                while (padIdx >= 0 && decPadded[padIdx] == 0x00) padIdx--;
                if (padIdx >= 0 && decPadded[padIdx] == 0x80)
                {
                    return decPadded.Take(padIdx).ToArray();
                }
                return decPadded;
            }
            return Array.Empty<byte>();
        }

        private static byte[] Derive3DesKey(byte[] kSeed, int counter)
        {
            byte[] data = new byte[20];
            Array.Copy(kSeed, 0, data, 0, 16);
            data[19] = (byte)counter;

            using SHA1 sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(data);

            byte[] key = new byte[16];
            Array.Copy(hash, 0, key, 0, 16);
            AdjustParity(key);
            return key;
        }

        private static void AdjustParity(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                int b = key[i] & 0xFE;
                int parity = 0;
                for (int j = 1; j < 8; j++)
                {
                    parity ^= (b >> j) & 1;
                }
                key[i] = (byte)(b | (parity ^ 1));
            }
        }

        public static byte[] Encrypt3DesCbc(byte[] data, byte[] key16)
        {
            using TripleDES tdes = TripleDES.Create();
            byte[] key24 = new byte[24];
            Array.Copy(key16, 0, key24, 0, 16);
            Array.Copy(key16, 0, key24, 16, 8);
            tdes.Key = key24;
            tdes.IV = new byte[8];
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            using ICryptoTransform enc = tdes.CreateEncryptor();
            return enc.TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] Decrypt3DesCbc(byte[] data, byte[] key16)
        {
            using TripleDES tdes = TripleDES.Create();
            byte[] key24 = new byte[24];
            Array.Copy(key16, 0, key24, 0, 16);
            Array.Copy(key16, 0, key24, 16, 8);
            tdes.Key = key24;
            tdes.IV = new byte[8];
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            using ICryptoTransform dec = tdes.CreateDecryptor();
            return dec.TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] ComputeMac(byte[] data, byte[] kMac16)
        {
            byte[] k1 = kMac16.Take(8).ToArray();
            byte[] k2 = kMac16.Skip(8).ToArray();

            int padLen = 8 - (data.Length % 8);
            byte[] padded = new byte[data.Length + padLen];
            Array.Copy(data, padded, data.Length);
            padded[data.Length] = 0x80;

            using DES des1 = DES.Create();
            des1.Key = k1;
            des1.Mode = CipherMode.ECB;
            des1.Padding = PaddingMode.None;

            using DES des2 = DES.Create();
            des2.Key = k2;
            des2.Mode = CipherMode.ECB;
            des2.Padding = PaddingMode.None;

            using ICryptoTransform enc1 = des1.CreateEncryptor();
            using ICryptoTransform dec2 = des2.CreateDecryptor();

            byte[] block = new byte[8];
            for (int i = 0; i < padded.Length; i += 8)
            {
                for (int j = 0; j < 8; j++)
                    block[j] ^= padded[i + j];
                block = enc1.TransformFinalBlock(block, 0, 8);
            }

            block = dec2.TransformFinalBlock(block, 0, 8);
            return enc1.TransformFinalBlock(block, 0, 8);
        }

        public static void ParseDg1Mrz(string mrz, BiometricDataResult result)
        {
            result.RawMrz = mrz;
            var sb = new StringBuilder();
            foreach (char c in mrz)
            {
                if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '<')
                    sb.Append(c);
            }
            string clean = sb.ToString();

            int idx = clean.IndexOf("IDALB", StringComparison.Ordinal);
            if (idx < 0) idx = clean.IndexOf("I<ALB", StringComparison.Ordinal);
            if (idx < 0) idx = clean.IndexOf("P<ALB", StringComparison.Ordinal);
            if (idx > 0) clean = clean.Substring(idx);

            if (clean.Length >= 90 && (clean.StartsWith("I") || clean.StartsWith("A") || clean.StartsWith("C")))
            {
                string line1 = clean.Substring(0, 30);
                string line2 = clean.Substring(30, 30);
                string line3 = clean.Substring(60, 30);

                result.DocumentType = line1.Substring(0, 2).Trim('<');
                result.IssuingState = line1.Substring(2, 3).Trim('<');
                result.DocumentNumber = line1.Substring(5, 9).Trim('<');
                result.PersonalNumberNid = line1.Substring(15, 15).Trim('<');

                result.BirthDate = FormatMrzDate(line2.Substring(0, 6), isExpiry: false);
                result.Gender = line2.Substring(7, 1) == "M" ? "Mashkull (M)" : (line2.Substring(7, 1) == "F" ? "Femër (F)" : line2.Substring(7, 1));
                result.ExpiryDate = FormatMrzDate(line2.Substring(8, 6), isExpiry: true);
                result.Nationality = line2.Substring(15, 3).Trim('<');

                ParseNameLine(line3, result);
            }
            else if (clean.Length >= 88)
            {
                string line1 = clean.Substring(0, 44);
                string line2 = clean.Substring(44, 44);

                result.DocumentType = line1.Substring(0, 2).Trim('<');
                result.IssuingState = line1.Substring(2, 3).Trim('<');
                ParseNameLine(line1.Substring(5, 39), result);

                result.DocumentNumber = line1.Substring(0, 9).Trim('<');
                result.Nationality = line2.Substring(10, 3).Trim('<');
                result.BirthDate = FormatMrzDate(line2.Substring(13, 6), isExpiry: false);
                result.Gender = line2.Substring(20, 1) == "M" ? "Mashkull (M)" : "Femër (F)";
                result.ExpiryDate = FormatMrzDate(line2.Substring(21, 6), isExpiry: true);
                result.PersonalNumberNid = line2.Substring(28, 14).Trim('<');
            }
        }

        private static void ParseNameLine(string nameField, BiometricDataResult result)
        {
            string[] parts = nameField.Split(new[] { "<<" }, StringSplitOptions.None);
            result.LastName = parts[0].Replace('<', ' ').Trim();
            if (parts.Length > 1)
            {
                result.FirstName = parts[1].Replace('<', ' ').Trim();
            }
        }

        private static string FormatMrzDate(string yymmdd, bool isExpiry)
        {
            if (yymmdd.Length != 6 || !int.TryParse(yymmdd.Substring(0, 2), out int yy))
                return yymmdd;
            string mm = yymmdd.Substring(2, 2);
            string dd = yymmdd.Substring(4, 2);
            int year = isExpiry ? (2000 + yy) : (yy > 35 ? 1900 + yy : 2000 + yy);
            return $"{dd}.{mm}.{year}";
        }
    }
}
