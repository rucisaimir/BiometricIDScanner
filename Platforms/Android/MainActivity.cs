using Android.App;
using Android.Content.PM;
using Android.Nfc;
using Android.Nfc.Tech;
using Android.OS;
using BiometricIDScanner.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BiometricIDScanner
{
    [Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTop,
        ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
    public class MainActivity : MauiAppCompatActivity, NfcAdapter.IReaderCallback
    {
        private NfcAdapter? _nfcAdapter;

        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            _nfcAdapter = NfcAdapter.GetDefaultAdapter(this);
        }

        protected override void OnResume()
        {
            base.OnResume();
            if (_nfcAdapter != null && _nfcAdapter.IsEnabled)
            {
                var flags = NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck;
                _nfcAdapter.EnableReaderMode(this, this, flags, null);
            }
        }

        protected override void OnPause()
        {
            base.OnPause();
            _nfcAdapter?.DisableReaderMode(this);
        }

        public void OnTagDiscovered(Tag? tag)
        {
            if (tag == null || MainPage.CurrentInstance == null) return;

            var result = new BiometricDataResult();
            var log = new StringBuilder();

            try
            {
                byte[] uidBytes = tag.GetId() ?? Array.Empty<byte>();
                result.ChipUid = BitConverter.ToString(uidBytes).Replace("-", ":");
                log.AppendLine($"[+] Kartë NFC u zbulua! UID: {result.ChipUid}");

                using IsoDep? isoDep = IsoDep.Get(tag);
                if (isoDep == null)
                {
                    result.StatusMessage = "Kjo kartë nuk mbështet ISO 14443-4 (IsoDep).";
                    result.ApduTraceLog = log.ToString();
                    MainPage.CurrentInstance.OnCardScanFinished(result, null, null);
                    return;
                }

                isoDep.Connect();
                isoDep.Timeout = 6000;

                byte[] selectEmrtdApdu = { 0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
                log.AppendLine($">> SELECT eMRTD: {ToHex(selectEmrtdApdu)}");
                byte[] selectResp = isoDep.Transceive(selectEmrtdApdu);
                log.AppendLine($"<< SW: {ToHex(selectResp)}");

                if (!IsSuccessSw(selectResp))
                {
                    result.StatusMessage = $"Aplikacioni eMRTD ktheu SW: {ToHex(selectResp)}";
                    result.ApduTraceLog = log.ToString();
                    MainPage.CurrentInstance.OnCardScanFinished(result, null, null);
                    return;
                }

                bool isCheckInMode = MainPage.CurrentInstance.IsCheckInModeActive();
                var employees = AttendanceDbService.GetEmployees();

                var candidateKeys = new List<(string DocNo, string Dob, string Exp, EmployeeRecord? Emp)>();
                var (uiDoc, uiDob, uiExp) = MainPage.CurrentInstance.GetBacInputs();

                if (isCheckInMode)
                {
                    var uidMatch = employees.FirstOrDefault(e => e.LastKnownChipUid == result.ChipUid);
                    if (uidMatch != null)
                        candidateKeys.Add((uidMatch.DocumentNumber, uidMatch.BirthDateYYMMDD, uidMatch.ExpiryDateYYMMDD, uidMatch));

                    foreach (var emp in employees)
                    {
                        if (uidMatch != null && emp.PersonalNumberNid == uidMatch.PersonalNumberNid) continue;
                        if (!string.IsNullOrWhiteSpace(emp.DocumentNumber) && emp.BirthDateYYMMDD.Length == 6 && emp.ExpiryDateYYMMDD.Length == 6)
                            candidateKeys.Add((emp.DocumentNumber, emp.BirthDateYYMMDD, emp.ExpiryDateYYMMDD, emp));
                    }
                }

                if (!string.IsNullOrWhiteSpace(uiDoc) && uiDob.Length == 6 && uiExp.Length == 6)
                {
                    if (!candidateKeys.Any(k => k.DocNo == uiDoc))
                        candidateKeys.Add((uiDoc, uiDob, uiExp, null));
                }

                if (candidateKeys.Count == 0)
                {
                    result.StatusMessage = "Karta nuk është e regjistruar ende! Kalo te skeda '2. Regjistro ID' dhe vendos 3 numrat BAC.";
                    result.ApduTraceLog = log.ToString();
                    MainPage.CurrentInstance.OnCardScanFinished(result, null, null);
                    return;
                }

                bool authenticated = false;
                string matchedDocNo = "";
                string matchedDob = "";
                string matchedExp = "";
                byte[]? ksEnc = null;
                byte[]? ksMac = null;
                byte[]? ssc = null;

                foreach (var cand in candidateKeys)
                {
                    byte[] getChallengeApdu = { 0x00, 0x84, 0x00, 0x00, 0x08 };
                    byte[] challengeResp = isoDep.Transceive(getChallengeApdu);
                    if (!IsSuccessSw(challengeResp) || challengeResp.Length < 10) break;

                    byte[] rndIc = challengeResp.Take(8).ToArray();
                    var (kEnc, kMac) = Icao9303BacEngine.DeriveBacKeys(cand.DocNo, cand.Dob, cand.Exp);

                    byte[] rndIfd = new byte[8];
                    byte[] kIfd = new byte[16];
                    RandomNumberGenerator.Fill(rndIfd);
                    RandomNumberGenerator.Fill(kIfd);

                    byte[] s = new byte[32];
                    Array.Copy(rndIfd, 0, s, 0, 8);
                    Array.Copy(rndIc, 0, s, 8, 8);
                    Array.Copy(kIfd, 0, s, 16, 16);

                    byte[] eIfd = Icao9303BacEngine.Encrypt3DesCbc(s, kEnc);
                    byte[] mIfd = Icao9303BacEngine.ComputeMac(eIfd, kMac);

                    byte[] extAuthApdu = new byte[46];
                    extAuthApdu[0] = 0x00;
                    extAuthApdu[1] = 0x82;
                    extAuthApdu[2] = 0x00;
                    extAuthApdu[3] = 0x00;
                    extAuthApdu[4] = 0x28;
                    Array.Copy(eIfd, 0, extAuthApdu, 5, 32);
                    Array.Copy(mIfd, 0, extAuthApdu, 37, 8);
                    extAuthApdu[45] = 0x28;

                    byte[] authResp = isoDep.Transceive(extAuthApdu);
                    if (IsSuccessSw(authResp) && authResp.Length >= 42)
                    {
                        authenticated = true;
                        matchedDocNo = cand.DocNo;
                        matchedDob = cand.Dob;
                        matchedExp = cand.Exp;

                        byte[] eIc = authResp.Take(32).ToArray();
                        byte[] rDecrypted = Icao9303BacEngine.Decrypt3DesCbc(eIc, kEnc);
                        byte[] kIc = rDecrypted.Skip(16).Take(16).ToArray();
                        (ksEnc, ksMac, ssc) = Icao9303BacEngine.DeriveSessionKeys(kIfd, kIc, rndIc, rndIfd);
                        log.AppendLine($"[+] Autentikimi Kriptografik BAC & Sesioni 3DES u krye me sukses (Dok: {matchedDocNo})!");
                        break;
                    }
                    else
                    {
                        isoDep.Transceive(selectEmrtdApdu);
                    }
                }

                if (!authenticated || ksEnc == null || ksMac == null || ssc == null)
                {
                    result.StatusMessage = "Karta nuk u zhbllokua dot. Kontrollo 3 numrat BAC te skeda '2. Regjistro ID'.";
                    result.ApduTraceLog = log.ToString();
                    MainPage.CurrentInstance.OnCardScanFinished(result, null, null);
                    return;
                }

                var dg1FullBytes = new List<byte>();
                byte[] offsets = { 0x00, 0x24, 0x48 };
                foreach (byte offset in offsets)
                {
                    byte p1 = (offset == 0x00) ? (byte)0x81 : (byte)0x00;
                    byte[] smReadApdu = Icao9303BacEngine.WrapSecureMessagingApdu(0xB0, p1, offset, 0x24, ksEnc, ksMac, ssc);
                    byte[] smResp = isoDep.Transceive(smReadApdu);
                    if (IsSuccessSw(smResp))
                    {
                        byte[] chunk = Icao9303BacEngine.UnwrapSecureMessagingResponse(smResp, ksEnc, ssc);
                        dg1FullBytes.AddRange(chunk);
                    }
                }

                if (dg1FullBytes.Count > 0)
                {
                    string asciiMrz = Encoding.ASCII.GetString(dg1FullBytes.ToArray());
                    log.AppendLine($"[+] EF.DG1 MRZ u dekriptua ({dg1FullBytes.Count} bytes)");
                    Icao9303BacEngine.ParseDg1Mrz(asciiMrz, result);
                }

                EmployeeRecord? empRecord = null;
                AttendanceLogItem? punchLog = null;

                if (!string.IsNullOrEmpty(result.FirstName) || !string.IsNullOrEmpty(result.LastName))
                {
                    empRecord = new EmployeeRecord
                    {
                        PersonalNumberNid = result.PersonalNumberNid,
                        FirstName = result.FirstName,
                        LastName = result.LastName,
                        DocumentNumber = !string.IsNullOrEmpty(result.DocumentNumber) ? result.DocumentNumber : matchedDocNo,
                        BirthDateYYMMDD = matchedDob,
                        ExpiryDateYYMMDD = matchedExp,
                        BirthDateFormatted = result.BirthDate,
                        Gender = result.Gender,
                        Nationality = result.Nationality,
                        LastKnownChipUid = result.ChipUid
                    };
                    AttendanceDbService.SaveEmployee(empRecord);
                    punchLog = AttendanceDbService.PunchAttendance(empRecord, result.ChipUid);
                }

                try
                {
                    var vibrator = (Vibrator?)GetSystemService(VibratorService);
                    vibrator?.Vibrate(VibrationEffect.CreateOneShot(180, VibrationEffect.DefaultAmplitude));
                }
                catch { }

                result.IsSuccess = true;
                result.StatusMessage = punchLog != null
                    ? $"{punchLog.ActionType}: {empRecord?.FullName} ({punchLog.Timestamp:HH:mm:ss})"
                    : "Leximi dhe Dekriptimi i EF.DG1 përfundoi me sukses!";
                result.ApduTraceLog = log.ToString();

                MainPage.CurrentInstance.OnCardScanFinished(result, empRecord, punchLog);
            }
            catch (Exception ex)
            {
                result.IsSuccess = false;
                result.StatusMessage = $"Gabim gjatë komunikimit NFC: {ex.Message}";
                result.ApduTraceLog = log.AppendLine(ex.Message).ToString();
                MainPage.CurrentInstance.OnCardScanFinished(result, null, null);
            }
        }

        private static bool IsSuccessSw(byte[] resp)
        {
            return resp != null && resp.Length >= 2 &&
                   resp[resp.Length - 2] == 0x90 && resp[resp.Length - 1] == 0x00;
        }

        private static string ToHex(byte[] data) => BitConverter.ToString(data).Replace("-", " ");
    }
}
