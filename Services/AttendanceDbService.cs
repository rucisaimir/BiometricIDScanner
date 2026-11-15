using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Maui.Storage;

namespace BiometricIDScanner.Services
{
    public class EmployeeRecord
    {
        public string PersonalNumberNid { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string DocumentNumber { get; set; } = string.Empty;
        public string BirthDateYYMMDD { get; set; } = string.Empty;
        public string ExpiryDateYYMMDD { get; set; } = string.Empty;
        public string BirthDateFormatted { get; set; } = string.Empty;
        public string Gender { get; set; } = string.Empty;
        public string Nationality { get; set; } = string.Empty;
        public string LastKnownChipUid { get; set; } = string.Empty;
        public DateTime RegisteredAt { get; set; } = DateTime.Now;

        public string FullName => $"{FirstName} {LastName}".Trim();
    }

    public class AttendanceLogItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string PersonalNumberNid { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string ActionType { get; set; } = "CHECK-IN";
        public bool IsCheckIn { get; set; } = true;
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string ChipUid { get; set; } = string.Empty;
        public string DurationInfo { get; set; } = string.Empty;

        public string TimeFormatted => Timestamp.ToString("dd.MM.yyyy HH:mm:ss");
        public string BadgeColor => IsCheckIn ? "#10B981" : "#F59E0B";
    }

    public static class AttendanceDbService
    {
        private static readonly string EmpFile = Path.Combine(FileSystem.AppDataDirectory, "employees_v6.json");
        private static readonly string LogsFile = Path.Combine(FileSystem.AppDataDirectory, "attendance_logs_v6.json");

        public static List<EmployeeRecord> GetEmployees()
        {
            try
            {
                if (!File.Exists(EmpFile)) return new List<EmployeeRecord>();
                string json = File.ReadAllText(EmpFile);
                return JsonSerializer.Deserialize<List<EmployeeRecord>>(json) ?? new List<EmployeeRecord>();
            }
            catch
            {
                return new List<EmployeeRecord>();
            }
        }

        public static void SaveEmployee(EmployeeRecord emp)
        {
            var list = GetEmployees();
            var existing = list.FirstOrDefault(x =>
                (!string.IsNullOrEmpty(emp.PersonalNumberNid) && x.PersonalNumberNid == emp.PersonalNumberNid) ||
                (!string.IsNullOrEmpty(emp.DocumentNumber) && x.DocumentNumber == emp.DocumentNumber));

            if (existing != null)
            {
                existing.FirstName = emp.FirstName;
                existing.LastName = emp.LastName;
                existing.DocumentNumber = emp.DocumentNumber;
                existing.BirthDateYYMMDD = emp.BirthDateYYMMDD;
                existing.ExpiryDateYYMMDD = emp.ExpiryDateYYMMDD;
                existing.BirthDateFormatted = emp.BirthDateFormatted;
                existing.Gender = emp.Gender;
                existing.Nationality = emp.Nationality;
                existing.LastKnownChipUid = emp.LastKnownChipUid;
            }
            else
            {
                list.Add(emp);
            }

            File.WriteAllText(EmpFile, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
        }

        public static List<AttendanceLogItem> GetLogs()
        {
            try
            {
                if (!File.Exists(LogsFile)) return new List<AttendanceLogItem>();
                string json = File.ReadAllText(LogsFile);
                var list = JsonSerializer.Deserialize<List<AttendanceLogItem>>(json) ?? new List<AttendanceLogItem>();
                return list.OrderByDescending(x => x.Timestamp).ToList();
            }
            catch
            {
                return new List<AttendanceLogItem>();
            }
        }

        public static AttendanceLogItem PunchAttendance(EmployeeRecord emp, string chipUid)
        {
            var logs = GetLogs();
            var lastEmpLog = logs.FirstOrDefault(x => x.PersonalNumberNid == emp.PersonalNumberNid);

            bool isCheckIn = true;
            string durationText = "Filloi turnin e punës";

            if (lastEmpLog != null && lastEmpLog.IsCheckIn && lastEmpLog.Timestamp.Date == DateTime.Now.Date)
            {
                isCheckIn = false;
                TimeSpan worked = DateTime.Now - lastEmpLog.Timestamp;
                if (worked.TotalHours >= 1)
                    durationText = $"Kohëzgjatja në punë: {(int)worked.TotalHours} orë e {worked.Minutes} min ({worked.Seconds} sek)";
                else
                    durationText = $"Kohëzgjatja në punë: {worked.Minutes} min e {worked.Seconds} sek";
            }

            var newLog = new AttendanceLogItem
            {
                PersonalNumberNid = emp.PersonalNumberNid,
                FullName = emp.FullName,
                IsCheckIn = isCheckIn,
                ActionType = isCheckIn ? "HYRJE (CHECK-IN)" : "DALJE (CHECK-OUT)",
                Timestamp = DateTime.Now,
                ChipUid = chipUid,
                DurationInfo = durationText
            };

            logs.Insert(0, newLog);
            File.WriteAllText(LogsFile, JsonSerializer.Serialize(logs, new JsonSerializerOptions { WriteIndented = true }));
            return newLog;
        }

        public static void ClearLogs()
        {
            if (File.Exists(LogsFile)) File.Delete(LogsFile);
        }

        public static string ExportLogsToCsv()
        {
            var logs = GetLogs();
            var sb = new StringBuilder();
            sb.AppendLine("Data dhe Ora,Punonjesi,NID,Veprimi,Kohezgjatja,UID Cipi");
            foreach (var l in logs)
            {
                string row = string.Join(",",
                     EscapeCsv(l.TimeFormatted),
                     EscapeCsv(l.FullName),
                     EscapeCsv(l.PersonalNumberNid),
                     EscapeCsv(l.ActionType),
                     EscapeCsv(l.DurationInfo),
                     EscapeCsv(l.ChipUid));
                sb.AppendLine(row);
            }
            string filePath = Path.Combine(FileSystem.CacheDirectory, $"Raporti_Prezences_{DateTime.Now:yyyyMMdd_HHmm}.csv");
            File.WriteAllText(filePath, sb.ToString(), Encoding.UTF8);
            return filePath;
        }

        private static string EscapeCsv(string val)
        {
            if (string.IsNullOrEmpty(val)) return "";
            return "\"" + val.Replace("\"", "\"\"") + "\"";
        }
    }
}
