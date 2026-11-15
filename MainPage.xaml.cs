using BiometricIDScanner.Services;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Storage;
using System;
using System.Linq;

namespace BiometricIDScanner
{
    public partial class MainPage : ContentPage
    {
        public static MainPage? CurrentInstance { get; private set; }
        private bool _isCheckInMode = true;

        public MainPage()
        {
            InitializeComponent();
            CurrentInstance = this;

            TxtBacDocNo.Text = Preferences.Default.Get("LastBacDocNo", "035113714");
            TxtBacDob.Text = Preferences.Default.Get("LastBacDob", "910201");
            TxtBacExp.Text = Preferences.Default.Get("LastBacExp", "291113");

            TxtBacDocNo.TextChanged += OnBacInputChanged;
            TxtBacDob.TextChanged += OnBacInputChanged;
            TxtBacExp.TextChanged += OnBacInputChanged;

            RefreshAttendanceUi();
        }

        public bool IsCheckInModeActive() => _isCheckInMode;

        private void OnBacInputChanged(object? sender, TextChangedEventArgs e)
        {
            Preferences.Default.Set("LastBacDocNo", TxtBacDocNo.Text?.Trim() ?? "");
            Preferences.Default.Set("LastBacDob", TxtBacDob.Text?.Trim() ?? "");
            Preferences.Default.Set("LastBacExp", TxtBacExp.Text?.Trim() ?? "");
        }

        private void OnTabCheckInClicked(object? sender, EventArgs e)
        {
            _isCheckInMode = true;
            ViewCheckIn.IsVisible = true;
            ViewRegister.IsVisible = false;
            ViewReports.IsVisible = false;

            BtnTabCheckIn.BackgroundColor = Color.FromArgb("#0284C7");
            BtnTabCheckIn.TextColor = Colors.White;
            BtnTabRegister.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabRegister.TextColor = Color.FromArgb("#94A3B8");
            BtnTabReports.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabReports.TextColor = Color.FromArgb("#94A3B8");

            RefreshAttendanceUi();
        }

        private void OnTabRegisterClicked(object? sender, EventArgs e)
        {
            _isCheckInMode = false;
            ViewCheckIn.IsVisible = false;
            ViewRegister.IsVisible = true;
            ViewReports.IsVisible = false;

            BtnTabRegister.BackgroundColor = Color.FromArgb("#0284C7");
            BtnTabRegister.TextColor = Colors.White;
            BtnTabCheckIn.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabCheckIn.TextColor = Color.FromArgb("#94A3B8");
            BtnTabReports.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabReports.TextColor = Color.FromArgb("#94A3B8");
        }

        private void OnTabReportsClicked(object? sender, EventArgs e)
        {
            _isCheckInMode = true;
            ViewCheckIn.IsVisible = false;
            ViewRegister.IsVisible = false;
            ViewReports.IsVisible = true;

            BtnTabReports.BackgroundColor = Color.FromArgb("#0284C7");
            BtnTabReports.TextColor = Colors.White;
            BtnTabCheckIn.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabCheckIn.TextColor = Color.FromArgb("#94A3B8");
            BtnTabRegister.BackgroundColor = Color.FromArgb("#1E293B");
            BtnTabRegister.TextColor = Color.FromArgb("#94A3B8");

            RefreshAttendanceUi();
        }

        public (string DocNo, string Dob, string Exp) GetBacInputs()
        {
            return (
                TxtBacDocNo.Text?.Trim() ?? "",
                TxtBacDob.Text?.Trim() ?? "",
                TxtBacExp.Text?.Trim() ?? ""
            );
        }

        public void OnCardScanFinished(BiometricDataResult res, EmployeeRecord? emp, AttendanceLogItem? punch)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                LblStatus.Text = res.StatusMessage;
                LblStatus.TextColor = res.IsSuccess ? Color.FromArgb("#10B981") : Color.FromArgb("#F59E0B");

                TxtChipUid.Text = res.ChipUid;
                LblApduLog.Text = res.ApduTraceLog;

                if (!string.IsNullOrEmpty(res.FirstName) || !string.IsNullOrEmpty(res.LastName))
                {
                    TxtFirstName.Text = res.FirstName;
                    TxtLastName.Text = res.LastName;
                    TxtPersonalId.Text = res.PersonalNumberNid;
                    TxtDocNumber.Text = res.DocumentNumber;
                    TxtBirthDate.Text = res.BirthDate;
                    TxtGender.Text = res.Gender;
                    TxtExpiryDate.Text = res.ExpiryDate;
                    TxtNationality.Text = $"{res.Nationality} ({res.DocumentType})";
                }

                if (emp != null && punch != null)
                {
                    TerminalCard.Stroke = Color.FromArgb(punch.BadgeColor);
                    LblTerminalAction.Text = punch.IsCheckIn ? "HYRJE NË PUNË (CHECK-IN)" : "DALJE NGA PUNA (CHECK-OUT)";
                    LblTerminalAction.TextColor = Color.FromArgb(punch.BadgeColor);
                    LblTerminalEmployee.Text = $"{emp.FullName}  |  NID: {emp.PersonalNumberNid}";
                    LblTerminalTime.Text = punch.TimeFormatted + " - " + punch.DurationInfo;

                    TxtQuickName.Text = emp.FullName;
                    TxtQuickNid.Text = emp.PersonalNumberNid;
                    TxtQuickAction.Text = punch.ActionType;
                    TxtQuickAction.TextColor = Color.FromArgb(punch.BadgeColor);
                    TxtQuickTime.Text = $"{punch.Timestamp:HH:mm:ss} ({punch.DurationInfo})";
                }

                RefreshAttendanceUi();
            });
        }

        private void RefreshAttendanceUi()
        {
            var emps = AttendanceDbService.GetEmployees();
            LblRegisteredCount.Text = $"Punonjës të regjistruar në databazë: {emps.Count}";

            var logs = AttendanceDbService.GetLogs();
            LogsContainer.Children.Clear();

            if (logs.Count == 0)
            {
                LogsContainer.Children.Add(new Label
                {
                    Text = "Ende nuk ka asnjë hyrje/dalje të regjistruar. Afro kartën e ID-së pas telefonit!",
                    TextColor = Color.FromArgb("#94A3B8"),
                    FontSize = 12
                });
                return;
            }

            foreach (var item in logs.Take(50))
            {
                var card = new Border
                {
                    BackgroundColor = Color.FromArgb("#0F172A"),
                    Stroke = Color.FromArgb(item.BadgeColor),
                    StrokeThickness = 1,
                    Padding = new Thickness(12, 8)
                };

                var stack = new VerticalStackLayout { Spacing = 3 };
                stack.Children.Add(new Label
                {
                    Text = $"{item.ActionType}  •  {item.FullName} ({item.PersonalNumberNid})",
                    TextColor = Color.FromArgb(item.BadgeColor),
                    FontAttributes = FontAttributes.Bold,
                    FontSize = 13
                });
                stack.Children.Add(new Label
                {
                    Text = $"Ora: {item.TimeFormatted}  |  {item.DurationInfo}",
                    TextColor = Color.FromArgb("#CBD5E1"),
                    FontSize = 11
                });

                card.Content = stack;
                LogsContainer.Children.Add(card);
            }
        }

        private async void OnExportCsvClicked(object? sender, EventArgs e)
        {
            try
            {
                string csvPath = AttendanceDbService.ExportLogsToCsv();
                await Share.Default.RequestAsync(new ShareFileRequest
                {
                    Title = "Eksporto Raportin e Prezencës (CSV / Excel)",
                    File = new ShareFile(csvPath)
                });
            }
            catch (Exception ex)
            {
                await DisplayAlert("Gabim", ex.Message, "OK");
            }
        }

        private async void OnClearLogsClicked(object? sender, EventArgs e)
        {
            bool confirm = await DisplayAlert("Pastro Raportet", "A jeni të sigurt që doni të fshini historikun e hyrje-daljeve?", "Po", "Jo");
            if (confirm)
            {
                AttendanceDbService.ClearLogs();
                RefreshAttendanceUi();
            }
        }
    }
}
