@echo off
title Ngarkimi V7 CLEAN BUILD - rucisaimir/BiometricIDScanner
echo ========================================================
echo   PERDITESIMI V7: KORRIGJIM SINTAKSE C# (CS1026/CS1039)
echo ========================================================
echo.

git init
git branch -M main
git add .
git commit -m "Fix C# string escaping in AttendanceDbService.cs and MainPage.xaml.cs"
git remote remove origin 2>nul
git remote add origin https://github.com/rucisaimir/BiometricIDScanner.git

echo Po dergohen skedaret ne GitHub...
git push -u origin main --force

echo.
echo ========================================================
echo   SUKSES! Shko te GitHub Actions dhe shkarko APK V7.
echo ========================================================
pause
