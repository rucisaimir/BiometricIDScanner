# BiometricIDScanner - Aplikacion Android (.APK) në C# .NET 9 MAUI

Ky projekt është ndërtuar posaçërisht për të lexuar çipin biometrik **ISO 14443-4 (`IsoDep`)** të **Kartave të Identitetit Shqiptare (IdentiTek / Aleat)** dhe **Pasaportave Biometrike (ICAO 9303)** duke përdorur antenën fizike NFC të celularit Android.

## Si ta gjenerosh skedarin `.APK` për 2 minuta:

### Mënyra 1: Nga kompjuteri yt (Visual Studio / CLI)
Nëse ke të instaluar .NET 9 SDK në Windows, hap terminalin (PowerShell ose CMD) brenda kësaj dosjeje dhe ekzekuto këtë komandë të vetme:

```bash
dotnet publish -f net9.0-android -c Release -p:AndroidPackageFormat=apk
```
Skedari yt i gatshëm `.apk` do të dalë te:
`bin/Release/net9.0-android/publish/com.albania.biometricidscanner-Signed.apk`

### Mënyra 2: Pa instaluar asgjë në PC (Me GitHub Actions)
1. Ngarkoje këtë dosje në një Repository në GitHub.
2. GitHub Actions (`.github/workflows/build-apk.yml`) do ta kompajlojë vetë projektin dhe do të të japë skedarin **`.APK`** gati për shkarkim te seksioni **Actions -> Artifacts**.
