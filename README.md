# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Galaxy is a one-click installer for explicitly
supported Samsung model and kernel combinations. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/BuSung-dev/Root-My-Galaxy/releases)

The device feed and native payloads are maintained in
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).

## Application


<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app selects a payload whose model list and three-part kernel version match
the phone. For example, `6.6.98-android15-8-...` matches `6.6.98`. Advanced
mode filters the catalog by both values and allows manual selection with model
and kernel-version warnings.

The Home screen has a collapsible payload-source menu with three complete
pipelines:

1. **Online repository** resolves the device profile and downloads the matching
   exploit and ksud.
2. **Bundled payload** extracts the included S938BXXSBCZG3 exploit and ksud from
   the APK, verifies their exact size and SHA-256 fingerprint, and performs no
   payload download.
3. **Custom payload** imports a local `.so` into app-private storage. It becomes
   selectable as soon as that payload is present. A custom ksud is optional: if
   none is selected, the app resolves and downloads the matching online ksud;
   selecting an imported ksud skips that download.

Bundled and custom files are placed directly into `VerifiedPayloads`, then sent
through the same exploit, ksud staging, and KernelSU `--late-load` verification
used by the online source. Custom imports are limited to 256 MB, checked for the
ELF magic header, and recorded with a SHA-256 fingerprint. Removing the custom
payload switches an active custom selection to the bundled source; removing
only custom ksud keeps the custom payload active and restores online ksud.

Custom payload import is based on the Apache-2.0 implementation in
[hmascs/KSuRoot](https://github.com/hmascs/KSuRoot).

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 28 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

Use only on devices you own or are explicitly authorized to test.
