# Android emulator automation blocker — 2026-07-27

The current agent cannot provision or execute an Android emulator run:

```text
adb: unavailable
sdkmanager: unavailable
avdmanager: unavailable
emulator: unavailable
/dev/kvm: absent
CPU virtualization flags: 0
xray binary: unavailable
physical Android/iOS device: unavailable
```

An Android emulator can be fully scripted only on a runner with Android SDK
command-line tools, a downloaded system image, sufficient disk/RAM, and KVM or
an explicitly supported software-acceleration configuration. The GitHub
workflow cannot be updated by the current GitHub App credential because it
lacks workflow-write permission, so an emulator-specific job cannot be added or
scoped safely in this session.

No Android emulator, v2rayNG/NekoBox APK, Xray binary, adb install, proxy
request, or nonce evidence is claimed. A future run must label itself
**“emulator automation, not physical device”** and retain the physical-device
and real-carrier limitation in its status.

For iOS, this environment has neither macOS nor Xcode/`xcrun simctl`, and
physical-device/App Store/TestFlight validation remains a human-operated task.
