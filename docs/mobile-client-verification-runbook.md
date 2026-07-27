# Mobile client verification runbook

**Status:** human-operated device validation required; no result is implied by
this document.

## Preconditions

- A real, authorized server endpoint and a server-side test URL returning a
  known nonce are available.
- A generated subscription is saved with its SHA-256 and creation time.
- The app version, OS version, device model, network type, and core version are
  recorded in `results/mobile-client-compat.md`.
- Do not paste a long-lived personal subscription into screenshots or logs.

## Common success criterion

1. Import the generated subscription using the app’s native import action.
2. Select the imported profile without manually editing transport/security
   fields.
3. Connect and fetch the authorized nonce URL through the VPN/proxy.
4. Record exact response body hash, connection time, selected profile fields,
   and the app/core log with secrets redacted.
5. Disconnect and revoke the test subscription after the run.

A successful import alone is not a connectivity result. A UI “connected” state
without the nonce response is not a success.

## v2rayNG (Android)

1. Install a released v2rayNG build from its official release channel.
2. Use **+ → Import config from clipboard/QR** with the generated VLESS URI or
   subscription URL.
3. Confirm the imported transport/security fields match the generated profile.
4. Start the VPN permission flow, then run the common success criterion.
5. Export redacted core log and record application version.

## NekoBox for Android

1. Install the exact released NekoBox build to be tested.
2. Use its subscription import UI, refresh once, then select the generated
   profile.
3. Start the service and run the common success criterion.
4. Record whether the application delegates to sing-box/Xray and the embedded
   core version shown by the app.

## Shadowrocket (iOS)

1. Install the exact App Store/TestFlight build on a physical iPhone/iPad.
2. Use **Subscribe → Add Subscription** and refresh the generated URL.
3. Select the imported node/profile, approve VPN configuration, and run the
   common success criterion.
4. Record iOS version, app version, profile rendering, and redacted connection
   log/screenshot.

## Steps that cannot be safely automated here

- Physical Android/iOS installation, OS VPN approval, mobile radio behavior,
  captive portals, battery restrictions, and app import UI are manual.
- Iranian ISP and mobile-carrier behavior requires an authorized human
  vantage point; do not fabricate a result from a desktop emulator or CI.
- A mobile app must not be called compatible until a row in the results tracker
  contains a real run date, device, app version, and nonce-response evidence.
