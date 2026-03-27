# flutter_build_guard

[![Pub Version](https://img.shields.io/pub/v/flutter_build_guard?logo=dart&label=pub.dev)](https://pub.dev/packages/flutter_build_guard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/schmiemandev/flutter_build_guard/actions/workflows/dart.yml/badge.svg)](https://github.com/schmiemandev/flutter_build_guard/actions/workflows/dart.yml)

A Shift-Left security scanner for Flutter projects. `flutter_build_guard` audits native configurations (`AndroidManifest.xml`, `Info.plist`, `proguard-rules.pro`) to prevent security misconfigurations and data leaks from reaching production.

Unlike static regex scanners, this tool analyzes the final *merged* Android manifest, catching vulnerabilities introduced silently by third-party plugins.

## Features

- **Unified Auditing:** Scans both Android and iOS native configurations.
- **Merged Manifest Analysis:** Audits the final Android manifest after Gradle merges all plugin dependencies.
- **Non-Destructive Auto-Remediation:** Uses the `--fix` flag to safely resolve misconfigurations without altering your custom XML/Plist formatting or comments.
- **Plugin Injection Awareness:** Identifies if a vulnerability originates from your source code or was injected by a third-party package.
- **CI/CD Ready:** Exits with code `1` on high-severity findings to break insecure pipeline builds.

## Installation

You can install `flutter_build_guard` either globally or as a project-specific development dependency.

### Option 1: Global Installation (Recommended for local use)

```bash
dart pub global activate flutter_build_guard
```

*Ensure your `PATH` is updated to include the Dart SDK's `bin` directory.*

### Option 2: Project Dependency (Recommended for teams and CI/CD)

Add it to your `pubspec.yaml`:

```yaml
dev_dependencies:
  flutter_build_guard: ^1.0.0
```

Run it via Dart:

```bash
dart run flutter_build_guard <command>
```

## Usage

### Initialization

Run the `init` command in your project root to generate a `build_guard.yaml` configuration file. You will be prompted to select a baseline security preset (Low, Medium, or High).

```bash
flutter_build_guard init
```

### Scanning

Execute a security audit against your current native configurations:

```bash
flutter_build_guard scan
```

### Auto-Remediation

To automatically fix detected vulnerabilities, append the `--fix` flag. The tool will safely modify your source files where possible and warn you if a vulnerability is originating from a third-party dependency.

```bash
flutter_build_guard scan --fix
```

### CI Environment

For automated pipelines, use the `--ci` flag for streamlined, non-interactive output:

```bash
flutter_build_guard scan --ci
```

## Configuration

The `build_guard.yaml` file allows you to define explicit rulesets, adjust severity thresholds, and whitelist specific components.

```yaml
scanner_settings:
  fail_on_process_error: true
  stop_on_first_fail: false

rules:
  android:
    backup_leaks: { enabled: true, severity: high }
    cleartext_traffic: { enabled: true, severity: high }
    component_hijacking: { enabled: true, severity: medium }
    debuggable_enabled: { enabled: true, severity: high }
    proguard_misconfiguration: { enabled: true, severity: medium }
  ios:
    insecure_network: { enabled: true, severity: high }
    apple_privacy_manifest: { enabled: true, severity: high }
```

## Supported Checks

**Android**

- Backup Leaks (`android:allowBackup`)
- Cleartext Traffic (`android:usesCleartextTraffic`)
- Exported Component Hijacking (Missing permissions on exported activities/services)
- Debuggable Mode (`android:debuggable`)
- ProGuard Misconfigurations (Disabling obfuscation/shrinking)
- Network Security Config (User certificates / Debug overrides)
- Secret Auditing (Hardcoded high-entropy tokens)
- Deep Link Hijacking (Missing `autoVerify`)

**iOS**

- ATS Insecure Network (`NSAllowsArbitraryLoads`)
- Privacy Manifest Compliance (`PrivacyInfo.xcprivacy`)
- Universal Link Verification
```