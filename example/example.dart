import 'dart:io';

import 'package:flutter_build_guard/flutter_build_guard.dart';

/// This example demonstrates how to use flutter_build_guard programmatically.
///
/// Note: This package is primarily intended to be used as a CLI tool.
/// For standard usage, run `dart run flutter_build_guard scan` in your terminal.
void main() async {
  // Load the configuration from build_guard.yaml, or use default settings.
  final config = await ConfigManager.load();
  final scanner = SecurityScanner(config);

  final manifestPath = 'android/app/src/main/AndroidManifest.xml';

  if (!File(manifestPath).existsSync()) {
    print('Manifest not found at $manifestPath. Skipping scan.');
    return;
  }

  print('Running programmatic scan...');

  final hasIssues = await scanner.scanAndroid(
    manifestPath,
    (platform, rule, fix, severity) {
      print('[FAIL] $rule: $fix');
    },
    (platform, rule) {
      print('[PASS] $rule');
    },
    (platform, rule, reason) {
      print('[SKIP] $rule - $reason');
    },
  );

  if (hasIssues) {
    print('Scan completed with vulnerabilities.');
    exitCode = 1;
  } else {
    print('Scan completed successfully.');
    exitCode = 0;
  }
}
