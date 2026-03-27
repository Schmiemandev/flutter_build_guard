import 'dart:io';
import 'package:flutter_build_guard/flutter_build_guard.dart';
import 'package:test/test.dart';

void main() {
  late Directory tempDir;
  late String originalCwd;
  late ScannerConfig defaultConfig;
  late ScannerConfig highSeverityConfig;

  setUp(() async {
    tempDir = await TestUtils.createIsolatedTestEnvironment();
    originalCwd = Directory.current.path;
    Directory.current = tempDir;

    defaultConfig = ScannerConfig.defaultStrict();

    highSeverityConfig = const ScannerConfig(
      androidRules: {
        'backup_leaks': RuleConfig(enabled: true, severity: 'high'),
        'cleartext_traffic': RuleConfig(enabled: true, severity: 'high'),
        'component_hijacking': RuleConfig(enabled: true, severity: 'high'),
        'debuggable_enabled': RuleConfig(enabled: true, severity: 'high'),
        'proguard_misconfiguration':
            RuleConfig(enabled: true, severity: 'high'),
        'network_security_config': RuleConfig(enabled: true, severity: 'high'),
        'android_secret_auditor': RuleConfig(enabled: true, severity: 'high'),
        'deep_link_hijacking': RuleConfig(enabled: true, severity: 'high'),
      },
      iosRules: {
        'insecure_network': RuleConfig(enabled: true, severity: 'high'),
        'deep_link_hijacking': RuleConfig(enabled: true, severity: 'high'),
        'apple_privacy_manifest': RuleConfig(enabled: true, severity: 'high'),
      },
    );
  });

  tearDown(() async {
    Directory.current = originalCwd;
    await tempDir.delete(recursive: true);
  });

  group('SecurityScanner - Android', tags: ['Security'], () {
    test('PASS: Valid manifest with allowBackup="false"', () async {
      TestUtils.createAndroidManifest(
          tempDir, TestUtils.getMinimalSecureAndroidManifest());

      final passes = <String>[];
      final scanner = SecurityScanner(defaultConfig);
      final result = await scanner.scanAndroid(
        'AndroidManifest.xml',
        (p, r, f, s) {},
        (p, r) => passes.add(r),
        (p, r, re) => {},
      );

      expect(result, isFalse);
      expect(passes, anyElement(startsWith('Backup Leaks')));
      expect(passes, anyElement(startsWith('Cleartext Traffic')));
    });

    test('FAIL: Manifest missing allowBackup', () async {
      TestUtils.createAndroidManifest(
          tempDir, '<manifest><application></application></manifest>');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Backup Leaks'));
    });

    test('FAIL: Cleartext Traffic enabled', () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true"></application>
</manifest>''');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Cleartext Traffic'));
    });

    test('FAIL: Component Hijacking (Non-launcher Activity)', () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".Insecure" android:exported="true">
            <intent-filter><action android:name="android.intent.action.VIEW" /></intent-filter>
        </activity>
    </application>
</manifest>''');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Component Hijacking'));
    });

    test('PASS: Component filtering (ignore_components)', () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name="com.example.Ignored" android:exported="true">
            <intent-filter><action android:name="android.intent.action.VIEW" /></intent-filter>
        </activity>
    </application>
</manifest>''');

      final config = ScannerConfig(
        androidRules: {
          'component_hijacking': const RuleConfig(
            enabled: true,
            severity: 'high',
            ignoreComponents: ['com.example.Ignored'],
          ),
        },
      );

      final passes = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml', (p, r, f, s) {},
          (p, r) => passes.add(r), (p, r, re) {});

      expect(passes.any((p) => p.contains('Ignored: com.example.Ignored')),
          isTrue);
    });

    test('WARNING: Medium severity does not break build', () async {
      TestUtils.createAndroidManifest(tempDir,
          '<manifest><application android:allowBackup="true"></application></manifest>');

      final config = ScannerConfig(
        androidRules: {
          'backup_leaks': const RuleConfig(enabled: true, severity: 'medium'),
        },
      );

      final scanner = SecurityScanner(config);
      final result = await scanner.scanAndroid(
          'AndroidManifest.xml', (p, r, f, s) {}, (p, r) {}, (p, r, re) {});

      expect(result, isFalse);
    });

    test('EDGE CASE: Gracefully handles missing manifest file', () async {
      final failures = <String>[];
      final scanner = SecurityScanner(defaultConfig);
      final result = await scanner.scanAndroid('non_existent.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(result, isFalse);
      expect(failures, isEmpty);
    });

    test('EDGE CASE: Multiple components (one safe, one vulnerable)', () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".Safe" android:exported="true" android:permission="perm.REQUIRED">
            <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
        </activity>
        <service android:name=".Vulnerable" android:exported="true">
            <intent-filter><action android:name="com.example.ACTION" /></intent-filter>
        </service>
    </application>
</manifest>''');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Component Hijacking'));
    });

    test('EDGE CASE: Attribute casing robustness', () async {
      TestUtils.createAndroidManifest(tempDir,
          '<manifest><application android:allowBackup="True"></application></manifest>');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Backup Leaks'));
    });

    test('EDGE CASE: Manifest without <application> tag', () async {
      TestUtils.createAndroidManifest(tempDir, '<manifest></manifest>');
      final scanner = SecurityScanner(defaultConfig);
      final result = await scanner.scanAndroid(
          'AndroidManifest.xml', (p, r, f, s) {}, (p, r) {}, (p, r, re) {});
      expect(result, isFalse);
    });

    test(
        'Severity Escalation: Medium severity does not result in true return (fail)',
        () async {
      TestUtils.createAndroidManifest(tempDir,
          '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="true"></application></manifest>');
      final config = ScannerConfig(
        androidRules: {
          'backup_leaks': const RuleConfig(enabled: true, severity: 'medium'),
        },
      );
      final scanner = SecurityScanner(config);
      final result = await scanner.scanAndroid(
          'AndroidManifest.xml', (p, r, f, s) {}, (p, r) {}, (p, r, re) {});
      expect(result, isFalse); // Medium should NOT fail build
    });

    test(
        'Ignore List Specificity: ignore_components is case-sensitive and requires exact match',
        () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name="com.example.ExactMatch" android:exported="true">
            <intent-filter><action android:name="android.intent.action.VIEW" /></intent-filter>
        </activity>
    </application>
</manifest>''');

      final config = ScannerConfig(
        androidRules: {
          'component_hijacking': const RuleConfig(
            enabled: true,
            severity: 'high',
            ignoreComponents: ['com.example.exactmatch'], // Wrong casing
          ),
        },
      );

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(
          failures,
          contains(
              'Component Hijacking')); // Should still fail because of casing
    });

    test(
        'Platform Isolation: Failure in Android should not prevent scanning of iOS',
        () async {
      // Setup both Android (vulnerable) and iOS
      TestUtils.createAndroidManifest(tempDir,
          '<manifest><application></application></manifest>'); // Missing allowBackup
      TestUtils.createInfoPlist(tempDir, TestUtils.getMinimalSecureInfoPlist());

      final scannedPlatforms = <String>{};
      final scanner = SecurityScanner(highSeverityConfig);

      // Simulate the scan process in bin
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => scannedPlatforms.add(p), (p, r) {}, (p, r, re) {});
      await scanner.scanIOS((p, r, f, s) => scannedPlatforms.add(p),
          (p, r) => scannedPlatforms.add(p), (p, r, re) {});

      expect(scannedPlatforms, contains('Android'));
      expect(scannedPlatforms, contains('iOS'));
    });
  });

  group('SecurityScanner - iOS', tags: ['Security'], () {
    test('FAIL: Plist with NSAllowsArbitraryLoads set to true', () async {
      TestUtils.createInfoPlist(tempDir, '''
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>''');

      final failures = <String>[];
      final scanner = SecurityScanner(highSeverityConfig);
      final result = await scanner.scanIOS(
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(result, isTrue);
      expect(failures, contains('Insecure Network Traffic'));
    });

    test('PASS: Plist with secure transport configuration', () async {
      TestUtils.createInfoPlist(tempDir, TestUtils.getMinimalSecureInfoPlist());

      final passes = <String>[];
      final scanner = SecurityScanner(defaultConfig);
      final result = await scanner.scanIOS(
          (p, r, f, s) {}, (p, r) => passes.add(r), (p, r, re) {});

      expect(result, isFalse);
      expect(passes, anyElement(startsWith('Insecure Network')));
    });
  });
}
