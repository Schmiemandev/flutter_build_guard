import 'dart:io';
import 'package:flutter_build_guard/flutter_build_guard.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  late Directory tempDir;
  late String originalCwd;
  late ScannerConfig config;

  setUp(() async {
    tempDir = await TestUtils.createIsolatedTestEnvironment();
    originalCwd = Directory.current.path;
    Directory.current = tempDir;
    config = ScannerConfig.defaultStrict();
  });

  tearDown(() async {
    Directory.current = originalCwd;
    await tempDir.delete(recursive: true);
  });

  group('Robustness - Malformed & Deeply Nested Files', tags: ['Robustness'],
      () {
    test('Should report failure when AndroidManifest.xml is malformed',
        () async {
      TestUtils.createAndroidManifest(tempDir, '<manifest><application>');

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      final result = await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(result, isTrue);
      expect(failures, contains('Manifest Parsing'));
    });

    test('Should report failure when AndroidManifest.xml is empty', () async {
      TestUtils.createAndroidManifest(tempDir, '');

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      final result = await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(result, isTrue);
      expect(failures, contains('Manifest Parsing'));
    });

    test('Should handle deeply nested XML tags without crashing', () async {
      String nested = '<manifest>';
      for (int i = 0; i < 1000; i++) {
        nested += '<tag$i>';
      }
      for (int i = 999; i >= 0; i--) {
        nested += '</tag$i>';
      }
      nested += '</manifest>';

      TestUtils.createAndroidManifest(tempDir, nested);
      final scanner = SecurityScanner(config);

      // Should either parse or report a parsing error, but NOT stack overflow/crash
      final result = await scanner.scanAndroid(
          'AndroidManifest.xml', (p, r, f, s) {}, (p, r) {}, (p, r, re) {});
      expect(result, isNotNull);
    });

    test('Should report failure when iOS Info.plist is malformed', () async {
      TestUtils.createInfoPlist(tempDir, 'MALFORMED PLIST');

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      final result = await scanner.scanIOS(
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(result, isTrue);
      expect(failures, contains('Plist Parsing'));
    });
  });

  group('Robustness - Component Protection & Permissions', tags: ['Security'],
      () {
    test('Should report failure when an exported Service lacks protection',
        () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <service android:name=".VulnerableService" android:exported="true">
            <intent-filter>
                <action android:name="com.example.ACTION" />
            </intent-filter>
        </service>
    </application>
</manifest>
''');
      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});
      expect(failures, contains('Component Hijacking'));
    });

    test('Should report failure when an exported Receiver lacks protection',
        () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <receiver android:name=".VulnerableReceiver" android:exported="true">
            <intent-filter>
                <action android:name="com.example.EVENT" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
''');
      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});
      expect(failures, contains('Component Hijacking'));
    });

    test(
        'Should report failure when an exported Content Provider lacks protection',
        () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider android:name=".VulnerableProvider" android:authorities="com.example.provider" android:exported="true" />
    </application>
</manifest>
''');
      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});
      expect(failures, contains('Component Hijacking'));
    });

    test('Should PASS when component uses a custom, non-system permission',
        () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".ProtectedActivity" android:exported="true" android:permission="com.my.app.CUSTOM_PERMISSION">
            <intent-filter><action android:name="android.intent.action.VIEW" /></intent-filter>
        </activity>
    </application>
</manifest>
''');
      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});
      expect(failures, isNot(contains('Component Hijacking')));
    });
  });

  group('Robustness - iOS Additional Coverage', tags: ['Security'], () {
    test('FAIL: iOS Missing Privacy Manifest when dependencies present',
        () async {
      File(p.join(tempDir.path, 'pubspec.lock'))
          .writeAsStringSync('  shared_preferences:');
      TestUtils.createInfoPlist(tempDir,
          '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>');

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanIOS(
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Apple Privacy Compliance'));
    });

    test('FAIL: iOS Privacy Manifest missing NSPrivacyAccessedAPITypes',
        () async {
      File(p.join(tempDir.path, 'pubspec.lock'))
          .writeAsStringSync('  shared_preferences:');
      TestUtils.createInfoPlist(tempDir,
          '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>');

      final iosDir = Directory(p.join(tempDir.path, 'ios', 'Runner'));
      File(p.join(iosDir.path, 'PrivacyInfo.xcprivacy')).writeAsStringSync(
          '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict></dict></plist>');

      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanIOS(
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});

      expect(failures, contains('Apple Privacy Compliance'));
    });
  });

  group('Robustness - Universal Links', tags: ['Security'], () {
    test('FAIL: Android Deep Link Hijacking (Missing autoVerify)', () async {
      TestUtils.createAndroidManifest(tempDir, '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="my-app" />
            </intent-filter>
        </activity>
    </application>
</manifest>
''');
      final failures = <String>[];
      final scanner = SecurityScanner(config);
      await scanner.scanAndroid('AndroidManifest.xml',
          (p, r, f, s) => failures.add(r), (p, r) {}, (p, r, re) {});
      expect(failures, contains('Deep Link Hijacking'));
    });
  });
}
