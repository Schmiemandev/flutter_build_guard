import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:flutter_build_guard/src/rules/rules.dart';

void main() {
  late Directory tempDir;
  late String originalCwd;
  const config = RuleConfig(enabled: true, severity: 'high');

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('build_guard_test_');
    originalCwd = Directory.current.path;
    Directory.current = tempDir;
  });

  tearDown(() {
    Directory.current = originalCwd;
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  // Helper to create directory structure and write file
  void writeFile(String relativePath, String content) {
    final file = File(p.join(tempDir.path, relativePath));
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(content);
  }

  group('Fix Remediation - Android', () {
    test(
        'AndroidBackupRule: Fixes explicit allowBackup="true" and preserves comments',
        () async {
      const manifestPath = 'android/app/src/main/AndroidManifest.xml';
      const originalContent = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- Critical Application Config -->
    <application 
        android:label="MyApp"
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher">
        <activity android:name=".MainActivity" />
    </application>
</manifest>''';

      writeFile(manifestPath, originalContent);

      final rule = const AndroidBackupRule();
      final fixed = await rule.tryFix('merged_path_ignored', config);

      expect(fixed, isTrue);
      final newContent =
          File(p.join(tempDir.path, manifestPath)).readAsStringSync();
      expect(newContent, contains('android:allowBackup="false"'));
      expect(newContent, contains('<!-- Critical Application Config -->'));
      expect(newContent, contains('android:label="MyApp"'));
    });

    test('AndroidCleartextRule: Removes usesCleartextTraffic="true"', () async {
      const manifestPath = 'android/app/src/main/AndroidManifest.xml';
      const originalContent = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application 
        android:usesCleartextTraffic="true"
        android:theme="@style/LaunchTheme">
        <!-- Comment here -->
    </application>
</manifest>''';

      writeFile(manifestPath, originalContent);

      final rule = const AndroidCleartextRule();
      final fixed = await rule.tryFix('merged_path_ignored', config);

      expect(fixed, isTrue);
      final newContent =
          File(p.join(tempDir.path, manifestPath)).readAsStringSync();
      expect(
          newContent, isNot(contains('android:usesCleartextTraffic="true"')));
      expect(newContent, contains('android:theme="@style/LaunchTheme"'));
      expect(newContent, contains('<!-- Comment here -->'));
    });

    test('AndroidProGuardRule: Comments out nuclear flags', () async {
      const proguardPath = 'android/app/proguard-rules.pro';
      const originalContent = '''
# My Custom Proguard Rules
-keep class com.example.** { *; }

-dontobfuscate
-dontshrink

-keepattributes *Annotation*''';

      writeFile(proguardPath, originalContent);

      final rule = const AndroidProGuardRule();
      final fixed = await rule.tryFix('merged_path_ignored', config);

      expect(fixed, isTrue);
      final newContent =
          File(p.join(tempDir.path, proguardPath)).readAsStringSync();
      expect(newContent, contains('# -dontobfuscate'));
      expect(newContent, contains('# -dontshrink'));
      expect(newContent, contains('-keep class com.example.** { *; }'));
    });

    test(
        'AndroidBackupRule: Plugin Injection Safety - returns false if attribute missing in source',
        () async {
      const manifestPath = 'android/app/src/main/AndroidManifest.xml';
      const originalContent = '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="MyApp">
        <activity android:name=".MainActivity" />
    </application>
</manifest>''';

      writeFile(manifestPath, originalContent);

      // Note: In our current implementation, we need to decide if "missing" is a vulnerability in source.
      // The requirement asks for it to return false if NOT present in source.
      final rule = const AndroidBackupRule();
      final fixed = await rule.tryFix('merged_path_ignored', config);

      // This expectation might fail if the implementation still injects when missing.
      // I will adjust the implementation after running this test if it fails.
      expect(fixed, isFalse,
          reason:
              'Should not modify source if attribute is missing (likely plugin injection in merged manifest)');

      final currentContent =
          File(p.join(tempDir.path, manifestPath)).readAsStringSync();
      expect(currentContent, equals(originalContent));
    });
    group('Fix Remediation - iOS', () {
      test(
          'IOSInsecureNetworkRule: Removes NSAllowsArbitraryLoads key and value',
          () async {
        const plistPath = 'ios/Runner/Info.plist';
        const originalContent = '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>\$(BUNDLE_NAME)</string>
	<key>NSAppTransportSecurity</key>
	<dict>
		<!-- Insecure flag -->
		<key>NSAllowsArbitraryLoads</key>
		<true/>
	</dict>
</dict>
</plist>''';

        writeFile(plistPath, originalContent);

        final rule = const IOSInsecureNetworkRule();
        final fixed = await rule.tryFix('merged_path_ignored', config);

        expect(fixed, isTrue);
        final newContent =
            File(p.join(tempDir.path, plistPath)).readAsStringSync();
        expect(
            newContent, isNot(contains('<key>NSAllowsArbitraryLoads</key>')));
        expect(newContent, isNot(contains('<true/>')));
        expect(newContent, contains('<key>CFBundleName</key>'));
        expect(newContent, contains('<!-- Insecure flag -->'));
      });
    });
  });
}
