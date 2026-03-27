import 'package:test/test.dart';
import 'package:xml/xml.dart';
import 'package:flutter_build_guard/flutter_build_guard.dart';

void main() {
  group('AndroidSecretAuditorRule', tags: ['Security'], () {
    const rule = AndroidSecretAuditorRule();
    const config = RuleConfig(enabled: true, severity: 'high');

    test('FAIL: High-Confidence Google API Key detected', () {
      final manifest = XmlDocument.parse('''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <meta-data android:name="com.google.android.geo.API_KEY" android:value="AIzaSyA12345678901234567890123456789012" />
    </application>
</manifest>
''');
      final failures = <String>[];

      rule.validate(
        manifest,
        config,
        (p, r, f, s) => failures.add(r),
        (p, r) => {},
        (p, r, re) => {},
      );

      expect(
          failures,
          anyElement(
              contains('High-Confidence Secret Detected (Google API Key)')));
    });

    test('Mathematical Validation: Shannon Entropy Calculation', () {
      const testString = 'aabbccdd';
      final entropy = rule.calculateEntropy(testString);
      expect(entropy, closeTo(2.0, 0.001));
    });

    test('Entropy Thresholding: High entropy strings at the 4.5 bit threshold',
        () {
      // 4.5 is a common threshold. We need to test values around it.

      // Let's use a known string that should be above 4.5 if it's long and varied.
      final entropy = rule.calculateEntropy(
          'pk_live_51P8p4o2nS7f9K3L0vR2T5wE1xY6zC9mQ8uV7bN4iG0hJ');
      expect(entropy, greaterThan(4.5));
    });

    test('False Positive Mitigation: Safe common patterns', () {
      final manifest = XmlDocument.parse('''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <!-- Hex Colors -->
        <meta-data android:name="theme_color" android:value="#FF5733" />
        <!-- UUIDs (often used for non-secret tracking) -->
        <meta-data android:name="instance_id" android:value="550e8400-e29b-41d4-a716-446655440000" />
        <!-- Firebase Project IDs -->
        <meta-data android:name="project_id" android:value="my-awesome-project-123" />
    </application>
</manifest>
''');
      final failures = <String>[];

      rule.validate(
        manifest,
        config,
        (p, r, f, s) => failures.add(r),
        (p, r) => {},
        (p, r, re) => {},
      );

      // These should NOT be flagged as high-confidence secrets.
      // Entropy might flag them as medium, but only if they are in "targeted" attributes.
      expect(
          failures.any((f) => f.contains('High-Confidence Secret')), isFalse);
    });

    test('Obfuscated Keys: Detection within meta-data tags', () {
      final manifest = XmlDocument.parse('''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <!-- Key split across name and value -->
        <meta-data android:name="api_key_part_1" android:value="AIzaSyA12345678901234567890123456789012" />
    </application>
</manifest>
''');
      final failures = <String>[];

      rule.validate(
        manifest,
        config,
        (p, r, f, s) => failures.add(r),
        (p, r) => {},
        (p, r, re) => {},
      );

      // The signature matcher should catch this regardless of tag name if it matches the value
      expect(failures, anyElement(contains('High-Confidence Secret')));
    });

    test('WARNING: Potential Secret Detected via Entropy', () {
      final manifest = XmlDocument.parse('''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <meta-data android:name="stripe_publishable_key" android:value="pk_test_aB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R7s8T9u0V" />
    </application>
</manifest>
''');
      final failures = <String>[];

      rule.validate(
        manifest,
        config,
        (p, r, f, s) => failures.add(r),
        (p, r) => {},
        (p, r, re) => {},
      );

      expect(failures,
          anyElement(contains('Potential Secret Detected (High Entropy:')));
    });

    test('IGNORE: Resource references and short strings', () {
      final manifest = XmlDocument.parse('''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="@string/app_name">
        <meta-data android:name="short_key" android:value="12345" />
        <meta-data android:name="build_var" android:value="\$BUILD_VAR" />
    </application>
</manifest>
''');
      final failures = <String>[];
      final passes = <String>[];

      rule.validate(
        manifest,
        config,
        (p, r, f, s) => failures.add(r),
        (p, r) => passes.add(r),
        (p, r, re) => {},
      );

      expect(failures, isEmpty);
      expect(passes, anyElement(contains('Secrets Audit')));
    });
  });
}
