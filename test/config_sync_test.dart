import 'dart:io';
import 'package:flutter_build_guard/flutter_build_guard.dart';
import 'package:flutter_build_guard/src/constants.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  late Directory tempDir;
  late String originalCwd;

  setUp(() async {
    tempDir = await TestUtils.createIsolatedTestEnvironment();
    originalCwd = Directory.current.path;
    Directory.current = tempDir;
  });

  tearDown(() async {
    Directory.current = originalCwd;
    await tempDir.delete(recursive: true);
  });

  group('ConfigManager Sync', tags: ['Functional'], () {
    test('ConfigManager: Automatically syncs missing rules to build_guard.yaml',
        () async {
      final configFile = File(p.join(tempDir.path, 'build_guard.yaml'));

      const initialYaml = '''
rules:
  android:
    backup_leaks: { enabled: true, severity: high }
  ios:
    insecure_network: { enabled: true, severity: high }
''';
      await configFile.writeAsString(initialYaml);

      final config = await ConfigManager.load();

      expect(config.androidRules.containsKey('android_secret_auditor'), isTrue);

      final updatedYaml = await configFile.readAsString();
      expect(updatedYaml, contains('android_secret_auditor:'));
    });

    test('Idempotency: Syncing twice does not modify a complete file',
        () async {
      final configFile = File(p.join(tempDir.path, 'build_guard.yaml'));

      // Initial write to ensure it's not starting from empty/default
      await configFile.writeAsString(medConfigYaml);

      // Load once to sync
      await ConfigManager.load();
      final firstSyncContent = await configFile.readAsString();

      // Load again
      await ConfigManager.load();
      final secondSyncContent = await configFile.readAsString();

      expect(secondSyncContent, equals(firstSyncContent));
    });

    test('Comment Preservation: Syncing does not strip user comments',
        () async {
      final configFile = File(p.join(tempDir.path, 'build_guard.yaml'));
      const initialYaml = '''
# Global Settings
scanner_settings:
  fail_on_process_error: true

rules:
  # Android Rules
  android:
    backup_leaks: { enabled: true, severity: high } # Keep this enabled
  ios:
    insecure_network: { enabled: true, severity: high }
''';
      await configFile.writeAsString(initialYaml);

      await ConfigManager.load();

      final updatedYaml = await configFile.readAsString();
      expect(updatedYaml, contains('# Global Settings'));
      expect(updatedYaml, contains('# Android Rules'));
      expect(updatedYaml, contains('# Keep this enabled'));
    });

    test('Partial Config: Handles missing platform sections', () async {
      final configFile = File(p.join(tempDir.path, 'build_guard.yaml'));
      const initialYaml = '''
rules:
  android:
    backup_leaks: { enabled: true, severity: high }
''';
      await configFile.writeAsString(initialYaml);

      // Should not crash, and should ideally eventually support adding 'ios:' if missing
      // (The current implementation needs 'ios:' key to exist to add rules to it)
      final config = await ConfigManager.load();
      expect(config.androidRules, isNotEmpty);
    });

    test('Negative Testing: Malformed YAML results in default config',
        () async {
      final configFile = File(p.join(tempDir.path, 'build_guard.yaml'));
      await configFile.writeAsString('MALFORMED: [ YAML: : :');

      // Should not crash, should return defaults
      final config = await ConfigManager.load();

      expect(config, isNotNull);
      expect(config.androidRules, isNotEmpty); // Defaults loaded
    });
  });
}
