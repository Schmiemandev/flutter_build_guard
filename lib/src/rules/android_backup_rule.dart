import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

/// Analyzes the AndroidManifest.xml for backup vulnerabilities.
///
/// This rule checks if `android:allowBackup` is set to `false`.
/// If it's `true` or missing, it may allow sensitive app data to be
/// extracted via ADB backup.
class AndroidBackupRule extends AndroidRule implements FixableRule {
  /// Default constructor for the backup rule.
  const AndroidBackupRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final sourcePath =
        p.join('android', 'app', 'src', 'main', 'AndroidManifest.xml');
    final file = File(sourcePath);
    if (!file.existsSync()) return false;

    try {
      String content = await file.readAsString();

      // Locate <application tag and check if allowBackup already exists
      final appTagRegExp = RegExp(r'<application([^>]*)>');
      final match = appTagRegExp.firstMatch(content);
      if (match == null) return false;

      String appTagContent = match.group(1)!;
      String newContent;

      if (appTagContent.contains('android:allowBackup')) {
        // If it already says false in the source, then the vulnerability in the
        // merged manifest must be from a plugin.
        if (appTagContent.contains('android:allowBackup="false"')) {
          print(
              '\x1B[33m[WARNING] Vulnerability "android:allowBackup" appears to be injected by a 3rd-party plugin. Cannot auto-fix source manifest.\x1B[0m');
          return false;
        }

        // Replace existing attribute (e.g. if it's "true")
        newContent = content.replaceFirst(
          RegExp(r'android:allowBackup="[^"]*"'),
          'android:allowBackup="false"',
        );
      } else {
        // Safety: If it's missing in source, but found in merged, it's likely a plugin injection or Gradle default.
        // User requested NOT to modify if it's not explicitly in source to avoid mangling.
        print(
            '\x1B[33m[WARNING] Vulnerability "android:allowBackup" is missing from source. Likely injected or defaulting. Cannot auto-fix.\x1B[0m');
        return false;
      }

      // Double-check XML validity
      XmlDocument.parse(newContent);

      await file.writeAsString(newContent);
      print(
          '\x1B[32m[FIXED] android:allowBackup="false" applied to AndroidManifest.xml\x1B[0m');
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  bool validate(
      XmlDocument document,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false}) {
    final app = document.findAllElements('application').firstOrNull;
    if (app == null) {
      onSkip('Android', 'Backup Leaks', 'No <application> tag found.');
      return false;
    }

    final allowBackup = app.getAttribute('android:allowBackup')?.toLowerCase();
    if (allowBackup != 'false') {
      onFail(
          'Android',
          'Backup Leaks',
          'Set android:allowBackup="false" to prevent ADB data extraction.',
          config.severity);
      return true;
    }
    onPass('Android', 'Backup Leaks (android:allowBackup is false)');
    return false;
  }
}
