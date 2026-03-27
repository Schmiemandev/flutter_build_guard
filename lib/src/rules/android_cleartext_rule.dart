import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidCleartextRule extends AndroidRule implements FixableRule {
  const AndroidCleartextRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final sourcePath =
        p.join('android', 'app', 'src', 'main', 'AndroidManifest.xml');
    final file = File(sourcePath);
    if (!file.existsSync()) return false;

    try {
      String content = await file.readAsString();

      if (!content.contains('android:usesCleartextTraffic="true"')) {
        print(
            '\x1B[33m[WARNING] Vulnerability "android:usesCleartextTraffic" appears to be injected by a 3rd-party plugin. Cannot auto-fix source manifest.\x1B[0m');
        return false;
      }

      final newContent = content.replaceFirst(
        RegExp(r'android:usesCleartextTraffic="true"'),
        '',
      );

      // Double-check XML validity
      XmlDocument.parse(newContent);

      await file.writeAsString(newContent);
      print(
          '\x1B[32m[FIXED] Removed android:usesCleartextTraffic="true" from AndroidManifest.xml\x1B[0m');
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  bool validate(XmlDocument document, config, onFail, onPass, onSkip,
      {bool verbose = false}) {
    final app = document.findAllElements('application').firstOrNull;
    if (app == null) {
      onSkip('Android', 'Cleartext Traffic', 'No <application> tag found.');
      return false;
    }

    final cleartext =
        app.getAttribute('android:usesCleartextTraffic')?.toLowerCase();
    if (cleartext == 'true') {
      onFail(
          'Android',
          'Cleartext Traffic',
          'Insecure HTTP allowed. Remove usesCleartextTraffic="true".',
          config.severity);
      return true;
    }
    onPass('Android', 'Cleartext Traffic (Insecure HTTP disabled)');
    return false;
  }
}
