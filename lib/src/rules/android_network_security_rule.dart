import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidNetworkSecurityRule extends AndroidRule implements FixableRule {
  const AndroidNetworkSecurityRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    // Note: The original validate method finds the actual XML file path.
    // We attempt to locate the standard path for auto-fixing.
    final xmlPath = p.join('android', 'app', 'src', 'main', 'res', 'xml',
        'network_security_config.xml');
    final xmlFile = File(xmlPath);

    if (!xmlFile.existsSync()) return false;

    try {
      String content = await xmlFile.readAsString();
      String newContent = content;

      // Remove user certificates
      newContent =
          newContent.replaceAll(RegExp(r'<certificates src="user"[^>]*/>'), '');

      // Remove debug-overrides block
      newContent = newContent.replaceAll(
          RegExp(r'<debug-overrides>.*?</debug-overrides>', dotAll: true), '');

      // Double-check XML validity
      XmlDocument.parse(newContent);

      if (newContent != content) {
        await xmlFile.writeAsString(newContent);
        print(
            '\x1B[32m[FIXED] Removed insecure certificates/overrides from ${xmlFile.path}\x1B[0m');
        return true;
      } else {
        print(
            '\x1B[33m[WARNING] Network Security vulnerability appears to be in a non-standard file or injected. Cannot auto-fix.\x1B[0m');
        return false;
      }
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
    final application = document.findAllElements('application').firstOrNull;
    if (application == null) {
      onSkip('Android', 'Network Security', 'No <application> tag found.');
      return false;
    }

    final configAttr =
        application.getAttribute('android:networkSecurityConfig');
    if (configAttr == null) {
      onSkip(
          'Android', 'Network Security', 'No networkSecurityConfig attribute.');
      return false;
    }

    // Locate the XML file in res/xml (usually @xml/network_security_config)
    final fileName = '${configAttr.replaceAll('@xml/', '')}.xml';
    final xmlPath =
        p.join('android', 'app', 'src', 'main', 'res', 'xml', fileName);
    final xmlFile = File(xmlPath);

    if (verbose) print('      [DEBUG] Checking: $xmlPath');

    if (!xmlFile.existsSync()) {
      onSkip('Android', 'Network Security Config', '(File not found)');
      return false;
    }

    final xmlContent = xmlFile.readAsStringSync();
    final configDoc = XmlDocument.parse(xmlContent);
    bool failed = false;

    // Detection: Parse the XML and flag user certificates or debug-overrides
    final hasUserCert = configDoc
        .findAllElements('certificates')
        .any((node) => node.getAttribute('src') == 'user');
    final hasDebugOverrides =
        configDoc.findAllElements('debug-overrides').isNotEmpty;

    if (hasUserCert) {
      onFail(
          'Android',
          'Insecure Communication',
          'User-installed certificates detected in Network Security Config.',
          config.severity);
      failed = true;
    }

    if (hasDebugOverrides) {
      onFail('Android', 'Insecure Communication',
          'Debug overrides found in Network Security Config.', config.severity);
      failed = true;
    }

    if (!failed) {
      onPass('Android',
          'Network Security (No user-installed certificates allowed)');
    }
    return failed;
  }
}
