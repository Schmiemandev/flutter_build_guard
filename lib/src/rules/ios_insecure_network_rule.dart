import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class IOSInsecureNetworkRule extends IOSRule implements FixableRule {
  const IOSInsecureNetworkRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final path = p.join('ios', 'Runner', 'Info.plist');
    final file = File(path);
    if (!file.existsSync()) return false;

    try {
      String content = await file.readAsString();

      // Target: <key>NSAllowsArbitraryLoads</key>\s*<true/>
      final newContent = content.replaceFirst(
        RegExp(r'<key>NSAllowsArbitraryLoads</key>\s*<true/>'),
        '',
      );

      if (newContent != content) {
        // Double-check XML/Plist validity
        XmlDocument.parse(newContent);
        await file.writeAsString(newContent);
        print(
            '\x1B[32m[FIXED] Removed NSAllowsArbitraryLoads from Info.plist\x1B[0m');
        return true;
      } else {
        print(
            '\x1B[33m[WARNING] NSAllowsArbitraryLoads vulnerability appears to be injected by a 3rd-party plugin. Cannot auto-fix source Info.plist.\x1B[0m');
        return false;
      }
    } catch (e) {
      return false;
    }
  }

  @override
  bool validate(
      Map<dynamic, dynamic> plist,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false}) {
    if (verbose) {
      print(
          '      [DEBUG] Checking: ios/Runner/Info.plist for NSAppTransportSecurity');
    }
    final transportSecurity = plist['NSAppTransportSecurity'] as Map?;

    // 2024 M5: Flag NSAllowsArbitraryLoads=true to prevent insecure HTTP.
    if (transportSecurity != null &&
        transportSecurity['NSAllowsArbitraryLoads'] == true) {
      onFail(
          'iOS',
          'Insecure Network Traffic',
          'NSAllowsArbitraryLoads is true. App allows insecure HTTP.',
          config.severity);
      return true;
    }
    onPass('iOS', 'Insecure Network (NSAllowsArbitraryLoads is false/omitted)');
    return false;
  }
}
