import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidProGuardRule extends AndroidRule implements FixableRule {
  const AndroidProGuardRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final proguardPath = p.join('android', 'app', 'proguard-rules.pro');
    final proguardFile = File(proguardPath);

    if (!proguardFile.existsSync()) return false;

    try {
      String content = await proguardFile.readAsString();

      final nuclearFlags = ['-dontobfuscate', '-dontshrink'];
      bool modified = false;

      for (var flag in nuclearFlags) {
        if (content.contains(flag) && !content.contains('# $flag')) {
          content = content.replaceFirst(
              flag, '# $flag (Removed by flutter_build_guard)');
          modified = true;
          print('\x1B[32m[FIXED] Removed $flag from proguard-rules.pro\x1B[0m');
        }
      }

      if (modified) {
        await proguardFile.writeAsString(content);
        return true;
      }
      return false;
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
    final proguardPath = p.join('android', 'app', 'proguard-rules.pro');
    final proguardFile = File(proguardPath);

    if (verbose) print('      [DEBUG] Checking: $proguardPath');

    if (!proguardFile.existsSync()) {
      onSkip('Android', 'ProGuard Auditor', '(File not found)');
      return false;
    }

    final content = proguardFile.readAsStringSync();
    bool failed = false;

    // Nuclear flags that disable security/obfuscation
    final nuclearFlags = {
      '-dontobfuscate': 'Obfuscation is disabled.',
      '-dontshrink': 'Code shrinking is disabled.',
      r'-keep\s+class\s+\*\s+\{\s+\*\s+;\s+\}':
          'Wildcard keep rule detected (keeps everything).',
    };

    nuclearFlags.forEach((pattern, reason) {
      if (RegExp(pattern).hasMatch(content)) {
        onFail(
            'Android',
            'ProGuard Misconfiguration',
            '$reason Remove flags that disable obfuscation to comply with OWASP MASVS-RESILIENCE.',
            config.severity);
        failed = true;
      }
    });

    if (!failed) {
      onPass('Android', 'ProGuard Obfuscation (No \'nuclear\' flags found)');
    }
    return failed;
  }
}
