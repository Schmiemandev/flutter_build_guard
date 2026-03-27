import 'dart:io';
import 'package:path/path.dart' as p;
import 'base_rule.dart';

class IOSPrivacyManifestRule extends IOSRule implements FixableRule {
  const IOSPrivacyManifestRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final manifestPath = p.join('ios', 'Runner', 'PrivacyInfo.xcprivacy');
    final manifestFile = File(manifestPath);

    if (manifestFile.existsSync()) return false;

    try {
      const boilerplate = '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyAccessedAPITypes</key>
    <array/>
</dict>
</plist>
''';
      await manifestFile.writeAsString(boilerplate);
      print(
          '\x1B[32m[FIXED] Created baseline PrivacyInfo.xcprivacy manifest\x1B[0m');
      return true;
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
    final lockFile = File('pubspec.lock');
    if (!lockFile.existsSync()) {
      onSkip('iOS', 'Apple Privacy Compliance', 'pubspec.lock not found.');
      return false;
    }

    final content = lockFile.readAsStringSync();

    // Critical packages known to require Privacy Manifests
    final criticalPackages = [
      'shared_preferences',
      'path_provider',
      'device_info_plus',
      'package_info_plus',
    ];

    bool needsManifest = criticalPackages.any((pkg) => content.contains(pkg));

    final manifestPath = p.join('ios', 'Runner', 'PrivacyInfo.xcprivacy');
    final manifestFile = File(manifestPath);

    if (verbose) print('      [DEBUG] Checking: $manifestPath');

    if (!manifestFile.existsSync()) {
      if (needsManifest) {
        onFail(
            'iOS',
            'Apple Privacy Compliance',
            'Privacy Manifest required due to detected dependencies.',
            config.severity);
        return true;
      } else {
        onSkip('iOS', 'Apple Privacy Compliance', '(File not found)');
        return false;
      }
    }

    // Basic content check for NSPrivacyAccessedAPITypes
    final manifestContent = manifestFile.readAsStringSync();
    if (!manifestContent.contains('NSPrivacyAccessedAPITypes')) {
      onFail(
          'iOS',
          'Apple Privacy Compliance',
          'PrivacyInfo.xcprivacy lacks NSPrivacyAccessedAPITypes key.',
          config.severity);
      return true;
    }

    onPass('iOS',
        'Apple Privacy Manifest (Valid NSPrivacyAccessedAPITypes found)');
    return false;
  }
}
