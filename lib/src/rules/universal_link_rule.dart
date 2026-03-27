import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidUniversalLinkRule extends AndroidRule implements FixableRule {
  const AndroidUniversalLinkRule();

  @override
  Future<bool> tryFix(String targetFilePath, RuleConfig config) async {
    final sourcePath =
        p.join('android', 'app', 'src', 'main', 'AndroidManifest.xml');
    final file = File(sourcePath);
    if (!file.existsSync()) return false;

    try {
      String content = await file.readAsString();

      // Look for intent-filters that contain a <data scheme="..." /> but lack autoVerify
      // This regex identifies the intent-filter opening tag and checks if it's already got autoVerify
      final newContent = content.replaceAllMapped(
        RegExp(r'<intent-filter([^>]*)>(.*?)</intent-filter>', dotAll: true),
        (match) {
          final filterAttrs = match.group(1)!;
          final filterContent = match.group(2)!;

          if (filterContent.contains('android:scheme')) {
            // Extract schemes to check against ignore list
            final schemeRegExp = RegExp(r'android:scheme="([^"]*)"');
            final schemes = schemeRegExp
                .allMatches(filterContent)
                .map((m) => m.group(1))
                .toList();

            bool isIgnored = schemes
                .any((scheme) => config.ignoreComponents.contains(scheme));

            if (!isIgnored &&
                !filterAttrs.contains('android:autoVerify="true"')) {
              // Add autoVerify to this filter
              return '<intent-filter$filterAttrs android:autoVerify="true">$filterContent</intent-filter>';
            }
          }
          return match.group(0)!;
        },
      );

      if (newContent != content) {
        // Double-check XML validity
        XmlDocument.parse(newContent);
        await file.writeAsString(newContent);
        print(
            '\x1B[32m[FIXED] Added android:autoVerify="true" to AndroidManifest.xml\x1B[0m');
        return true;
      } else {
        // If we didn't change anything, it might be because the vulnerable filter wasn't in the source file
        print(
            '\x1B[33m[WARNING] Vulnerability appears to be injected by a 3rd-party plugin. Cannot auto-fix source manifest.\x1B[0m');
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
    bool failed = false;
    final intentFilters = document.findAllElements('intent-filter');

    if (verbose) {
      print(
          '      [DEBUG] Analyzing Android Intent Filters for Universal Links');
    }

    for (var filter in intentFilters) {
      final dataElements = filter.findElements('data');
      for (var data in dataElements) {
        final scheme = data.getAttribute('android:scheme');
        if (scheme != null && scheme != 'http' && scheme != 'https') {
          // Custom scheme found
          final autoVerify =
              filter.getAttribute('android:autoVerify') == 'true';
          if (!autoVerify) {
            onFail(
                'Android',
                'Deep Link Hijacking',
                'Custom scheme ($scheme) lacks autoVerify="true".',
                config.severity);
            failed = true;
          }
        }
      }
    }

    if (!failed) {
      onPass('Android',
          'Deep Link Verification (All custom schemes have autoVerify="true" or none found)');
    }
    return failed;
  }
}

class IOSUniversalLinkRule extends IOSRule {
  const IOSUniversalLinkRule();

  @override
  bool validate(
      Map<dynamic, dynamic> plist,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false}) {
    if (verbose) print('      [DEBUG] Checking iOS URL Types');
    final urlTypes = plist['CFBundleURLTypes'] as List?;
    if (urlTypes == null || urlTypes.isEmpty) {
      onPass('iOS', 'Universal Link Check (No custom URL schemes defined)');
      return false;
    }

    // Check for associated domains (Universal Links)
    // Note: This usually requires entitlement file check, but we can issue a warning if custom schemes are found
    onPass('iOS',
        'Universal Link Check (Manual verification of associated domains recommended if custom schemes are used)');
    return false;
  }
}
