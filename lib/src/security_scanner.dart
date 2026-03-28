import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:xml/xml.dart';
import 'package:plist_parser/plist_parser.dart';

import 'rules/rules.dart';
import 'config_manager.dart';

// ANSI Color Codes
const String red = '\x1B[31m';
const String yellow = '\x1B[33m';
const String green = '\x1B[32m';
const String reset = '\x1B[0m';

/// Orchestrates security validation against 2024 OWASP Mobile Top 10.
///
/// This class is the primary entry point for running security scans
/// on both Android and iOS platform configurations.
class SecurityScanner {
  /// The configuration used for the security scan.
  final ScannerConfig config;

  /// Creates a new [SecurityScanner] with the given [config].
  SecurityScanner(this.config);

  /// A mapping of rule IDs to their corresponding [AndroidRule] implementations.
  static const Map<String, AndroidRule> androidRuleMap = {
    'backup_leaks': AndroidBackupRule(),
    'cleartext_traffic': AndroidCleartextRule(),
    'component_hijacking': AndroidComponentHijackRule(),
    'debuggable_enabled': AndroidDebuggableRule(),
    'proguard_misconfiguration': AndroidProGuardRule(),
    'network_security_config': AndroidNetworkSecurityRule(),
    'android_secret_auditor': AndroidSecretAuditorRule(),
    'deep_link_hijacking': AndroidUniversalLinkRule(),
  };

  /// A mapping of rule IDs to their corresponding [IOSRule] implementations.
  static const Map<String, IOSRule> iosRuleMap = {
    'insecure_network': IOSInsecureNetworkRule(),
    'deep_link_hijacking': IOSUniversalLinkRule(),
    'apple_privacy_manifest': IOSPrivacyManifestRule(),
  };

  /// Validates Android Manifest using registered security rules.
  ///
  /// [path] is the file path to the merged AndroidManifest.xml.
  /// [onFail], [onPass], and [onSkip] are callbacks for reporting scan results.
  /// [verbose] enables detailed logging.
  /// [attemptFix] triggers auto-remediation for supported rules.
  ///
  /// Returns `true` if any high-severity failures were detected.
  Future<bool> scanAndroid(
      String path,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false,
      bool attemptFix = false}) async {
    print('$yellow[#] Analyzing merged manifest at: $path$reset');
    final file = File(p.join(Directory.current.path, path));
    if (!file.existsSync()) {
      print('$red[!] Internal Error: Merged manifest not found.$reset');
      return false;
    }

    XmlDocument document;
    try {
      document = XmlDocument.parse(file.readAsStringSync());
    } catch (e) {
      onFail(
          'Android',
          'Manifest Parsing',
          'The merged AndroidManifest.xml is malformed. Check build logs.',
          'high');
      return true;
    }

    bool hasHighSeverityFailure = false;

    for (final entry in androidRuleMap.entries) {
      final id = entry.key;
      final rule = entry.value;
      final ruleConfig =
          config.androidRules[id] ?? const RuleConfig(enabled: true);

      if (ruleConfig.enabled) {
        if (rule.validate(document, ruleConfig, onFail, onPass, onSkip,
            verbose: verbose)) {
          bool fixed = false;
          if (attemptFix && rule is FixableRule) {
            print('$yellow[#] Attempting auto-fix for $id...$reset');
            if (await (rule as FixableRule).tryFix(path, ruleConfig)) {
              print('$green[FIXED] $id applied to AndroidManifest.xml$reset');
              fixed = true;
            }
          }

          if (!fixed && ruleConfig.isHighSeverity) {
            hasHighSeverityFailure = true;
          }
        }
      } else {
        onSkip('Android', id, '(Disabled in config)');
      }
    }

    return hasHighSeverityFailure;
  }

  /// Validates iOS Info.plist using registered security rules.
  ///
  /// [onFail], [onPass], and [onSkip] are callbacks for reporting scan results.
  /// [verbose] enables detailed logging.
  /// [attemptFix] triggers auto-remediation for supported rules.
  ///
  /// Returns `true` if any high-severity failures were detected.
  Future<bool> scanIOS(
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false,
      bool attemptFix = false}) async {
    final path = p.join('ios', 'Runner', 'Info.plist');
    final file = File(path);
    if (!file.existsSync()) return false;

    Map<dynamic, dynamic> plist;
    try {
      plist = PlistParser().parse(file.readAsStringSync());
    } catch (e) {
      onFail('iOS', 'Plist Parsing',
          'The iOS Info.plist is malformed or inaccessible.', 'high');
      return true;
    }

    bool hasHighSeverityFailure = false;

    for (final entry in iosRuleMap.entries) {
      final id = entry.key;
      final rule = entry.value;
      final ruleConfig = config.iosRules[id] ?? const RuleConfig(enabled: true);

      if (ruleConfig.enabled) {
        if (rule.validate(plist, ruleConfig, onFail, onPass, onSkip,
            verbose: verbose)) {
          bool fixed = false;
          if (attemptFix && rule is FixableRule) {
            print('$yellow[#] Attempting auto-fix for $id...$reset');
            if (await (rule as FixableRule).tryFix(path, ruleConfig)) {
              print('$green[FIXED] $id applied to $path$reset');
              fixed = true;
            }
          }

          if (!fixed && ruleConfig.isHighSeverity) {
            hasHighSeverityFailure = true;
          }
        }
      } else {
        onSkip('iOS', id, '(Disabled in config)');
      }
    }

    return hasHighSeverityFailure;
  }
}
