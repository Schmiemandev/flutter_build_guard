import 'package:xml/xml.dart';
import '../config_manager.dart';

export '../config_manager.dart' show RuleConfig;

/// Interface for rules that can automatically remediate issues.
abstract class FixableRule {
  /// Attempts to automatically fix a detected vulnerability.
  ///
  /// [targetFilePath] is the path to the source file to be modified.
  /// [config] is the configuration for the current rule.
  /// Returns `true` if the fix was successfully applied, `false` otherwise.
  Future<bool> tryFix(String targetFilePath, RuleConfig config);
}

/// Base interface for all security validation rules.
///
/// [T] is the context type for the rule (e.g., `XmlDocument` for Android,
/// `Map` for iOS).
abstract class SecurityRule<T> {
  /// Default constructor for security rules.
  const SecurityRule();

  /// Validates the given [context] against the security rule.
  ///
  /// [config] provides the rule's specific settings and severity.
  /// [onFail], [onPass], and [onSkip] are callback functions for reporting results.
  /// Returns `true` if a vulnerability was detected, `false` otherwise.
  bool validate(
      T context,
      RuleConfig config,
      void Function(String platform, String rule, String fix, String severity)
          onFail,
      void Function(String platform, String rule) onPass,
      void Function(String platform, String rule, String reason) onSkip,
      {bool verbose = false});
}

/// Specialized rule for Android Manifest validation.
abstract class AndroidRule implements SecurityRule<XmlDocument> {
  /// Default constructor for Android rules.
  const AndroidRule();

  @override
  bool validate(
      XmlDocument document,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false});
}

/// Specialized rule for iOS Plist validation.
abstract class IOSRule implements SecurityRule<Map<dynamic, dynamic>> {
  /// Default constructor for iOS rules.
  const IOSRule();

  @override
  bool validate(
      Map<dynamic, dynamic> plist,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false});
}
