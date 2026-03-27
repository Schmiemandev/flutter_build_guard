import 'package:xml/xml.dart';
import '../config_manager.dart';

export '../config_manager.dart' show RuleConfig;

/// Interface for rules that can automatically remediate issues.
abstract class FixableRule {
  Future<bool> tryFix(String targetFilePath, RuleConfig config);
}

/// Base interface for all security validation rules.
abstract class SecurityRule<T> {
  const SecurityRule();
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
