import 'dart:io';
import 'package:yaml/yaml.dart';
import 'package:path/path.dart' as p;
import 'constants.dart';
import 'security_scanner.dart';

/// Represents the global security policy for the scanner.
class ScannerConfig {
  final bool failOnProcessError;
  final bool stopOnFirstFail;
  final Map<String, RuleConfig> androidRules;
  final Map<String, RuleConfig> iosRules;

  const ScannerConfig({
    this.failOnProcessError = true,
    this.stopOnFirstFail = false,
    this.androidRules = const {},
    this.iosRules = const {},
  });

  /// Default strict policy if no config file exists.
  factory ScannerConfig.defaultStrict() {
    return ConfigManager.parseYaml(defaultConfigYaml);
  }
}

/// Individual rule configuration for enablement and severity.
class RuleConfig {
  final bool enabled;
  final String severity; // high, medium, low
  final List<String> ignoreComponents;

  const RuleConfig({
    this.enabled = true,
    this.severity = 'high',
    this.ignoreComponents = const [],
  });

  bool get isHighSeverity => severity.toLowerCase() == 'high';
}

/// ConfigManager handles loading and parsing of build_guard.yaml.
class ConfigManager {
  static Future<ScannerConfig> load() async {
    final configFile = File(p.join(Directory.current.path, 'build_guard.yaml'));

    if (!configFile.existsSync()) {
      return ScannerConfig.defaultStrict();
    }

    try {
      final yamlString = await configFile.readAsString();
      var config = parseYaml(yamlString);

      // Check for missing rules and update file if necessary
      final wasModified =
          await _syncMissingRules(configFile, yamlString, config);

      if (wasModified) {
        final updatedYaml = await configFile.readAsString();
        config = parseYaml(updatedYaml);
      }

      return config;
    } catch (e) {
      print(
          '\x1B[33m[!] Warning: Error parsing build_guard.yaml. Using defaults.\x1B[0m');
      return ScannerConfig.defaultStrict();
    }
  }

  static Future<bool> _syncMissingRules(
      File configFile, String currentYaml, ScannerConfig config) async {
    bool modified = false;
    final List<String> lines = currentYaml.split('\n');

    // Helper to check if a rule exists in the YAML content (not just the parsed object)
    bool yamlHasRule(String ruleId, String platformKey) {
      final platformIndex =
          lines.indexWhere((l) => l.trim() == '$platformKey:');
      if (platformIndex == -1) return false;

      final platformLine = lines[platformIndex];
      final platformIndent = platformLine.indexOf(platformKey);

      // Look forward until the next top-level key or end of file
      for (var i = platformIndex + 1; i < lines.length; i++) {
        final line = lines[i];
        if (line.trim().isEmpty || line.trim().startsWith('#')) continue;

        // Check indentation to see if we've left the platform section
        final currentIndent = line.indexOf(line.trim());
        if (currentIndent <= platformIndent && line.trim().endsWith(':')) break;

        if (line.trim().startsWith('$ruleId:')) return true;
      }
      return false;
    }

    void addMissingRules(
        Map<String, dynamic> availableRules, String platformKey) {
      for (final ruleId in availableRules.keys) {
        if (!yamlHasRule(ruleId, platformKey)) {
          print(
              '\x1B[33m[#] Auto-sync: Adding missing rule "$ruleId" to build_guard.yaml\x1B[0m');

          final platformIndex =
              lines.indexWhere((l) => l.trim() == '$platformKey:');
          if (platformIndex != -1) {
            final platformLine = lines[platformIndex];
            final platformIndent = platformLine.indexOf(platformKey);
            final ruleIndent = ' ' * (platformIndent + 2);
            lines.insert(platformIndex + 1,
                '$ruleIndent$ruleId: { enabled: true, severity: high }');
            modified = true;
          }
        }
      }
    }

    addMissingRules(SecurityScanner.androidRuleMap, 'android');
    addMissingRules(SecurityScanner.iosRuleMap, 'ios');

    if (modified) {
      await configFile.writeAsString(lines.join('\n'));
    }
    return modified;
  }

  static ScannerConfig parseYaml(String yamlString) {
    final dynamic yaml = loadYaml(yamlString);
    if (yaml is! YamlMap) return const ScannerConfig();

    final YamlMap? settings = yaml['scanner_settings'];
    final YamlMap? rules = yaml['rules'];

    return ScannerConfig(
      failOnProcessError: settings?['fail_on_process_error'] ?? true,
      stopOnFirstFail: settings?['stop_on_first_fail'] ?? false,
      androidRules: _parseRules(rules?['android']),
      iosRules: _parseRules(rules?['ios']),
    );
  }

  static Map<String, RuleConfig> _parseRules(dynamic rulesYaml) {
    if (rulesYaml is! YamlMap) return {};
    final Map<String, RuleConfig> rules = {};

    rulesYaml.forEach((key, value) {
      if (value is YamlMap) {
        rules[key.toString()] = RuleConfig(
          enabled: value['enabled'] ?? true,
          severity: value['severity'] ?? 'high',
          ignoreComponents: (value['ignore_components'] as YamlList?)
                  ?.map((e) => e.toString())
                  .toList() ??
              const [],
        );
      }
    });

    return rules;
  }
}
