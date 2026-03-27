import 'dart:math' as math;
import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidSecretAuditorRule extends AndroidRule {
  const AndroidSecretAuditorRule();

  static const Map<String, String> _signatures = {
    'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Stripe API Key': r'sk_(test|live)_[0-9a-zA-Z]{24}',
    'Mapbox Token': r'pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}',
  };

  static const List<String> _targetedAttributes = [
    'key',
    'secret',
    'token',
    'password',
    'credential',
  ];

  double calculateEntropy(String value) {
    if (value.isEmpty) return 0.0;
    final Map<String, int> frequencies = {};
    for (var i = 0; i < value.length; i++) {
      final char = value[i];
      frequencies[char] = (frequencies[char] ?? 0) + 1;
    }

    double entropy = 0.0;
    for (final count in frequencies.values) {
      final pi = count / value.length;
      entropy -= pi * (math.log(pi) / math.log(2));
    }
    return entropy;
  }

  @override
  bool validate(
      XmlDocument document,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false}) {
    bool hasFailure = false;
    bool foundAnySecret = false;

    // We scan all attributes in all elements of the manifest
    for (final element in document.findAllElements('*')) {
      final elementPath = element.name.local;
      final elementName = element.getAttribute('android:name') ?? '';

      for (final attribute in element.attributes) {
        final attrName = attribute.name.local.toLowerCase();
        final attrValue = attribute.value;

        // Contextual Filtering
        if (attrValue.startsWith('@') || attrValue.startsWith('\$')) continue;
        if (attrValue.length < 16) continue;

        // 1. Signature Matching (High Confidence)
        String? matchedSignature;
        _signatures.forEach((key, pattern) {
          if (RegExp(pattern).hasMatch(attrValue)) {
            matchedSignature = key;
          }
        });

        if (matchedSignature != null) {
          onFail(
              'Android',
              'High-Confidence Secret Detected ($matchedSignature)',
              'Remove hardcoded secrets from AndroidManifest.xml. Use local.properties or CI secrets instead.',
              'high');
          hasFailure = true;
          foundAnySecret = true;
          continue; // Move to next attribute
        }

        // 2. Entropy-based Detection (Targeted Context)
        // Check if the attribute name itself is targeted OR if the element name (like in meta-data) is targeted
        final isTargeted = _targetedAttributes.any((t) =>
            attrName.contains(t) ||
            elementName.toLowerCase().contains(t) ||
            elementPath.toLowerCase().contains(t));

        if (isTargeted) {
          final entropy = calculateEntropy(attrValue);
          if (entropy > 4.5) {
            onFail(
                'Android',
                'Potential Secret Detected (High Entropy: ${entropy.toStringAsFixed(2)})',
                'Attribute "$attrName" in <$elementPath> contains a high-entropy string that looks like a secret. Verify if this should be externalized.',
                'medium');
            foundAnySecret = true;
          }
        }
      }
    }

    if (!foundAnySecret) {
      onPass('Android', 'Secrets Audit (No unencrypted keys found)');
    }

    return hasFailure;
  }
}
