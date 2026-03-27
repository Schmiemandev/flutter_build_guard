/// High Security Preset: All rules enabled with high severity.
const String highConfigYaml = '''
# flutter_build_guard: High Security Policy (Strict)
scanner_settings:
  fail_on_process_error: true
  stop_on_first_fail: false

rules:
  android:
    backup_leaks: { enabled: true, severity: high }
    cleartext_traffic: { enabled: true, severity: high }
    component_hijacking: { enabled: true, severity: high }
    debuggable_enabled: { enabled: true, severity: high }
    proguard_misconfiguration: { enabled: true, severity: high }
    network_security_config: { enabled: true, severity: high }
    android_secret_auditor: { enabled: true, severity: high }
    deep_link_hijacking: { enabled: true, severity: high }
  ios:
    insecure_network: { enabled: true, severity: high }
    deep_link_hijacking: { enabled: true, severity: high }
    apple_privacy_manifest: { enabled: true, severity: high }
''';

/// Medium Security Preset: Balanced security with mixed severities.
const String medConfigYaml = '''
# flutter_build_guard: Medium Security Policy (Balanced)
scanner_settings:
  fail_on_process_error: true
  stop_on_first_fail: false

rules:
  android:
    backup_leaks: { enabled: true, severity: high }
    cleartext_traffic: { enabled: true, severity: high }
    component_hijacking: { enabled: true, severity: medium }
    debuggable_enabled: { enabled: true, severity: high }
    proguard_misconfiguration: { enabled: true, severity: medium }
    network_security_config: { enabled: true, severity: high }
    android_secret_auditor: { enabled: true, severity: high }
    deep_link_hijacking: { enabled: true, severity: medium }
  ios:
    insecure_network: { enabled: true, severity: high }
    deep_link_hijacking: { enabled: true, severity: medium }
    apple_privacy_manifest: { enabled: true, severity: high }
''';

/// Low Security Preset: All rules enabled but treated as warnings.
const String lowConfigYaml = '''
# flutter_build_guard: Low Security Policy (Permissive)
scanner_settings:
  fail_on_process_error: false
  stop_on_first_fail: false

rules:
  android:
    backup_leaks: { enabled: true, severity: low }
    cleartext_traffic: { enabled: true, severity: low }
    component_hijacking: { enabled: true, severity: low }
    debuggable_enabled: { enabled: true, severity: low }
    proguard_misconfiguration: { enabled: true, severity: low }
    network_security_config: { enabled: true, severity: low }
    android_secret_auditor: { enabled: true, severity: low }
    deep_link_hijacking: { enabled: true, severity: low }
  ios:
    insecure_network: { enabled: true, severity: low }
    deep_link_hijacking: { enabled: true, severity: low }
    apple_privacy_manifest: { enabled: true, severity: low }
''';

/// Default configuration used for internal fallbacks.
const String defaultConfigYaml = medConfigYaml;
