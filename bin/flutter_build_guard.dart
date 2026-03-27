import 'dart:io';

import 'package:args/args.dart';
import 'package:flutter_build_guard/flutter_build_guard.dart';
import 'package:flutter_build_guard/src/constants.dart';
import 'package:path/path.dart' as p;

const String red = '\x1B[31m';
const String green = '\x1B[32m';
const String yellow = '\x1B[33m';
const String reset = '\x1B[0m';

void main(List<String> arguments) async {
  final scanParser = ArgParser()
    ..addFlag('verbose',
        abbr: 'v', help: 'Show full Gradle output', negatable: false)
    ..addFlag('ci', help: 'Enable CI mode (minimal output)', negatable: false)
    ..addFlag('fix',
        help: 'Attempt to auto-remediate issues', negatable: false);

  final initParser = ArgParser();

  final parser = ArgParser()
    ..addCommand('scan', scanParser)
    ..addCommand('init', initParser);

  final results = parser.parse(arguments);

  if (results.command == null) {
    print('Usage: flutter_build_guard <command> [arguments]');
    print('\nAvailable commands:');
    print('  scan    Run security scan');
    print('  init    Initialize default build_guard.yaml');
    exit(64);
  }

  if (results.command?.name == 'init') {
    await _handleInit();
    return;
  }

  if (results.command?.name == 'scan') {
    await _handleScan(results.command!);
    return;
  }
}

Future<void> _handleInit() async {
  final configFile = File(p.join(Directory.current.path, 'build_guard.yaml'));
  if (configFile.existsSync()) {
    print('$yellow[!] build_guard.yaml already exists.$reset');
    return;
  }

  final presetYaml = _promptForPreset();
  print('$yellow[#] Generating build_guard.yaml...$reset');
  await configFile.writeAsString(presetYaml);
  print('$green[+] Successfully initialized build_guard.yaml$reset');
}

Future<void> _handleScan(ArgResults scanArgs,
    {ProcessWrapper? processWrapper}) async {
  final bool verbose = scanArgs['verbose'] ?? false;
  final bool ci = scanArgs['ci'] ?? false;
  final bool fix = scanArgs['fix'] ?? false;
  final wrapper = processWrapper ?? DefaultProcessWrapper();

  if (!File('pubspec.yaml').existsSync()) {
    print(
        '$red[!] Error: Must be run from the root of a Flutter project.$reset');
    exit(1);
  }

  // Auto-discovery logic for build_guard.yaml
  ScannerConfig config;
  final configFile = File(p.join(Directory.current.path, 'build_guard.yaml'));

  if (!configFile.existsSync()) {
    if (ci) {
      config = ScannerConfig.defaultStrict();
    } else {
      print(
          '$yellow[!] No config found. Let\'s set up your security policy.$reset');
      final presetYaml = _promptForPreset();
      await configFile.writeAsString(presetYaml);
      config = ConfigManager.parseYaml(presetYaml);
    }
  } else {
    config = await ConfigManager.load();
  }

  final scanner = SecurityScanner(config);

  _log('$yellow[#] Initializing Security Scan...$reset',
      isProgress: true, ci: ci, verbose: verbose);

  bool hasVulnerabilities = false;
  bool androidScanned = false;
  bool iosScanned = false;
  bool processError = false;

  // Task: Execute Gradle manifest merge to analyze final build state.
  if (Directory('android').existsSync()) {
    try {
      final mergedManifestPath = await runAndroidMerge(
        wrapper: wrapper,
        verbose: verbose,
        logger: (msg, {isProgress = false}) => _log('$yellow[#] $msg$reset',
            ci: ci, verbose: verbose, isProgress: isProgress),
      );
      if (mergedManifestPath != null) {
        androidScanned = true;
        if (await scanner.scanAndroid(
            mergedManifestPath, _printFail, _printPass, _printSkip,
            verbose: verbose, attemptFix: fix)) {
          hasVulnerabilities = true;
        }
      } else {
        if (config.failOnProcessError) processError = true;
      }
    } on ManifestMergeException catch (e) {
      print('$red[!] SCAN FAILED: Android Manifest Merge Failed.$reset');
      print(
          '    Likely causes: An XML syntax error (e.g., missing closing tag) OR a plugin merge conflict.');
      print(
          '    Run the scan again with the -v or --verbose flag to see the full Gradle stack trace.');
      if (verbose) {
        print('\n${e.message}');
      }
      exit(1);
    } on GradleBuildException catch (e) {
      print('$red[!] SCAN FAILED: The Gradle build failed unexpectedly.$reset');
      print(
          '    Run the scan again with the -v or --verbose flag to see the full Gradle stack trace.');
      if (verbose) {
        print('\n${e.message}');
      }
      exit(1);
    }
  } else {
    _log(
        '$yellow[#] Skipping Android scan: "android" directory not found.$reset',
        isProgress: true,
        ci: ci,
        verbose: verbose);
  }

  // Task: Analyze iOS Info.plist for ATS and permission leaks.
  if (File('ios/Runner/Info.plist').existsSync()) {
    iosScanned = true;
    _log('$yellow[#] Analyzing iOS Info.plist at: ios/Runner/Info.plist$reset',
        isProgress: true, ci: ci, verbose: verbose);
    if (await scanner.scanIOS(_printFail, _printPass, _printSkip,
        verbose: verbose, attemptFix: fix)) {
      hasVulnerabilities = true;
    }
  } else if (Directory('ios').existsSync()) {
    _log(
        '$yellow[!] Warning: "ios" directory found but "ios/Runner/Info.plist" missing. Skipping iOS scan.$reset',
        isProgress: true,
        ci: ci,
        verbose: verbose);
  } else {
    _log('$yellow[#] Skipping iOS scan: "ios" directory not found.$reset',
        isProgress: true, ci: ci, verbose: verbose);
  }

  // Result: Determine build exit code based on findings and execution state.
  if (hasVulnerabilities || processError) {
    final reason = processError
        ? "Tool execution error"
        : "High severity vulnerabilities detected";
    print('\n$red[!] SCAN FAILED: $reason. Breaking build.$reset');
    exit(1);
  } else if (!androidScanned && !iosScanned) {
    print(
        '\n$red[!] ERROR: No mobile platforms (Android/iOS) detected to scan.$reset');
    print(
        '$yellow    If this is a pure Dart package, this tool is not required.$reset');
    exit(1);
  } else {
    print(
        '\n$green[+] SCAN COMPLETE: No critical native configuration leaks found in detected platforms.$reset');
    exit(0);
  }
}

/// Prompts the user to select a security preset level.
String _promptForPreset() {
  if (!stdin.hasTerminal) return medConfigYaml;

  stdout.write(
      '\n[?] Select Security Level (1: Low, 2: Medium [Default], 3: High): ');
  final input = stdin.readLineSync()?.trim();

  switch (input) {
    case '1':
      print('$yellow[#] Applying Low Security Preset (Permissive).$reset');
      return lowConfigYaml;
    case '3':
      print('$red[#] Applying High Security Preset (Strict).$reset');
      return highConfigYaml;
    case '2':
    case '':
    default:
      print('$green[#] Applying Medium Security Preset (Balanced).$reset');
      return medConfigYaml;
  }
}

/// Helper to manage conditional logging for CI and Verbose modes.
void _log(String message,
    {required bool ci, required bool verbose, bool isProgress = false}) {
  if (verbose || !ci || !isProgress) {
    print(message);
  }
}

void _printPass(String platform, String rule) {
  print('$green[PASS]$reset $platform: $rule');
}

void _printSkip(String platform, String rule, String reason) {
  print('$yellow[SKIP]$reset $platform: $rule $reason');
}

void _printFail(String platform, String rule, String fix, String severity) {
  final isHigh = severity.toLowerCase() == 'high';
  final label = isHigh ? '$red[FAIL]$reset' : '$yellow[WARNING]$reset';
  print(
      '$label $platform: $rule\n      $yellow Fix: $fix (Severity: $severity)$reset');
}
