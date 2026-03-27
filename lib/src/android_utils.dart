import 'dart:io';
import 'package:path/path.dart' as p;
import 'test_utils.dart';

typedef LogCallback = void Function(String message, {bool isProgress});

class ManifestMergeException implements Exception {
  final String message;
  ManifestMergeException(this.message);
  @override
  String toString() => 'ManifestMergeException: $message';
}

class GradleBuildException implements Exception {
  final String message;
  GradleBuildException(this.message);
  @override
  String toString() => 'GradleBuildException: $message';
}

/// Executes Gradle merge to analyze final manifest state.
Future<String?> runAndroidMerge({
  ProcessWrapper? wrapper,
  LogCallback? logger,
  bool verbose = false,
}) async {
  final processWrapper = wrapper ?? DefaultProcessWrapper();
  final gradleWrapper =
      File(p.join(Directory.current.path, 'android', 'gradlew'));

  if (!gradleWrapper.existsSync()) {
    logger?.call('Skip: Android gradlew not found.', isProgress: true);
    return null;
  }

  final env = Map<String, String>.from(Platform.environment);

  // Task: Query Flutter SDK for bundled Java if JAVA_HOME is missing.
  if (!env.containsKey('JAVA_HOME')) {
    logger?.call(
        'automatically trying to discover java because JAVA_HOME not set',
        isProgress: true);
    final flutterDoctor = await processWrapper.run('flutter', ['doctor', '-v']);
    if (flutterDoctor.exitCode == 0) {
      final output = flutterDoctor.stdout as String;
      final match = RegExp(r'Java binary at: (.*)').firstMatch(output);
      if (match != null) {
        final javaBinaryPath = match.group(1)!.trim();
        final javaHome = File(javaBinaryPath).parent.parent.path;
        env['JAVA_HOME'] = javaHome;
        env['PATH'] = '${env['PATH']}:${p.join(javaHome, 'bin')}';
        logger?.call('Successfully discovered java at: $javaHome',
            isProgress: true);
      }
    }
  }

  logger?.call('Merging Android Manifests (this may take a moment)...',
      isProgress: true);

  // Task: Run manifest merge using absolute path and custom environment.
  final result = await processWrapper.run(
      gradleWrapper.path, ['processReleaseManifest'],
      workingDirectory: 'android', environment: env);

  if (verbose) {
    print('\n--- Gradle Output ---');
    print(result.stdout);
    print(result.stderr);
    print('---------------------\n');
  }

  if (result.exitCode != 0) {
    final stderr = result.stderr.toString();
    if (stderr.contains('processReleaseMainManifest') ||
        stderr.contains('ManifestMerger2')) {
      throw ManifestMergeException(stderr);
    }
    throw GradleBuildException(stderr);
  }

  // Task: Dynamically locate merged manifest with preference for 'release' builds.
  final searchRoot = Directory(p.join(Directory.current.path, 'build', 'app',
      'intermediates', 'merged_manifests'));

  if (searchRoot.existsSync()) {
    final manifestFiles = searchRoot
        .listSync(recursive: true)
        .whereType<File>()
        .where((file) => p.basename(file.path) == 'AndroidManifest.xml')
        .toList();

    // Sort: Ensure 'release' paths are prioritized over 'debug' or other flavors.
    manifestFiles.sort((a, b) {
      final aIsRelease = a.path.contains('release');
      final bIsRelease = b.path.contains('release');
      if (aIsRelease && !bIsRelease) return -1;
      if (!aIsRelease && bIsRelease) return 1;
      return 0;
    });

    final manifestFile = manifestFiles.firstOrNull;

    if (manifestFile != null) {
      return p.relative(manifestFile.path, from: Directory.current.path);
    }
  }

  logger?.call(
      'Error: Could not locate merged manifest in ${p.join('build', 'app', 'intermediates', 'merged_manifests')}');
  return null;
}
