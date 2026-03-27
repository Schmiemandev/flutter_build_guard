import 'dart:io';
import 'package:test/test.dart';
import 'package:path/path.dart' as p;
import 'package:flutter_build_guard/flutter_build_guard.dart';

class MockProcessWrapper implements ProcessWrapper {
  final int exitCode;
  final String stdout;
  final String stderr;

  MockProcessWrapper({this.exitCode = 0, this.stdout = '', this.stderr = ''});

  @override
  Future<ProcessResult> run(String executable, List<String> arguments,
      {String? workingDirectory, Map<String, String>? environment}) async {
    return ProcessResult(0, exitCode, stdout, stderr);
  }
}

void main() {
  group('Gradle Merge Logic', tags: ['Functional'], () {
    late Directory tempDir;
    late String originalCwd;

    setUp(() async {
      tempDir = await TestUtils.createIsolatedTestEnvironment();
      originalCwd = Directory.current.path;
      Directory.current = tempDir;

      // Create a dummy gradlew file
      final androidDir = Directory(p.join(tempDir.path, 'android'))
        ..createSync();
      File(p.join(androidDir.path, 'gradlew')).writeAsStringSync('');

      // Create the expected output directory structure
      final manifestDir = Directory(p.join(tempDir.path, 'build', 'app',
          'intermediates', 'merged_manifests', 'release'))
        ..createSync(recursive: true);
      File(p.join(manifestDir.path, 'AndroidManifest.xml'))
          .writeAsStringSync('<manifest></manifest>');
    });

    tearDown(() async {
      Directory.current = originalCwd;
      await tempDir.delete(recursive: true);
    });

    test('runAndroidMerge: Successfully locates manifest after mock run',
        () async {
      final mockWrapper = MockProcessWrapper();
      final result = await runAndroidMerge(wrapper: mockWrapper);

      expect(result, isNotNull);
      expect(result, contains('AndroidManifest.xml'));
      expect(result, contains('release'));
    });

    test('runAndroidMerge: Returns null if gradlew missing', () async {
      // Delete the gradlew file created in setUp
      File(p.join(tempDir.path, 'android', 'gradlew')).deleteSync();

      final result = await runAndroidMerge();
      expect(result, isNull);
    });

    test('runAndroidMerge: Throws GradleBuildException if gradle fails',
        () async {
      final mockWrapper = MockProcessWrapper(exitCode: 1);
      expect(() => runAndroidMerge(wrapper: mockWrapper),
          throwsA(isA<GradleBuildException>()));
    });

    test(
        'runAndroidMerge: Throws ManifestMergeException if manifest merger fails',
        () async {
      final mockWrapper = MockProcessWrapper(
          exitCode: 1,
          stderr: 'Execution failed for task :app:processReleaseMainManifest.');
      expect(() => runAndroidMerge(wrapper: mockWrapper),
          throwsA(isA<ManifestMergeException>()));
    });

    test('runAndroidMerge: Prioritizes release manifest over debug', () async {
      // Create a debug manifest as well
      final debugDir = Directory(p.join(tempDir.path, 'build', 'app',
          'intermediates', 'merged_manifests', 'debug'))
        ..createSync(recursive: true);
      File(p.join(debugDir.path, 'AndroidManifest.xml'))
          .writeAsStringSync('<manifest></manifest>');

      final mockWrapper = MockProcessWrapper();
      final result = await runAndroidMerge(wrapper: mockWrapper);

      expect(result, contains('release'));
    });
  });
}
