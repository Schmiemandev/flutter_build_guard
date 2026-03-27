import 'dart:io';
import 'package:path/path.dart' as p;

/// Shared test utilities for flutter_build_guard test suites.
class TestUtils {
  static Future<Directory> createIsolatedTestEnvironment() async {
    return await Directory.systemTemp
        .createTemp('flutter_build_guard_refactor_');
  }

  static void createAndroidManifest(Directory dir, String content) {
    File(p.join(dir.path, 'AndroidManifest.xml')).writeAsStringSync(content);
  }

  static void createInfoPlist(Directory dir, String content) {
    final iosDir = Directory(p.join(dir.path, 'ios', 'Runner'))
      ..createSync(recursive: true);
    File(p.join(iosDir.path, 'Info.plist')).writeAsStringSync(content);
  }

  static String getMinimalSecureAndroidManifest() {
    return '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="false" android:usesCleartextTraffic="false">
    </application>
</manifest>
''';
  }

  static String getMinimalSecureInfoPlist() {
    return '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<false/>
	</dict>
</dict>
</plist>
''';
  }
}

/// Abstract wrapper to allow mocking of process execution.
abstract class ProcessWrapper {
  Future<ProcessResult> run(String executable, List<String> arguments,
      {String? workingDirectory, Map<String, String>? environment});
}

class DefaultProcessWrapper implements ProcessWrapper {
  @override
  Future<ProcessResult> run(String executable, List<String> arguments,
          {String? workingDirectory, Map<String, String>? environment}) =>
      Process.run(executable, arguments,
          workingDirectory: workingDirectory, environment: environment);
}
