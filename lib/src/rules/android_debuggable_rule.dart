import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidDebuggableRule extends AndroidRule {
  const AndroidDebuggableRule();
  @override
  bool validate(XmlDocument document, config, onFail, onPass, onSkip,
      {bool verbose = false}) {
    final app = document.findAllElements('application').firstOrNull;
    if (app == null) {
      onSkip('Android', 'Debuggable Enabled', 'No <application> tag found.');
      return false;
    }

    final debuggable = app.getAttribute('android:debuggable')?.toLowerCase();
    if (debuggable == 'true') {
      onFail('Android', 'Debuggable Enabled',
          'Remove android:debuggable="true" from manifest.', config.severity);
      return true;
    }
    onPass('Android', 'Debuggable Enabled (Disabled for production)');
    return false;
  }
}
