import 'package:xml/xml.dart';
import 'base_rule.dart';

class AndroidComponentHijackRule extends AndroidRule {
  const AndroidComponentHijackRule();
  @override
  bool validate(
      XmlDocument document,
      RuleConfig config,
      void Function(String, String, String, String) onFail,
      void Function(String, String) onPass,
      void Function(String, String, String) onSkip,
      {bool verbose = false}) {
    bool failed = false;
    final components = [
      ...document.findAllElements('activity'),
      ...document.findAllElements('service'),
      ...document.findAllElements('receiver'),
      ...document.findAllElements('provider'),
    ];

    if (components.isEmpty) {
      onSkip('Android', 'Component Hijacking', 'No components found.');
      return false;
    }

    for (var node in components) {
      final name = node.getAttribute('android:name');
      final nodeType = node.name.local;

      if (config.ignoreComponents.contains(name)) {
        onPass('Android', 'Component Hijacking (Ignored: $name)');
        continue;
      }

      final isExportedAttr =
          node.getAttribute('android:exported')?.toLowerCase();
      final intentFilters = node.findElements('intent-filter');

      // Default exported status:
      // - If android:exported is explicitly set, use it.
      // - If not set, it's true if there's at least one intent filter (for most components).
      bool isExported = isExportedAttr == 'true';
      if (isExportedAttr == null && intentFilters.isNotEmpty) {
        isExported = true;
      }

      final hasPermission = node.getAttribute('android:permission') != null ||
          node.getAttribute('android:readPermission') != null ||
          node.getAttribute('android:writePermission') != null;

      if (isExported && !hasPermission) {
        // Providers usually don't have intent filters but are exported by default on older APIs or if explicitly set.
        // For non-providers, we specifically care about exported components with intent filters (common entry points).
        bool shouldFlag = false;
        if (nodeType == 'provider') {
          shouldFlag = true;
        } else if (intentFilters.isNotEmpty) {
          shouldFlag = true;
        }

        if (shouldFlag) {
          bool isLauncher = false;
          for (var filter in intentFilters) {
            final actions = filter
                .findElements('action')
                .map((e) => e.getAttribute('android:name'));
            final categories = filter
                .findElements('category')
                .map((e) => e.getAttribute('android:name'));
            if (actions.contains('android.intent.action.MAIN') &&
                categories.contains('android.intent.category.LAUNCHER')) {
              isLauncher = true;
              break;
            }
          }

          if (isLauncher) {
            onPass(
                'Android', 'Component Hijacking (Warning: $name is launcher)');
          } else {
            onFail(
                'Android',
                'Component Hijacking',
                'Exported $nodeType ($name) lacks permission.',
                config.severity);
            failed = true;
          }
        }
      }
    }

    if (!failed) {
      onPass(
          'Android', 'Component Hijacking (All exported components protected)');
    }
    return failed;
  }
}
