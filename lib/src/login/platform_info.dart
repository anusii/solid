// Dart imports:
import 'dart:io';
import 'package:flutter/foundation.dart' show kIsWeb;

// Class to return platform information
class PlatformInfo {
  bool isDesktopOS() {
    return Platform.isMacOS || Platform.isLinux || Platform.isWindows;
  }

  bool isAppOS() {
    return Platform.isIOS || Platform.isAndroid;
  }

  bool isWeb() {
    return kIsWeb;
  }

  PlatformType getCurrentPlatformType() {
    if (kIsWeb) {
      return PlatformType.Web;
    }
    if (Platform.isMacOS) {
      return PlatformType.MacOS;
    }
    if (Platform.isFuchsia) {
      return PlatformType.Fuchsia;
    }
    if (Platform.isLinux) {
      return PlatformType.Linux;
    }
    if (Platform.isWindows) {
      return PlatformType.Windows;
    }
    if (Platform.isIOS) {
      return PlatformType.iOS;
    }
    if (Platform.isAndroid) {
      return PlatformType.Android;
    }
    return PlatformType.Unknown;
  }
}

enum PlatformType { Web, iOS, Android, MacOS, Fuchsia, Linux, Windows, Unknown }
