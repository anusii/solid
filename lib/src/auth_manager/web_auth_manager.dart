// Dart imports:
import 'dart:html';

// Project imports:
import 'package:openid_client/openid_client_browser.dart';
import 'package:openidconnect_web/openidconnect_web.dart';

import 'auth_manager_abstract.dart';

late Window windowLoc;

class WebAuthManager implements AuthManager {
  WebAuthManager() {
    windowLoc = window;
    // storing something initially just to make sure it works.
    windowLoc.localStorage["MyKey"] = "I am from web local storage";
  }

  String getWebUrl() {
    if (window.location.href.contains('#/')) {
      return window.location.href.replaceAll('#/', 'callback.html');
    } else {
      return (window.location.href + 'callback.html');
    }
  }

  Authenticator createAuthenticator(
      Client client, List<String> scopes, String dPopToken) {
    var authenticator =
        Authenticator(client, scopes: scopes, popToken: dPopToken);
    return authenticator;
  }

  OpenIdConnectWeb getOidcWeb() {
    OpenIdConnectWeb oidc = OpenIdConnectWeb();
    return oidc;
  }

  String getKeyValue(String key) {
    return windowLoc.localStorage[key]!;
  }

  userLogout(String logoutUrl) {
    final child = window.open(logoutUrl, "user_logout");
    child.close();
  }
}

AuthManager getAuthManager() => WebAuthManager();
