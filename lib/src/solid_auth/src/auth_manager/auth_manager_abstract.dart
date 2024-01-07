// import just for the client class. Not used anywhere else.
import 'package:solid_auth/src/openid/src/openid.dart';

import 'auth_manager_stub.dart'
    // ignore: uri_does_not_exist
    // if (dart.library.io) 'MobileOpenId.dart'
    // ignore: uri_does_not_exist
    if (dart.library.html) 'web_auth_manager.dart';

abstract class AuthManager {
  // some generic methods to be exposed.

  // returns a value based on the key
  String getKeyValue(String key) {
    return "I am from the interface";
  }

  getWebUrl() {}
  createAuthenticator(Client client, List<String> scopes, String dPopToken) {}
  getOidcWeb() {}
  userLogout(String logoutUrl) {}

  // factory constructor to return the correct implementation.
  factory AuthManager() => getAuthManager();
}
