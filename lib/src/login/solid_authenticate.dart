/// Solid authenticate function, return null if authenticate function fails.
///
// Time-stamp: <Wednesday 2024-01-03 10:57:15 +1100 Zheyuan Xu>
///
/// Copyright (C) 2024, Software Innovation Institute, ANU.
///
/// Licensed under the MIT License (the "License").
///
/// License: https://choosealicense.com/licenses/mit/.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
///
/// Authors: Zheyuan Xu
library;

import 'package:fast_rsa/fast_rsa.dart';
import 'package:flutter/material.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:openid_client/openid_client.dart';
import 'package:solid/src/auth_manager/auth_manager_abstract.dart';
import 'package:solid/src/login/api/rest_api.dart';
import 'package:solid/src/login/issue_url.dart';
import 'package:solid/src/login/platform_info.dart';

// Scopes variables used in the authentication process.

final List<String> _scopes = <String>[
  'openid',
  'profile',
  'offline_access',
];

/// An asynchronous function designed to authenticate a user
/// against a Solid server.
/// [serverId] is an issuer URI and is essential for the
/// authentication process with the POD (Personal Online Datastore) issuer.
/// [context] is used in the authenticate method.
/// The authentication process requires the context of the current widget.
///
/// The function returns a list containing authentication data, the user's webId,
/// and their profile data.
/// Error Handling: The function has a broad error handling mechanism (on ()), which returns null
/// if any exception occurs during the authentication process.

Future<List<dynamic>?> solidAuthenticate(
    String serverId, BuildContext context) async {
  try {
    final issuerUri = await getIssuer(serverId);

    // Authentication process for the POD issuer.

    // ignore: use_build_context_synchronously
    final authData = await authenticate(Uri.parse(issuerUri), _scopes, context);

    final accessToken = authData['accessToken'].toString();
    final decodedToken = JwtDecoder.decode(accessToken);
    final webId = decodedToken['webid'].toString();

    final rsaInfo = authData['rsaInfo'];
    final rsaKeyPair = rsaInfo['rsa'];
    final publicKeyJwk = rsaInfo['pubKeyJwk'];
    final profCardUrl = webId.replaceAll('#me', '');
    final dPopToken =
        genDpopToken(profCardUrl, rsaKeyPair as KeyPair, publicKeyJwk, 'GET');

    final profData = await fetchPrvFile(profCardUrl, accessToken, dPopToken);

    return [authData, webId, profData];
  } on () {
    return null;
  }
}

/// The authentication function
Future<Map> authenticate(
    Uri issuerUri, List<String> scopes, BuildContext context) async {
  /// Platform type parameter
  String platformType;

  /// Re-direct URIs
  String redirUrl;
  List redirUriList;

  /// Authentication method
  String authMethod;

  /// Authentication response
  Credential authResponse;

  /// Output data from the authentication
  Map authData;

PlatformInfo currPlatform = PlatformInfo();

AuthManager authManager = AuthManager();


  /// Check the platform
  if (currPlatform.isWeb()) {
    platformType = 'web';
  } else if (currPlatform.isAppOS()) {
    platformType = 'mobile';
  } else {
    platformType = 'desktop';
  }

  /// Get issuer metatada
  Issuer issuer = await Issuer.discover(issuerUri);

  /// Get end point URIs
  String regEndPoint = issuer.metadata['registration_endpoint'].toString();
  String tokenEndPoint = issuer.metadata['token_endpoint'].toString();
  var authMethods = issuer.metadata['token_endpoint_auth_methods_supported'];

  if (authMethods is String) {
    authMethod = authMethods;
  } else {
    if ((authMethods as List).contains('client_secret_basic')) {
      authMethod = 'client_secret_basic';
    } else {
      authMethod = authMethods[1].toString();
    }
  }

  if (platformType == 'web') {
    redirUrl = authManager.getWebUrl().toString();
    redirUriList = [redirUrl];
  } else {
    redirUrl = 'http://localhost:$_port/';
    redirUriList = ['http://localhost:$_port/'];
  }

  /// Dynamic registration of the client (our app)
  var regResponse =
      await clientDynamicReg(regEndPoint, redirUriList, authMethod);

  /// Decode the registration details
  var regResJson = jsonDecode(regResponse);

  /// Generating the RSA key pair
  Map rsaResults = await genRsaKeyPair();
  var rsaKeyPair = rsaResults['rsa'];
  var publicKeyJwk = rsaResults['pubKeyJwk'];

  ///Generate DPoP token using the RSA private key
  String dPopToken =
      genDpopToken(tokenEndPoint, rsaKeyPair, publicKeyJwk, "POST");

  final String _clientId = regResJson['client_id'];
  final String _clientSecret = regResJson['client_secret'];
  var client = Client(issuer, _clientId, clientSecret: _clientSecret);

  if (platformType != 'web') {
    /// Create a function to open a browser with an url
    urlLauncher(String url) async {
      // if (await canLaunch(url)) {
      //   await launch(url, forceWebView: true, enableJavaScript: true);
      // } else {
      //   throw 'Could not launch $url';
      // }

      if (await canLaunchUrl(Uri.parse(url))) {
        await launchUrl(Uri.parse(url));
      } else {
        throw 'Could not launch $url';
      }
    }

    /// create an authenticator
    var authenticator = oidc_mobile.Authenticator(
      client,
      scopes: scopes,
      port: _port,
      urlLancher: urlLauncher,
      redirectUri: Uri.parse(redirUrl),
      popToken: dPopToken,
    );

    /// starts the authentication + authorisation process
    authResponse = await authenticator.authorize();

    /// close the webview when finished
    /// closing web view function does not work in Windows applications
    if (platformType == 'mobile') {
      //closeWebView();
      closeInAppWebView();
    }
  } else {
    ///create an authenticator
    var authenticator =
        authManager.createAuthenticator(client, scopes, dPopToken);

    var oidc = authManager.getOidcWeb();
    var callbackUri = await oidc.authorizeInteractive(
        context: context,
        title: 'authProcess',
        authorizationUrl: authenticator.flow.authenticationUri.toString(),
        redirectUrl: redirUrl,
        popupWidth: 700,
        popupHeight: 500);

    var regResponse = Uri.parse(callbackUri).queryParameters;
    authResponse = await authenticator.flow.callback(regResponse);
  }

  var tokenResponse = await authResponse.getTokenResponse();
  String? accessToken = tokenResponse.accessToken;

  /// Generate the logout URL
  final _logoutUrl = authResponse.generateLogoutUrl().toString();

  /// Store authentication data
  authData = {
    'client': client,
    'rsaInfo': rsaResults,
    'authResponse': authResponse,
    'tokenResponse': tokenResponse,
    'accessToken': accessToken,
    'idToken': tokenResponse.idToken,
    'refreshToken': tokenResponse.refreshToken,
    'expiresIn': tokenResponse.expiresIn,
    'logoutUrl': _logoutUrl
  };

  return authData;
}
