part of solid_auth;

/// Dynamically register the user in the POD server
Future<String> clientDynamicReg(
    String regEndPoint, List reidirUrlList, String authMethod) async {
  final response = await http.post(Uri.parse(regEndPoint),
      headers: <String, String>{
        'Accept': '*/*',
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
      },
      body: json.encode({
        "application_type": "web",
        //"client_name": "fluttersolidauth",
        //"id_token_signed_response_alg": "RS256",
        "redirect_uris": reidirUrlList,
        //"subject_type": "pairwise",
        "token_endpoint_auth_method": authMethod,
        //"userinfo_encrypted_response_alg": "RSA1_5",
        //"userinfo_encrypted_response_enc": "A128CBC-HS256",
      }));

  if (response.statusCode == 201) {
    /// If the server did return a 200 OK response,
    /// then parse the JSON.
    return response.body;
  } else {
    /// If the server did not return a 200 OK response,
    /// then throw an exception.
    throw Exception('Failed to load data! Try again in a while.');
  }
}

/// Generate RSA key pair for the authentication
Future<Map> genRsaKeyPair() async {
  /// Generate a key pair
  var rsaKeyPair = await RSA.generate(2048);

  /// JWK conversion of private and public keys
  var publicKeyJwk = await RSA.convertPublicKeyToJWK(rsaKeyPair.publicKey);
  var privateKeyJwk = await RSA.convertPrivateKeyToJWK(rsaKeyPair.privateKey);

  publicKeyJwk['alg'] = "RS256";
  return {
    'rsa': rsaKeyPair,
    'privKeyJwk': privateKeyJwk,
    'pubKeyJwk': publicKeyJwk
  };
}

/// Generate dPoP token for the authentication
String genDpopToken(String endPointUrl, KeyPair rsaKeyPair,
    dynamic publicKeyJwk, String httpMethod) {
  /// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-03
  /// Unique identifier for DPoP proof JWT
  /// Here we are using a version 4 UUID according to https://datatracker.ietf.org/doc/html/rfc4122
  var uuid = const Uuid();
  final String tokenId = uuid.v4();

  /// Initialising token head and body (payload)
  /// https://solid.github.io/solid-oidc/primer/#authorization-code-pkce-flow
  /// https://datatracker.ietf.org/doc/html/rfc7519
  var tokenHead = {"alg": "RS256", "typ": "dpop+jwt", "jwk": publicKeyJwk};

  var tokenBody = {
    "htu": endPointUrl,
    "htm": httpMethod,
    "jti": tokenId,
    "iat": (DateTime.now().millisecondsSinceEpoch / 1000).round()
  };

  /// Create a json web token
  final jwt = JWT(
    tokenBody,
    header: tokenHead,
  );

  /// Sign the JWT using private key
  var dpopToken = jwt.sign(RSAPrivateKey(rsaKeyPair.privateKey),
      algorithm: JWTAlgorithm.RS256);

  return dpopToken;
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
  String regEndPoint = issuer.metadata['registration_endpoint'];
  String tokenEndPoint = issuer.metadata['token_endpoint'];
  var authMethods = issuer.metadata['token_endpoint_auth_methods_supported'];

  if (authMethods is String) {
    authMethod = authMethods;
  } else {
    if (authMethods.contains('client_secret_basic')) {
      authMethod = 'client_secret_basic';
    } else {
      authMethod = authMethods[1];
    }
  }

  if (platformType == 'web') {
    redirUrl = authManager.getWebUrl();
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

Future<bool> logout(_logoutUrl) async {
  Uri url = Uri.parse(_logoutUrl);

  if (await canLaunchUrl(url)) {
    //await launch(_logoutUrl, forceWebView: true);
    await launchUrl(url);
  } else {
    throw 'Could not launch $url';
  }

  await Future.delayed(Duration(seconds: 4));

  /// closing web view function does not work in Windows applications
  if (currPlatform.isAppOS()) {
    //closeWebView();
    closeInAppWebView();
  }
  return true;
}
