import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:jose/jose.dart';
import 'package:openid_client/openid_client.dart';
import 'package:pointycastle/digests/sha256.dart';


class Issuer {
  /// The OpenId Provider's metadata
  final OpenIdProviderMetadata metadata;

  final Map<String, String> claimsMap;

  final JsonWebKeyStore _keyStore;

  /// Creates an issuer from its metadata.
  Issuer(this.metadata, {this.claimsMap = const {}})
      : _keyStore = metadata.jwksUri == null
            ? JsonWebKeyStore()
            : (JsonWebKeyStore()..addKeySetUrl(metadata.jwksUri!));

  /// Url of the facebook issuer.
  ///
  /// Note: facebook does not support OpenID Connect, but the authentication
  /// works.
  static final Uri facebook = Uri.parse('https://www.facebook.com');

  /// Url of the google issuer.
  static final Uri google = Uri.parse('https://accounts.google.com');

  /// Url of the yahoo issuer.
  static final Uri yahoo = Uri.parse('https://api.login.yahoo.com');

  /// Url of the microsoft issuer.
  static final Uri microsoft =
      Uri.parse('https://login.microsoftonline.com/common');

  /// Url of the salesforce issuer.
  static final Uri salesforce = Uri.parse('https://login.salesforce.com');

  static Uri firebase(String id) =>
      Uri.parse('https://securetoken.google.com/$id');

  static final Map<Uri, Issuer?> _discoveries = {
    facebook: Issuer(OpenIdProviderMetadata.fromJson({
      'issuer': facebook.toString(),
      'authorization_endpoint': 'https://www.facebook.com/v2.8/dialog/oauth',
      'token_endpoint': 'https://graph.facebook.com/v2.8/oauth/access_token',
      'userinfo_endpoint': 'https://graph.facebook.com/v2.8/879023912133394',
      'response_types_supported': ['token', 'code', 'code token'],
      'token_endpoint_auth_methods_supported': ['client_secret_post'],
      'scopes_supported': [
        'public_profile',
        'user_friends',
        'email',
        'user_about_me',
        'user_actions.books',
        'user_actions.fitness',
        'user_actions.music',
        'user_actions.news',
        'user_actions.video',
        'user_birthday',
        'user_education_history',
        'user_events',
        'user_games_activity',
        'user_hometown',
        'user_likes',
        'user_location',
        'user_managed_groups',
        'user_photos',
        'user_posts',
        'user_relationships',
        'user_relationship_details',
        'user_religion_politics',
        'user_tagged_places',
        'user_videos',
        'user_website',
        'user_work_history',
        'read_custom_friendlists',
        'read_insights',
        'read_audience_network_insights',
        'read_page_mailboxes',
        'manage_pages',
        'publish_pages',
        'publish_actions',
        'rsvp_event',
        'pages_show_list',
        'pages_manage_cta',
        'pages_manage_instant_articles',
        'ads_read',
        'ads_management',
        'business_management',
        'pages_messaging',
        'pages_messaging_subscriptions',
        'pages_messaging_phone_number'
      ]
    })),
    google: null,
    yahoo: null,
    microsoft: null,
    salesforce: null
  };

  static Iterable<Uri> get knownIssuers => _discoveries.keys;

  /// Discovers the OpenId Provider's metadata based on its uri.
  static Future<Issuer> discover(Uri uri, {http.Client? httpClient}) async {
    if (_discoveries[uri] != null) return _discoveries[uri]!;

    var segments = uri.pathSegments.toList();
    if (segments.isNotEmpty && segments.last.isEmpty) {
      segments.removeLast();
    }
    segments.addAll(['.well-known', 'openid-configuration']);
    uri = uri.replace(pathSegments: segments);

    var json = await http.get(uri, client: httpClient);
    return _discoveries[uri] = Issuer(OpenIdProviderMetadata.fromJson(json));
  }
}


class Credential {
  TokenResponse _token;
  final Client client;
  final String? nonce;

  final StreamController<TokenResponse> _onTokenChanged =
      StreamController.broadcast();

  Credential._(this.client, this._token, this.nonce);

  Map<String, dynamic>? get response => _token.toJson();

  Future<UserInfo> getUserInfo() async {
    var uri = client.issuer.metadata.userinfoEndpoint;
    if (uri == null) {
      throw UnsupportedError('Issuer does not support userinfo endpoint.');
    }
    return UserInfo.fromJson(await _get(uri));
  }

  /// Emits a new [TokenResponse] every time the token is refreshed
  Stream<TokenResponse> get onTokenChanged => _onTokenChanged.stream;

  /// Allows clients to notify the authorization server that a previously
  /// obtained refresh or access token is no longer needed
  ///
  /// See https://tools.ietf.org/html/rfc7009
  Future<void> revoke() async {
    var uri = client.issuer.metadata.revocationEndpoint;
    if (uri == null) {
      throw UnsupportedError('Issuer does not support revocation endpoint.');
    }
    var request = _token.refreshToken != null
        ? {'token': _token.refreshToken, 'token_type_hint': 'refresh_token'}
        : {'token': _token.accessToken, 'token_type_hint': 'access_token'};
    await _post(uri, body: request);
  }

  /// Returns an url to redirect to for a Relying Party to request that an
  /// OpenID Provider log out the End-User.
  ///
  /// [redirectUri] is an url to which the Relying Party is requesting that the
  /// End-User's User Agent be redirected after a logout has been performed.
  ///
  /// [state] is an opaque value used by the Relying Party to maintain state
  /// between the logout request and the callback to [redirectUri].
  ///
  /// See https://openid.net/specs/openid-connect-rpinitiated-1_0.html
  Uri? generateLogoutUrl({Uri? redirectUri, String? state}) {
    return client.issuer.metadata.endSessionEndpoint?.replace(queryParameters: {
      'id_token_hint': _token.idToken.toCompactSerialization(),
      if (redirectUri != null)
        'post_logout_redirect_uri': redirectUri.toString(),
      if (state != null) 'state': state
    });
  }

  http.Client createHttpClient([http.Client? baseClient]) =>
      http.AuthorizedClient(
          baseClient ?? client.httpClient ?? http.Client(), this);

  Future _get(uri) async {
    return http.get(uri, client: createHttpClient());
  }

  Future _post(uri, {dynamic body}) async {
    return http.post(uri, client: createHttpClient(), body: body);
  }

  IdToken get idToken => _token.idToken;

  Stream<Exception> validateToken(
      {bool validateClaims = true, bool validateExpiry = true}) async* {
    var keyStore = JsonWebKeyStore();
    var jwksUri = client.issuer.metadata.jwksUri;
    if (jwksUri != null) {
      keyStore.addKeySetUrl(jwksUri);
    }
    if (!await idToken.verify(keyStore,
        allowedArguments:
            client.issuer.metadata.idTokenSigningAlgValuesSupported)) {
      yield JoseException('Could not verify token signature');
    }

    yield* Stream.fromIterable(idToken.claims
        .validate(
            expiryTolerance: const Duration(seconds: 30),
            issuer: client.issuer.metadata.issuer,
            clientId: client.clientId,
            nonce: nonce)
        .where((e) =>
            validateExpiry ||
            !(e is JoseException && e.message.startsWith('JWT expired.'))));
  }

  String? get refreshToken => _token.refreshToken;

  Future<TokenResponse> getTokenResponse([bool forceRefresh = false]) async {
    if (!forceRefresh &&
        _token.accessToken != null &&
        (_token.expiresAt == null ||
            _token.expiresAt!.isAfter(DateTime.now()))) {
      return _token;
    }
    if (_token.accessToken == null && _token.refreshToken == null) {
      return _token;
    }

    var json = await http.post(client.issuer.tokenEndpoint,
        body: {
          'grant_type': 'refresh_token',
          'token_type': 'DPoP',
          'refresh_token': _token.refreshToken,
          'client_id': client.clientId,
          if (client.clientSecret != null) 'client_secret': client.clientSecret
        },
        client: client.httpClient);
    if (json['error'] != null) {
      throw OpenIdException(
          json['error'], json['error_description'], json['error_uri']);
    }

    //return _token = TokenResponse.fromJson(json);
    _token =
        TokenResponse.fromJson({'refresh_token': _token.refreshToken, ...json});
    _onTokenChanged.add(_token);
    return _token;
  }

  Credential.fromJson(Map<String, dynamic> json, {http.Client? httpClient})
      : this._(
            Client(
                Issuer(OpenIdProviderMetadata.fromJson(
                    (json['issuer'] as Map).cast())),
                json['client_id'],
                clientSecret: json['client_secret'],
                httpClient: httpClient),
            TokenResponse.fromJson((json['token'] as Map).cast()),
            json['nonce']);

  Map<String, dynamic> toJson() => {
        'issuer': client.issuer.metadata.toJson(),
        'client_id': client.clientId,
        'client_secret': client.clientSecret,
        'token': _token.toJson(),
        'nonce': nonce
      };
}

class Client {
  /// The id of the client.
  final String clientId;

  /// A secret for authenticating the client to the OP.
  final String? clientSecret;

  /// The [Issuer] representing the OP.
  final Issuer issuer;

  final http.Client? httpClient;

  Client(this.issuer, this.clientId, {this.clientSecret, this.httpClient});

  static Future<Client> forIdToken(String idToken,
      {http.Client? httpClient}) async {
    var token = JsonWebToken.unverified(idToken);
    var claims = OpenIdClaims.fromJson(token.claims.toJson());
    var issuer = await Issuer.discover(claims.issuer, httpClient: httpClient);
    if (!await token.verify(issuer._keyStore)) {
      throw ArgumentError('Unable to verify token');
    }
    var clientId = claims.authorizedParty ?? claims.audience.single;
    return Client(issuer, clientId, httpClient: httpClient);
  }

  /// Creates a [Credential] for this client.
  Credential createCredential(
          {String? accessToken,
          String? tokenType,
          String? refreshToken,
          Duration? expiresIn,
          DateTime? expiresAt,
          String? idToken}) =>
      Credential._(
          this,
          TokenResponse.fromJson({
            'access_token': accessToken,
            'token_type': tokenType,
            'refresh_token': refreshToken,
            'id_token': idToken,
            if (expiresIn != null) 'expires_in': expiresIn.inSeconds,
            if (expiresAt != null)
              'expires_at': expiresAt.millisecondsSinceEpoch ~/ 1000
          }),
          null);
}
