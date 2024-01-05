import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import 'package:jose/jose.dart';
import 'package:openid_client/openid_client.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:solid/src/login/http_util.dart';

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

    var json = await get(uri, client: httpClient);
    return _discoveries[uri] =
        Issuer(OpenIdProviderMetadata.fromJson(json as Map<String, dynamic>));
  }
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
}
