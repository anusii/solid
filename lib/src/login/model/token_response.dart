import 'package:clock/clock.dart';
import 'package:jose/src/util.dart';
import 'package:solid/src/login/model/token.dart';

class TokenResponse extends JsonObject {
  /// OAuth 2.0 Access Token
  ///
  /// This is returned unless the response_type value used is `id_token`.
  String? get accessToken => this['access_token'].toString();

  /// OAuth 2.0 Token Type value
  ///
  /// The value MUST be Bearer or another token_type value that the Client has
  /// negotiated with the Authorization Server.
  String? get tokenType => this['token_type'].toString();

  /// Refresh token
  String? get refreshToken => this['refresh_token'].toString();

  /// Expiration time of the Access Token since the response was generated.
  Duration? get expiresIn => expiresAt == null
      ? getTyped('expires_in')
      : expiresAt!.difference(clock.now());

  /// ID Token
  IdToken get idToken =>
      getTyped('id_token', factory: (v) => IdToken.unverified(v.toString()))!;

  DateTime? get expiresAt => getTyped('expires_at');

  TokenResponse.fromJson(Map<String, dynamic> json)
      : super.from({
          if (json['expires_in'] != null && json['expires_at'] == null)
            'expires_at': DateTime.now()
                    .add(Duration(
                        seconds: json['expires_in'] is String
                            ? int.parse(json['expires_in'].toString())
                            : json['expires_in'] as int))
                    .millisecondsSinceEpoch ~/
                1000,
          ...json,
        });
}
