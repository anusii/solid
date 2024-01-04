
import 'package:jose/jose.dart';
import 'package:solid/src/login/model/claims.dart';


class IdToken extends JsonWebToken {
  IdToken.unverified(String serialization) : super.unverified(serialization);

  @override
  OpenIdClaims get claims => OpenIdClaims.fromJson(super.claims.toJson());
}
