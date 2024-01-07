part of solid_auth;

/// Get POD issuer URI
Future<String> getIssuer(String textUrl) async {
  String _issuerUri = '';
  if (textUrl.contains('profile/card#me')) {
    String pubProf = await fetchProfileData(textUrl);
    _issuerUri = getIssuerUri(pubProf);
  }

  if (_issuerUri == '') {
    /// This reg expression works with localhost and other urls
    RegExp exp = RegExp(r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+(\.|\:)[\w\.]+');
    Iterable<RegExpMatch> matches = exp.allMatches(textUrl);
    matches.forEach((match) {
      _issuerUri = textUrl.substring(match.start, match.end);
    });
  }
  return _issuerUri;
}

/// Get public profile information from webId
Future<String> fetchProfileData(String profUrl) async {
  final response = await http.get(
    Uri.parse(profUrl),
    headers: <String, String>{
      'Content-Type': 'text/turtle',
    },
  );

  if (response.statusCode == 200) {
    /// If the server did return a 200 OK response,
    /// then parse the JSON.
    return response.body;
  } else {
    /// If the server did not return a 200 OK response,
    /// then throw an exception.
    throw Exception('Failed to load data! Try again in a while.');
  }
}

/// Read public profile RDF file and get the issuer URI
String getIssuerUri(String profileRdfStr) {
  String issuerUri = '';
  var profileDataList = profileRdfStr.split('\n');
  for (var i = 0; i < profileDataList.length; i++) {
    String dataItem = profileDataList[i];
    if (dataItem.contains(';')) {
      var itemList = dataItem.split(';');
      for (var j = 0; j < itemList.length; j++) {
        String item = itemList[j];
        if (item.contains('solid:oidcIssuer')) {
          var issuerUriDivide = item.replaceAll(' ', '').split('<');
          issuerUri = issuerUriDivide[1].replaceAll('>', '');
        }
      }
    }
  }
  return issuerUri;
}
