/// Functions to get issue url.
///
// Time-stamp: <Tuesday 2024-01-02 15:57:15 +1100 Zheyuan Xu>
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

import 'package:solid/src/login/api/rest_api.dart';

/// Extracts the issuer URI from a given RDF string in Turtle format.
///
/// This function parses a profile RDF string [profileRdfStr] in Turtle format
/// to find the issuer URI. It processes each line of the RDF string, searching
/// for the 'solid:oidcIssuer' predicate. Once found, it extracts and returns
/// the associated URI.

String getIssuerUri(String profileRdfStr) {
  var issuerUri = '';
  final profileDataList = profileRdfStr.split('\n');
  for (var i = 0; i < profileDataList.length; i++) {
    final dataItem = profileDataList[i];
    if (dataItem.contains(';')) {
      final itemList = dataItem.split(';');
      for (var j = 0; j < itemList.length; j++) {
        final item = itemList[j];
        if (item.contains('solid:oidcIssuer')) {
          final issuerUriDivide = item.replaceAll(' ', '').split('<');
          issuerUri = issuerUriDivide[1].replaceAll('>', '');
        }
      }
    }
  }
  return issuerUri;
}

/// Asynchronously retrieves the issuer URI from a given URL.
///
/// This function aims to extract the issuer URI associated with a Solid
/// identity by processing a provided URL [textUrl]. It primarily focuses on
/// handling URLs that point to a Solid profile (identified by containing
/// 'profile/card#me'). If such a pattern is detected, the function fetches
/// the profile data using `fetchProfileData` and then extracts the issuer URI
/// using `getIssuerUri`.

Future<String> getIssuer(String textUrl) async {
  var issuerUri = '';
  if (textUrl.contains('profile/card#me')) {
    final pubProf = await fetchProfileData(textUrl);
    issuerUri = getIssuerUri(pubProf);
  }

  if (issuerUri == '') {
    /// This reg expression works with localhost and other urls
    final exp = RegExp(r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+(\.|\:)[\w\.]+');
    final matches = exp.allMatches(textUrl);
    for (final match in matches) {
      issuerUri = textUrl.substring(match.start, match.end);
    }
  }
  return issuerUri;
}
