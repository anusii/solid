/// Functions with restful APIs.
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

import 'package:http/http.dart' as http;
import 'dart:async';
import 'dart:convert';

/// A function designed to fetch profile data from a specified URL [profCardUrl].
/// It takes three parameters: [profCardUrl] (the URL to fetch data from),
/// [accessToken] (used for authorization), and [dPopToken] (another form
/// of token used in headers for enhanced security).

Future<String> fetchPrvFile(
  String profCardUrl,
  String accessToken,
  String dPopToken,
) async {
  final profResponse = await http.get(
    Uri.parse(profCardUrl),
    headers: <String, String>{
      'Accept': '*/*',
      'Authorization': 'DPoP $accessToken',
      'Connection': 'keep-alive',
      'DPoP': dPopToken,
    },
  );

  if (profResponse.statusCode == 200) {
    // If the server did return a 200 OK response,
    // then parse the JSON.
    return profResponse.body;
  } else {
    // If the server did not return a 200 OK response,
    // then throw an exception.
    //print(profResponse.body);
    throw Exception('Failed to load profile data! Try again in a while.');
  }
}

/// A function designed to fetch profile data from a given URL.
/// [profUrl] is the URL to fetch data from.

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
