/// The SolidLogin widget to obtain a Solid token to access the user's POD.
//
// Time-stamp: <Tuesday 2023-12-26 15:51:01 +1100 Graham Williams>
//
/// Copyright (C) 2024, Software Innovation Institute, ANU
///
/// Licensed under the MIT License (the "License");
///
/// License: https://choosealicense.com/licenses/mit/
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
/// Authors: Graham Williams

library;

import 'package:flutter/material.dart';

/// A widget to login to a Solid server for a user's token to access their POD.
///
/// The login screen will be the intiial screen of the app when access to the
/// user's POD is required for any of the functionality of the app requires
/// access to the user's POD.
///
/// This widget currently does no more than to return the widget that is
/// supplied as its argument. This is the starting point of its implementation.
/// See https://github.com/anusii/solid/issues/1.

class SolidLogin extends StatelessWidget {
  final Widget child;

  const SolidLogin({required this.child, super.key});

  @override
  Widget build(BuildContext context) {
    return child;
  }
}