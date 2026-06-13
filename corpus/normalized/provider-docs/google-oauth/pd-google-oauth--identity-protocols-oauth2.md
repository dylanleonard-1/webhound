# Google OAuth 2.0 overview

Source: https://developers.google.com/identity/protocols/oauth2
Provider: Google OAuth / Identity | Authority: Tier A
Ingested: 2026-06-13 | Terms: Google developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Using OAuth 2.0 to Access Google APIs  |  Authorization  |  Google for Developers
Skip to main content
Google
Identity
Authentication
Sign In with Google
App Verification
Passkeys
Credential sharing
Samples
Authorization
Account Authorization
App verification to use Google Authorization APIs
Account Linking
Resources
Cross-platform
Implement identity for Android ⍈
Implement identity for Web ⍈
Implement identity for iOS
Cross-Account Protection (RISC)
Policies
OAuth 2.0 Policy
/
English
Deutsch
Español
Español – América Latina
Français
Indonesia
Italiano
Polski
Português – Brasil
Tiếng Việt
Türkçe
Русский
עברית
العربيّة
فارسی
हिंदी
বাংলা
ภาษาไทย
中文 – 简体
中文 – 繁體
日本語
한국어
Sign in
Authorization
Google Account Authorization
App verification to use Google Authorization APIs
Google Account Linking
Resources
Google
Identity
Authentication
More
Authorization
More
Google Account Authorization
App verification to use Google Authorization APIs
Google Account Linking
Resources
Cross-platform
More
Cross-Account Protection (RISC)
Policies
More
Google account authorization
Overview
Cross-client identity
OAuth 2.0 scopes
OAuth 2.0 policies
Authorization considerations by app type
for Server-side Web Apps
for JavaScript Web Apps
for Android Apps
for iOS & Desktop Apps
for TV & Device Apps
for Service Accounts
Sign In with Google
App Verification
Passkeys
Credential sharing
Samples
Account Authorization
App verification to use Google Authorization APIs
Account Linking
Resources
Implement identity for Android ⍈
Implement identity for Web ⍈
Implement identity for iOS
OAuth 2.0 Policy
Home
Products
Google Identity
Authorization
Google Account Authorization
Send feedback
Using OAuth 2.0 to Access Google APIs
Stay organized with collections
Save and categorize content based on your preferences.
Page Summary
outlined_flag
Google APIs use the OAuth 2.0 protocol for authentication and authorization, supporting various application scenarios.
The basic steps for accessing a Google API using OAuth 2.0 involve obtaining credentials, getting an access token from the Google Authorization Server, examining granted scopes, sending the access token to the API, and refreshing the token if needed.
Different application types, such as web server, installed, client-side, limited-input device, and service accounts, have specific authorization flows.
Refresh tokens can expire for various reasons, including user actions or policy settings.
Client libraries are available to simplify the implementation of OAuth 2.0 with Google APIs.
Note:  Use of Google's implementation of OAuth 2.0 is governed by
the  OAuth 2.0 Policies .
Google APIs use the
OAuth 2.0 protocol  for authentication and authorization. Google supports common OAuth
2.0 scenarios such as those for web server, client-side, installed, and limited-input device
applications.
To begin, obtain OAuth 2.0 client credentials from the
Google API Console . Then your client application requests an
access token from the Google Authorization Server, extracts a token from the response, and
sends the token to the Google API that you want to access. For an interactive demonstration
of using OAuth 2.0 with Google (including the option to use your own client credentials),
experiment with the  OAuth 2.0
Playground .
This page gives an overview of the OAuth 2.0 authorization scenarios that Google supports,
and provides links to more detailed content. For details about using OAuth 2.0 for
authentication, see  OpenID Connect .
Note:  Given the security implications of getting the implementation
correct, we strongly encourage you to use OAuth 2.0 libraries when interacting with Google's
OAuth 2.0 endpoints. It is a best practice to use well-debugged code provided by others, and
it will help you protect yourself and your users. For more information, see
Client libraries .
Basic steps
All applications follow a basic pattern when accessing a Google API using OAuth 2.0. At a
high level, you follow five steps:
1. Obtain OAuth 2.0 credentials from the Google API Console.
Visit the
Google API Console  to obtain OAuth 2.0 credentials such as a client
ID and client secret that are known to both Google and your application. The set of values
varies based on what type of application you are building. For example, a JavaScript
application does not require a secret, but a web server application does.
You must create an OAuth client appropriate for the platform on which your app will run,
for example:
android
For  Android apps , use the
Android  client type.
For  iOS and macOS apps , use
the  iOS  client type.
code
For  server-side  or  JavaScript web apps  use
the  Web application  client type. Don't use this client type for any other
application, such as native or mobile apps.
chrome_extension
For  Chrome
extensions , use the  Chrome Extension  client type.
tv
For  limited
input devices , such as TV or embedded devices, use the  TVs and Limited Input
devices  client type.
host
For  server-to-server
interactions , use service accounts. No OAuth Client ID is required.
2. Obtain an access token from the Google Authorization Server.
Before your application can access private data using a Google API, it must obtain an
access token that grants access to that API. A single access token can grant varying degrees
of access to multiple APIs. A variable parameter called  scope  controls the set
of resources and operations that an access token permits. During the access-token request,
your application sends one or more values in the  scope  parameter.
There are several ways to make this request, and they vary based on the type of application
you are building. For example, a JavaScript application might request an access token using
a browser redirect to Google, while an application installed on a device that has no browser
uses web service requests. For more information on how to make the request, see
Scenarios  and the detailed implementation guides for each app type.
Some requests require an authentication step wh
