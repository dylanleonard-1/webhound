## Template
Template is a YAML input file which defines all the requests and
 other metadata for a template.

id  string

ID is the unique id for the template.

#### Good IDs

A good ID uniquely identifies what the requests in the template
are doing. Let's say you have a template that identifies a git-config
file on the webservers, a good name would be `git-config-exposure`. Another
example name is `azure-apps-nxdomain-takeover`.

Examples:

```yaml
# ID Example
id: CVE-2021-19520
```

info  model.Info

Info contains metadata information about the template.

Examples:

```yaml
info:
    name: Argument Injection in Ruby Dragonfly
    author: 0xspara
    tags: cve,cve2021,rce,ruby
    reference: https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/
    severity: high
```

flow  string

description: |
   Flow contains the execution flow for the template.
 examples:
   - flow: |
 		for region in regions {
		    http(0)
		 }
		 for vpc in vpcs {
		    http(1)
		 }

requests  []http.Request

Requests contains the http request to make in the template.
WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.

Examples:

```yaml
requests:
    matchers:
        - type: word
          words:
            - '[core]'
        - type: dsl
          condition: and
          dsl:
            - '!contains(tolower(body), ''

http  []http.Request

description: |
   HTTP contains the http request to make in the template.
 examples:
   - value: exampleNormalHTTPRequest
 RequestsWithHTTP is placeholder(internal) only, and should not be used instead use RequestsHTTP
 Deprecated: Use RequestsHTTP instead.

dns  []dns.Request

DNS contains the dns request to make in the template

Examples:

```yaml
dns:
    extractors:
        - type: regex
          regex:
            - ec2-[-\d]+\.compute[-\d]*\.amazonaws\.com
            - ec2-[-\d]+\.[\w\d\-]+\.compute[-\d]*\.amazonaws\.com
    name: '{{FQDN}}'
    type: CNAME
    class: inet
    retries: 2
    recursion: false
```

file  []file.Request

File contains the file request to make in the template

Examples:

```yaml
file:
    extractors:
        - type: regex
          regex:
            - amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
    extensions:
        - all
```

network  []network.Request

Network contains the network request to make in the template
WARNING: 'network' will be deprecated and will be removed in a future release. Please use 'tcp' instead.

Examples:

```yaml
network:
    host:
        - '{{Hostname}}'
        - '{{Hostname}}:2181'
    inputs:
        - data: "envi\r\nquit\r\n"
    read-size: 2048
    matchers:
        - type: word
          words:
            - zookeeper.version
```

tcp  []network.Request

description: |
   TCP contains the network request to make in the template
 examples:
   - value: exampleNormalNetworkRequest
 RequestsWithTCP is placeholder(internal) only, and should not be used instead use RequestsNetwork
 Deprecated: Use RequestsNetwork instead.

headless  []headless.Request

Headless contains the headless request to make in the template.

ssl  []ssl.Request

SSL contains the SSL request to make in the template.

websocket  []websocket.Request

Websocket contains the Websocket request to make in the template.

whois  []whois.Request

WHOIS contains the WHOIS request to make in the template.

code  []code.Request

Code contains code snippets.

javascript  []javascript.Request

Javascript contains the javascript request to make in the template.

self-contained  bool

Self Contained marks Requests for the template as self-contained

stop-at-first-match  bool

Stop execution once first match is found

signature  http.SignatureTypeHolder

Signature is the request signature method
WARNING: 'signature' will be deprecated and will be removed in a future release. Prefer using 'code' protocol for writing cloud checks

Valid values:

  - AWS

variables  variables.Variable

Variables contains any variables for the current request.

constants  map[string]interface{}

Constants contains any scalar constant for the current template

## model.Info
Info contains metadata information about a template

Appears in:

- Template.info

```yaml
name: Argument Injection in Ruby Dragonfly
author: 0xspara
tags: cve,cve2021,rce,ruby
reference: https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/
severity: high
```

name  string

Name should be good short summary that identifies what the template does.

Examples:

```yaml
name: bower.json file disclosure
```

```yaml
name: Nagios Default Credentials Check
```

author  stringslice.StringSlice

Author of the template.

Multiple values can also be specified separated by commas.

Examples:

```yaml
author:
```

tags  stringslice.StringSlice

Any tags for the template.

Multiple values can also be specified separated by commas.

Examples:

```yaml
# Example tags
tags: cve,cve2019,grafana,auth-bypass,dos
```

description  string

Description of the template.

You can go in-depth here on what the template actually does.

Examples:

```yaml
description: Bower is a package manager which stores package information in the bower.json file
```

```yaml
description: Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations
```

impact  string

Impact of the template.

You can go in-depth here on impact of the template.

Examples:

```yaml
impact: Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation.
```

```yaml
impact: Successful exploitation of this vulnerability could allow an attacker to execute arbitrary script code in the context of the victim's browser, potentially leading to session hijacking, defacement, or theft of sensitive information.
```

reference  stringslice.RawStringSlice

References for the template.

This should contain links relevant to the template.

Examples:

```yaml
reference:
    - https://github.com/strapi/strapi
    - https://github.com/getgrav/grav
```

severity  severity.Holder

Severity of the template.

metadata  map[string]interface{}

Metadata of the template.

Examples:

```yaml
metadata:
    customField1: customValue1
```

classification  model.Classification

Classification contains classification information about the template.

remediation  string

Remediation steps for the template.

You can go in-depth here on how to mitigate the problem found by this template.

Examples:

```yaml
remediation: Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties
```

## stringslice.StringSlice
StringSlice represents a single (in-lined) or multiple string value(s).
 The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.

Appears in:

- model.Info.author

- model.Info.tags

- model.Classification.cve-id

- model.Classification.cwe-id

```yaml

```
```yaml
# Example tags
cve,cve2019,grafana,auth-bypass,dos
```
```yaml
CVE-2020-14420
```
```yaml
CWE-22
```

## stringslice.RawStringSlice

Appears in:

- model.Info.reference

```yaml
- https://github.com/strapi/strapi
- https://github.com/getgrav/grav
```

## severity.Holder
Holder holds a Severity type. Required for un/marshalling purposes

Appears in:

- model.Info.severity

  Severity

Enum Values:

  - undefined

  - info

  - low

  - medium

  - high

  - critical

  - unknown

## model.Classification

Appears in:

- model.Info.classification

cve-id  stringslice.StringSlice

CVE ID for the template

Examples:

```yaml
cve-id: CVE-2020-14420
```

cwe-id  stringslice.StringSlice

CWE ID for the template.

Examples:

```yaml
cwe-id: CWE-22
```

cvss-metrics  string

CVSS Metrics for the template.

Examples:

```yaml
cvss-metrics: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

cvss-score  float64

CVSS Score for the template.

Examples:

```yaml
cvss-score: "9.8"
```

epss-score  float64

EPSS Score for the template.

Examples:

```yaml
epss-score: "0.42509"
```

epss-percentile  float64

EPSS Percentile for the template.

Examples:

```yaml
epss-percentile: "0.42509"
```

cpe  string

CPE for the template.

Examples:

```yaml
cpe: cpe:/a:vendor:product:version
```

## http.Request
Request contains a http request to be made from a template

Appears in:

- Template.requests

- Template.http

```yaml
matchers:
    - type: word
      words:
        - '[core]'
    - type: dsl
      condition: and
      dsl:
        - '!contains(tolower(body), ''template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- host - Host is the input to the template
- matched - Matched is the input which was matched upon
- type - Type is the type of request made
- request - HTTP request made from the client
- response - HTTP response received from server
- status_code - Status Code received from the Server
- body - HTTP response body received from server (default)
- content_length - HTTP Response content length
- header,all_headers - HTTP response headers
- duration - HTTP request time duration
- all - HTTP response body + headers
- cookies_from_response - HTTP response cookies in name:value format
- headers_from_response - HTTP response headers in name:value format

path  []string

Path contains the path/s for the HTTP requests. It supports variables
as placeholders.

Examples:

```yaml
# Some example path values
path:
    - '{{BaseURL}}'
    - '{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions'
```

raw  []string

Raw contains HTTP Requests in Raw format.

Examples:

```yaml
# Some example raw requests
raw:
    - |-
      GET /etc/passwd HTTP/1.1
      Host:
      Content-Length: 4
    - |-
      POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
      Content-Length: 1
      Connection: close

      echo
      echo
      cat /etc/passwd 2>&1
```

id  string

ID is the optional id of the request

name  string

Name is the optional name of the request.

If a name is specified, all the named request in a template can be matched upon
in a combined manner allowing multi-request based matchers.

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

Valid values:

  - batteringram

  - pitchfork

  - clusterbomb

method  HTTPMethodTypeHolder

Method is the HTTP Request Method.

body  string

Body is an optional parameter which contains HTTP Request body.

Examples:

```yaml
# Same Body for a Login POST request
body: username=test&password=test
```

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

headers  map[string]string

Headers contains HTTP Headers to send with the request.

Examples:

```yaml
headers:
    Any-Header: Any-Value
    Content-Length: "1"
    Content-Type: application/x-www-form-urlencoded
```

race_count  int

RaceCount is the number of times to send a request in Race Condition Attack.

Examples:

```yaml
# Send a request 5 times
race_count: 5
```

max-redirects  int

MaxRedirects is the maximum number of redirects that should be followed.

Examples:

```yaml
# Follow up to 5 redirects
max-redirects: 5
```

pipeline-concurrent-connections  int

PipelineConcurrentConnections is number of connections to create during pipelining.

Examples:

```yaml
# Create 40 concurrent connections
pipeline-concurrent-connections: 40
```

pipeline-requests-per-connection  int

PipelineRequestsPerConnection is number of requests to send per connection when pipelining.

Examples:

```yaml
# Send 100 requests per pipeline connection
pipeline-requests-per-connection: 100
```

threads  int

Threads specifies number of threads to use sending requests. This enables Connection Pooling.

Connection: Close attribute must not be used in request while using threads flag, otherwise
pooling will fail and engine will continue to close connections after requests.

Examples:

```yaml
# Send requests using 10 concurrent threads
threads: 10
```

max-size  int

MaxSize is the maximum size of http response body to read in bytes.

Examples:

```yaml
# Read max 2048 bytes of the response
max-size: 2048
```

fuzzing  []fuzz.Rule

Fuzzing describes schema to fuzz http requests

analyzer  analyzers.AnalyzerTemplate

Analyzer is an analyzer to use for matching the response.

self-contained  bool

SelfContained specifies if the request is self-contained.

signature  SignatureTypeHolder

Signature is the request signature method

Valid values:

  - AWS

skip-secret-file  bool

SkipSecretFile skips the authentication or authorization configured in the secret file.

cookie-reuse  bool

CookieReuse is an optional setting that enables cookie reuse for
all requests defined in raw section.

disable-cookie  bool

DisableCookie is an optional setting that disables cookie reuse

read-all  bool

Enables force reading of the entire raw unsafe request body ignoring
any specified content length headers.

redirects  bool

Redirects specifies whether redirects should be followed by the HTTP Client.

This can be used in conjunction with `max-redirects` to control the HTTP request redirects.

host-redirects  bool

Redirects specifies whether only redirects to the same host should be followed by the HTTP Client.

This can be used in conjunction with `max-redirects` to control the HTTP request redirects.

protocol-redirects  bool

ProtocolRedirects specifies whether only redirects within the same protocol should be followed.

When set to true with redirects enabled, cross-protocol redirects (e.g. HTTP to HTTPS) will be blocked.

pipeline  bool

Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining

All requests must be idempotent (GET/POST). This can be used for race conditions/billions requests.

unsafe  bool

Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests.

This uses the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine to achieve complete
control over the request, with no normalization performed by the client.

race  bool

Race determines if all the request have to be attempted at the same time (Race Condition)

The actual number of requests that will be sent is determined by the `race_count`  field.

req-condition  bool

ReqCondition automatically assigns numbers to requests and preserves their history.

This allows matching on them later for multi-request conditions.

stop-at-first-match  bool

StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.

skip-variables-check  bool

SkipVariablesCheck skips the check for unresolved variables in request

iterate-all  bool

IterateAll iterates all the values extracted from internal extractors

digest-username  string

DigestAuthUsername specifies the username for digest authentication

digest-password  string

DigestAuthPassword specifies the password for digest authentication

disable-path-automerge  bool

DisablePathAutomerge disables merging target url path with raw request path

pre-condition  []matchers.Matcher

Fuzz PreCondition is matcher-like field to check if fuzzing should be performed on this request or not

pre-condition-operator  string

FuzzPreConditionOperator is the operator between multiple PreConditions for fuzzing Default is OR

global-matchers  bool

GlobalMatchers marks matchers as static and applies globally to all result events from other templates

## generators.AttackTypeHolder
AttackTypeHolder is used to hold internal type of the protocol

Appears in:

- http.Request.attack

- dns.Request.attack

- network.Request.attack

- headless.Request.attack

- websocket.Request.attack

- javascript.Request.attack

  AttackType

Enum Values:

  - batteringram

  - pitchfork

  - clusterbomb

## HTTPMethodTypeHolder
HTTPMethodTypeHolder is used to hold internal type of the HTTP Method

Appears in:

- http.Request.method

  HTTPMethodType

Enum Values:

  - GET

  - HEAD

  - POST

  - PUT

  - DELETE

  - CONNECT

  - OPTIONS

  - TRACE

  - PATCH

  - PURGE

  - Debug

## fuzz.Rule
Rule is a single rule which describes how to fuzz the request

Appears in:

- http.Request.fuzzing

- headless.Request.fuzzing

type  string

Type is the type of fuzzing rule to perform.

replace replaces the values entirely. prefix prefixes the value. postfix postfixes the value
and infix places between the values.

Valid values:

  - replace

  - prefix

  - postfix

  - infix

part  string

Part is the part of request to fuzz.

Valid values:

  - query

  - header

  - path

  - body

  - cookie

  - request

parts  []string

Parts is the list of parts to fuzz. If multiple parts need to be
defined while excluding some, this should be used instead of singular part.

Valid values:

  - query

  - header

  - path

  - body

  - cookie

  - request

mode  string

Mode is the mode of fuzzing to perform.

single fuzzes one value at a time. multiple fuzzes all values at same time.

Valid values:

  - single

  - multiple

keys  []string

Keys is the optional list of key named parameters to fuzz.

Examples:

```yaml
# Examples of keys
keys:
    - url
    - file
    - host
```

keys-regex  []string

KeysRegex is the optional list of regex key parameters to fuzz.

Examples:

```yaml
# Examples of key regex
keys-regex:
    - url.*
```

values  []string

Values is the optional list of regex value parameters to fuzz.

Examples:

```yaml
# Examples of value regex
values:
    - https?://.*
```

fuzz  SliceOrMapSlice

description: |
   Fuzz is the list of payloads to perform substitutions with.
 examples:
   - name: Examples of fuzz
     value: >
       []string{"{{ssrf}}", "{{interactsh-url}}", "example-value"}
      or
       x-header: 1
       x-header: 2

replace-regex  string

replace-regex is regex for regex-replace rule type
it is only required for replace-regex rule type

## SliceOrMapSlice

Appears in:

- fuzz.Rule.fuzz

## analyzers.AnalyzerTemplate
AnalyzerTemplate is the template for the analyzer

Appears in:

- http.Request.analyzer

name  string

Name is the name of the analyzer to use

Valid values:

  - time_delay

  - xss_context

parameters  map[string]interface{}

Parameters is the parameters for the analyzer

Parameters are different for each analyzer. For example, you can customize
time_delay analyzer with sleep_duration, time_slope_error_range, etc. Refer
to the docs for each analyzer to get an idea about parameters.

## SignatureTypeHolder
SignatureTypeHolder is used to hold internal type of the signature

Appears in:

- http.Request.signature

## matchers.Matcher
Matcher is used to match a part in the output from a protocol.

Appears in:

- http.Request.pre-condition

type  MatcherTypeHolder

Type is the type of the matcher.

condition  string

Condition is the optional condition between two matcher variables. By default,
the condition is assumed to be OR.

Valid values:

  - and

  - or

part  string

Part is the part of the request response to match data from.

Each protocol exposes a lot of different parts which are well
documented in docs for each request type.

Examples:

```yaml
part: body
```

```yaml
part: raw
```

negative  bool

Negative specifies if the match should be reversed
It will only match if the condition is not true.

name  string

Name of the matcher. Name should be lowercase and must not contain
spaces or underscores (_).

Examples:

```yaml
name: cookie-matcher
```

status  []int

Status are the acceptable status codes for the response.

Examples:

```yaml
status:
    - 200
    - 302
```

size  []int

Size is the acceptable size for the response

Examples:

```yaml
size:
    - 3029
    - 2042
```

words  []string

Words contains word patterns required to be present in the response part.

Examples:

```yaml
# Match for Outlook mail protection domain
words:
    - mail.protection.outlook.com
```

```yaml
# Match for application/json in response headers
words:
    - application/json
```

regex  []string

Regex contains Regular Expression patterns required to be present in the response part.

Examples:

```yaml
# Match for Linkerd Service via Regex
regex:
    - (?mi)^Via\\s*?:.*?linkerd.*$
```

```yaml
# Match for Open Redirect via Location header
regex:
    - (?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$
```

binary  []string

Binary are the binary patterns required to be present in the response part.

Examples:

```yaml
# Match for Springboot Heapdump Actuator "JAVA PROFILE", "HPROF", "Gunzip magic byte"
binary:
    - 4a4156412050524f46494c45
    - 4850524f46
    - 1f8b080000000000
```

```yaml
# Match for 7zip files
binary:
    - 377ABCAF271C
```

dsl  []string

DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
A list of these helper functions are available [here](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/).

Examples:

```yaml
# DSL Matcher for package.json file
dsl:
    - contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200
```

```yaml
# DSL Matcher for missing strict transport security header
dsl:
    - '!contains(tolower(all_headers), ''''strict-transport-security'''')'
```

xpath  []string

XPath are the xpath queries expressions that will be evaluated against the response part.

Examples:

```yaml
# XPath Matcher to check a title
xpath:
    - /html/head/title[contains(text(), 'How to Find XPath')]
```

```yaml
# XPath Matcher for finding links with target="_blank"
xpath:
    - //a[@target="_blank"]
```

encoding  string

Encoding specifies the encoding for the words field if any.

Valid values:

  - hex

case-insensitive  bool

CaseInsensitive enables case-insensitive matches. Default is false.

Valid values:

  - false

  - true

match-all  bool

MatchAll enables matching for all matcher values. Default is false.

Valid values:

  - false

  - true

internal  bool

description: |
  Internal when true hides the matcher from output. Default is false.
 It is meant to be used in multiprotocol / flow templates to create internal matcher condition without printing it in output.
 or other similar use cases.
 values:
   - false
   - true

## MatcherTypeHolder
MatcherTypeHolder is used to hold internal type of the matcher

Appears in:

- matchers.Matcher.type

  MatcherType

Enum Values:

  - word

  - regex

  - binary

  - status

  - size

  - dsl

  - xpath

## dns.Request
Request contains a DNS protocol request to be made from a template

Appears in:

- Template.dns

```yaml
extractors:
    - type: regex
      regex:
        - ec2-[-\d]+\.compute[-\d]*\.amazonaws\.com
        - ec2-[-\d]+\.[\w\d\-]+\.compute[-\d]*\.amazonaws\.com
name: '{{FQDN}}'
type: CNAME
class: inet
retries: 2
recursion: false
```

Part Definitions:

- template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- host - Host is the input to the template
- matched - Matched is the input which was matched upon
- request - Request contains the DNS request in text format
- type - Type is the type of request made
- rcode - Rcode field returned for the DNS request
- question - Question contains the DNS question field
- extra - Extra contains the DNS response extra field
- answer - Answer contains the DNS response answer field
- ns - NS contains the DNS response NS field
- raw,body,all - Raw contains the raw DNS response (default)
- trace - Trace contains trace data for DNS request if enabled

id  string

ID is the optional id of the request

name  string

Name is the Hostname to make DNS request for.

Generally, it is set to {{FQDN}} which is the domain we get from input.

Examples:

```yaml
name: '{{FQDN}}'
```

type  DNSRequestTypeHolder

RequestType is the type of DNS request to make.

class  string

Class is the class of the DNS request.

Usually it's enough to just leave it as INET.

Valid values:

  - inet

  - csnet

  - chaos

  - hesiod

  - none

  - any

retries  int

Retries is the number of retries for the DNS request

Examples:

```yaml
# Use a retry of 3 to 5 generally
retries: 5
```

trace  bool

Trace performs a trace operation for the target.

trace-max-recursion  int

TraceMaxRecursion is the number of max recursion allowed for trace operations

Examples:

```yaml
# Use a retry of 100 to 150 generally
trace-max-recursion: 100
```

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

threads  int

Threads to use when sending iterating over payloads

Examples:

```yaml
# Send requests using 10 concurrent threads
threads: 10
```

recursion  dns.bool

Recursion determines if resolver should recurse all records to get fresh results.

resolvers  []string

Resolvers to use for the dns requests

## DNSRequestTypeHolder
DNSRequestTypeHolder is used to hold internal type of the DNS type

Appears in:

- dns.Request.type

  DNSRequestType

Enum Values:

  - A

  - NS

  - DS

  - CNAME

  - SOA

  - PTR

  - MX

  - TXT

  - AAAA

  - CAA

  - TLSA

  - ANY

  - SRV

## file.Request
Request contains a File matching mechanism for local disk operations.

Appears in:

- Template.file

```yaml
extractors:
    - type: regex
      regex:
        - amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
extensions:
    - all
```

Part Definitions:

- template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- matched - Matched is the input which was matched upon
- path - Path is the path of file on local filesystem
- type - Type is the type of request made
- raw,body,all,data - Raw contains the raw file contents

extensions  []string

Extensions is the list of extensions or mime types to perform matching on.

Examples:

```yaml
extensions:
    - .txt
    - .go
    - .json
```

denylist  []string

DenyList is the list of file, directories, mime types or extensions to deny during matching.

By default, it contains some non-interesting extensions that are hardcoded
in nuclei.

Examples:

```yaml
denylist:
    - .avi
    - .mov
    - .mp3
```

id  string

ID is the optional id of the request

max-size  string

MaxSize is the maximum size of the file to run request on.

By default, nuclei will process 1 GB of content and not go more than that.
It can be set to much lower or higher depending on use.
If set to "no" then all content will be processed

Examples:

```yaml
max-size: 5Mb
```

archive  bool

elaborates archives

mime-type  bool

enables mime types check

no-recursive  bool

NoRecursive specifies whether to not do recursive checks if folders are provided.

## network.Request
Request contains a Network protocol request to be made from a template

Appears in:

- Template.network

- Template.tcp

```yaml
host:
    - '{{Hostname}}'
    - '{{Hostname}}:2181'
inputs:
    - data: "envi\r\nquit\r\n"
read-size: 2048
matchers:
    - type: word
      words:
        - zookeeper.version
```

Part Definitions:

- template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- host - Host is the input to the template
- matched - Matched is the input which was matched upon
- type - Type is the type of request made
- request - Network request made from the client
- body,all,data - Network response received from server (default)
- raw - Full Network protocol data

id  string

ID is the optional id of the request

host  []string

Host to send network requests to.

Usually it's set to `{{Hostname}}`. If you want to enable TLS for
TCP Connection, you can use `tls://{{Hostname}}`.

Examples:

```yaml
host:
    - '{{Hostname}}'
```

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

threads  int

Threads specifies number of threads to use sending requests. This enables Connection Pooling.

Connection: Close attribute must not be used in request while using threads flag, otherwise
pooling will fail and engine will continue to close connections after requests.

Examples:

```yaml
# Send requests using 10 concurrent threads
threads: 10
```

inputs  []network.Input

Inputs contains inputs for the network socket

port  string

description: |
   Port is the port to send network requests to. this acts as default port but is overridden if target/input contains
 non-http(s) ports like 80,8080,8081 etc. Supports both numeric ports and IANA service names (e.g. ftp, ssh, smtp).

exclude-ports  string

description:	|
	ExcludePorts is the list of ports to exclude from being scanned . It is intended to be used with `Port` field and contains a list of ports which are ignored/skipped

read-size  int

ReadSize is the size of response to read at the end

Default value for read-size is 1024.

Examples:

```yaml
read-size: 2048
```

read-all  bool

ReadAll determines if the data stream should be read till the end regardless of the size

Default value for read-all is false.

Examples:

```yaml
read-all: false
```

stop-at-first-match  bool

StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.

## network.Input

Appears in:

- network.Request.inputs

data  string

Data is the data to send as the input.

It supports DSL Helper Functions as well as normal expressions.

Examples:

```yaml
data: TEST
```

```yaml
data: hex_decode('50494e47')
```

type  NetworkInputTypeHolder

Type is the type of input specified in `data` field.

Default value is text, but hex can be used for hex formatted data.

Valid values:

  - hex

  - text

read  int

Read is the number of bytes to read from socket.

This can be used for protocols which expect an immediate response. You can
read and write responses one after another and eventually perform matching
on every data captured with `name` attribute.

The [network docs](https://nuclei.projectdiscovery.io/templating-guide/protocols/network/) highlight more on how to do this.

Examples:

```yaml
read: 1024
```

name  string

Name is the optional name of the data read to provide matching on.

Examples:

```yaml
name: prefix
```

## NetworkInputTypeHolder
NetworkInputTypeHolder is used to hold internal type of the Network type

Appears in:

- network.Input.type

  NetworkInputType

Enum Values:

  - hex

  - text

## headless.Request
Request contains a Headless protocol request to be made from a template

Appears in:

- Template.headless

Part Definitions:

- template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- host - Host is the input to the template
- matched - Matched is the input which was matched upon
- type - Type is the type of request made
- req - Headless request made from the client
- resp,body,data - Headless response received from client (default)

id  string

ID is the optional id of the request

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

steps  []engine.Action

Steps is the list of actions to run for headless request

user_agent  userAgent.UserAgentHolder

descriptions: |
 	 User-Agent is the type of user-agent to use for the request.

custom_user_agent  string

description: |
 	 If UserAgent is set to custom, customUserAgent is the custom user-agent to use for the request.

stop-at-first-match  bool

StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.

fuzzing  []fuzz.Rule

Fuzzing describes schema to fuzz headless requests

cookie-reuse  bool

CookieReuse is an optional setting that enables cookie reuse

disable-cookie  bool

DisableCookie is an optional setting that disables cookie reuse

## engine.Action
Action is an action taken by the browser to reach a navigation

 Each step that the browser executes is an action. Most navigations
 usually start from the ActionLoadURL event, and further navigations
 are discovered on the found page. We also keep track and only
 scrape new navigation from pages we haven't crawled yet.

Appears in:

- headless.Request.steps

args  map[string]string

Args contain arguments for the headless action.
Per action arguments are described in detail [here](https://nuclei.projectdiscovery.io/templating-guide/protocols/headless/).

name  string

Name is the name assigned to the headless action.

This can be used to execute code, for instance in browser
DOM using script action, and get the result in a variable
which can be matched upon by nuclei. An Example template [here](https://github.com/projectdiscovery/nuclei-templates/blob/main/headless/prototype-pollution-check.yaml).

description  string

Description is the optional description of the headless action

action  ActionTypeHolder

Action is the type of the action to perform.

## ActionTypeHolder
ActionTypeHolder is used to hold internal type of the action

Appears in:

- engine.Action.action

  ActionType

Enum Values:

  - navigate

  - script

  - click

  - rightclick

  - text

  - screenshot

  - time

  - select

  - files

  - waitdom

  - waitfcp

  - waitfmp

  - waitidle

  - waitload

  - waitstable

  - getresource

  - extract

  - setmethod

  - addheader

  - setheader

  - deleteheader

  - setbody

  - waitevent

  - dialog

  - keyboard

  - debug

  - sleep

  - waitvisible

## userAgent.UserAgentHolder
UserAgentHolder holds a UserAgent type. Required for un/marshalling purposes

Appears in:

- headless.Request.user_agent

  UserAgent

Enum Values:

  - random

  - off

  - default

  - custom

## ssl.Request
Request is a request for the SSL protocol

Appears in:

- Template.ssl

Part Definitions:

- template-id - ID of the template executed
- template-info - Info Block of the template executed
- template-path - Path of the template executed
- host - Host is the input to the template
- port - Port is the port of the host
- matched - Matched is the input which was matched upon
- type - Type is the type of request made
- timestamp - Timestamp is the time when the request was made
- response - JSON SSL protocol handshake details
- cipher - Cipher is the encryption algorithm used
- domains - Domains are the list of domain names in the certificate
- fingerprint_hash - Fingerprint hash is the unique identifier of the certificate
- ip - IP is the IP address of the server
- issuer_cn - Issuer CN is the common name of the certificate issuer
- issuer_dn - Issuer DN is the distinguished name of the certificate issuer
- issuer_org - Issuer organization is the organization of the certificate issuer
- not_after - Timestamp after which the remote cert expires
- not_before - Timestamp before which the certificate is not valid
- probe_status - Probe status indicates if the probe was successful
- serial - Serial is the serial number of the certificate
- sni - SNI is the server name indication used in the handshake
- subject_an - Subject AN is the list of subject alternative names
- subject_cn - Subject CN is the common name of the certificate subject
- subject_dn - Subject DN is the distinguished name of the certificate subject
- subject_org - Subject organization is the organization of the certificate subject
- tls_connection - TLS connection is the type of TLS connection used
- tls_version - TLS version is the version of the TLS protocol used

id  string

ID is the optional id of the request

address  string

Address contains address for the request

min_version  string

Minimum tls version - auto if not specified.

Valid values:

  - sslv3

  - tls10

  - tls11

  - tls12

  - tls13

max_version  string

Max tls version - auto if not specified.

Valid values:

  - sslv3

  - tls10

  - tls11

  - tls12

  - tls13

cipher_suites  []string

Client Cipher Suites  - auto if not specified.

scan_mode  string

description: |
   Tls Scan Mode - auto if not specified
 values:
   - "ctls"
   - "ztls"
   - "auto"
	 - "openssl" # reverts to "auto" is openssl is not installed

tls_version_enum  bool

TLS Versions Enum - false if not specified
Enumerates supported TLS versions

tls_cipher_enum  bool

TLS Ciphers Enum - false if not specified
Enumerates supported TLS ciphers

tls_cipher_types  []string

description: |
  TLS Cipher types to enumerate
 values:
   - "insecure" (default)
   - "weak"
   - "secure"
   - "all"

## websocket.Request
Request is a request for the Websocket protocol

Appears in:

- Template.websocket

Part Definitions:

- type - Type is the type of request made
- success - Success specifies whether websocket connection was successful
- request - Websocket request made to the server
- response - Websocket response received from the server
- host - Host is the input to the template
- matched - Matched is the input which was matched upon

id  string

ID is the optional id of the request

address  string

Address contains address for the request

inputs  []websocket.Input

Inputs contains inputs for the websocket protocol

headers  map[string]string

Headers contains headers for the request.

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

## websocket.Input

Appears in:

- websocket.Request.inputs

data  string

Data is the data to send as the input.

It supports DSL Helper Functions as well as normal expressions.

Examples:

```yaml
data: TEST
```

```yaml
data: hex_decode('50494e47')
```

name  string

Name is the optional name of the data read to provide matching on.

Examples:

```yaml
name: prefix
```

## whois.Request
Request is a request for the WHOIS protocol

Appears in:

- Template.whois

id  string

ID is the optional id of the request

query  string

Query contains query for the request

server  string

description: |
 	 Optional WHOIS server URL.

 	 If present, specifies the WHOIS server to execute the Request on.
   Otherwise, nil enables bootstrapping

## code.Request
Request is a request for the SSL protocol

Appears in:

- Template.code

Part Definitions:

- type - Type is the type of request made
- host - Host is the input to the template
- matched - Matched is the input which was matched upon

id  string

ID is the optional id of the request

engine  []string

Engine type

pre-condition  string

PreCondition is a condition which is evaluated before sending the request.

args  []string

Engine Arguments

pattern  string

Pattern preferred for file name

source  string

Source File/Snippet

## javascript.Request
Request is a request for the javascript protocol

Appears in:

- Template.javascript

Part Definitions:

- type - Type is the type of request made
- response - Javascript protocol result response
- host - Host is the input to the template
- matched - Matched is the input which was matched upon

id  string

description: |
 ID is request id in that protocol

init  string

Init is javascript code to execute after compiling template and before executing it on any target
This is helpful for preparing payloads or other setup that maybe required for exploits

pre-condition  string

PreCondition is a condition which is evaluated before sending the request.

args  map[string]interface{}

Args contains the arguments to pass to the javascript code.

code  string

Code contains code to execute for the javascript request.

stop-at-first-match  bool

StopAtFirstMatch stops processing the request at first match.

attack  generators.AttackTypeHolder

Attack is the type of payload combinations to perform.

Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

threads  int

Payload concurrency i.e threads for sending requests.

Examples:

```yaml
# Send requests using 10 concurrent threads
threads: 10
```

payloads  map[string]interface{}

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

## http.SignatureTypeHolder
SignatureTypeHolder is used to hold internal type of the signature

Appears in:

- Template.signature

## variables.Variable
Variable is a key-value pair of strings that can be used
 throughout template.

Appears in:

- Template.variables
