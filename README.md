<div align="center">
	<h1>TP-HTTP-Request-Response-Parser - PyPI</h1>
	<i>Parse/ Unparse the HTTP Request/ Response</i>
	<br><br>
	<a href="https://github.com/TPCyberSec/TP-HTTP-Request-Response-Parser/releases/"><img src="https://img.shields.io/github/release/TPCyberSec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/downloads/TPCyberSec/TP-HTTP-Request-Response-Parser/total" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/stars/TPCyberSec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/forks/TPCyberSec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="https://github.com/TPCyberSec/TP-HTTP-Request-Response-Parser/issues?q=is%3Aopen+is%3Aissue"><img src="https://img.shields.io/github/issues/TPCyberSec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="https://github.com/TPCyberSec/TP-HTTP-Request-Response-Parser/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/TPCyberSec/TP-HTTP-Request-Response-Parser" height=30></a>
	<br>
	<a href="#"><img src="https://img.shields.io/pypi/v/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/pypi/pyversions/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/pypi/dm/TP-HTTP-Request-Response-Parser" height=30></a>
</div>

---
# ✨ Features
- Parse raw HTTP Request/ Response strings
- Access and manipulate all HTTP fields: method, path, query, fragment, headers, cookies, body, etc
- Reconstruct HTTP Request/ Response from parsed objects, with automatic Content-Length update
- Easy integration for security testing, automation, or log analysis tools

---
# 🛠️ Installation
#### From PyPI:
```console
pip install tp-http-request-response-parser
```
#### From Source:
```console
git clone https://github.com/TPCyberSec/TP-HTTP-Request-Response-Parser.git --branch <Branch/Tag>
cd TP-HTTP-Request-Response-Parser
python -m build
python -m pip install dist/tp_http_request_response_parser-<version>-py3-none-any.whl
```

---
# 📘 Basic Usage
### TP_HTTP_REQUEST_PARSER
- **request_method**: returns the HTTP method (e.g., `GET`, `POST`)
- **request_path**: returns the request path (e.g., `/api/v1/data`)
- **request_pathParams**: returns parsed path parameters as JSON_DUPLICATE_KEYS object
- **request_queryParams**: returns parsed query parameters as JSON_DUPLICATE_KEYS object
- **request_fragment**: returns the URL fragment
- **request_httpVersion**: returns the HTTP version (e.g., `HTTP/1.1`, `HTTP/2`)
- **request_headers**: returns all request headers as JSON_DUPLICATE_KEYS object
- **request_cookies**: returns all cookies as JSON_DUPLICATE_KEYS object
- **request_body**: returns the request body as JSON_DUPLICATE_KEYS object
- **unparse**: reconstructs the HTTP request string from the parsed data. If `update_content_length=True`, automatically updates the Content-Length header

```python
from tp_http_request_response_parser import TP_HTTP_REQUEST_PARSER

rawRequest = """GET /v1/promo/extension HTTP/2
Host: d2y7f743exec8w.cloudfront.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Connection: close
Cache-Control: max-age=0

"""

# Parsing HTTP Request
RequestParser = TP_HTTP_REQUEST_PARSER(rawRequest, ordered_dict=True)

print("- request_method: {}".format(RequestParser.request_method))
print("- request_path: {}".format(RequestParser.request_path))
print("- request_pathParams: {}".format(RequestParser.request_pathParams.dumps(indent=4)))
print("- request_queryParams: {}".format(RequestParser.request_queryParams.dumps(indent=4)))
print("- request_fragment: {}".format(RequestParser.request_fragment))
print("- request_httpVersion: {}".format(RequestParser.request_httpVersion))
print("- request_headers: {}".format(RequestParser.request_headers.dumps(indent=4)))
print("- request_cookies: {}".format(RequestParser.request_cookies.dumps(indent=4)))
print("- request_body: {}".format(RequestParser.request_body.dumps(indent=4)))
print(RequestParser.unparse(update_content_length=True))
```

---
### TP_HTTP_RESPONSE_PARSER
- **response_httpVersion**: returns the HTTP version from the response (e.g., `HTTP/1.1`, `HTTP/2`)
- **response_statusCode**: returns the response status code (e.g., `200`, `404`)
- **response_statusText**: returns the status text (e.g., `OK`, `Not Found`)
- **response_headers**: returns all response headers as JSON_DUPLICATE_KEYS object
- **response_cookies**: returns all response cookies as JSON_DUPLICATE_KEYS object
- **response_body**: returns the response body as JSON_DUPLICATE_KEYS object
- **unparse**: reconstructs the HTTP response string from the parsed data. If `update_content_length=True`, automatically updates the Content-Length header

```python
from tp_http_request_response_parser import TP_HTTP_RESPONSE_PARSER

rawResponse = """HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
Server: nginx
Date: Mon, 21 Aug 2023 03:55:08 GMT
Etag: W/"846e0a9b390c273d2d7a6843085411d1"
Cache-Control: max-age=0, private, must-revalidate
X-Request-Id: 06024e22-f233-4517-b0f6-f444c8464e7b
Strict-Transport-Security: max-age=63072000; includeSubDomains
Strict-Transport-Security: max-age=63072000; preload
Vary: Accept-Encoding,Accept
X-Cache: Miss from cloudfront
Via: 1.1 19175f36fb9c16ba394561bae28598da.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: SGN50-P2
X-Amz-Cf-Id: eKssgTNGDCswPiQtSYFD1MRNBJCTHEbnQp4MQjtQx2B4eM7oqXYIHg==

{"ok":true,"promo":[]}"""

# Parsing HTTP Response
ResponseParser = TP_HTTP_RESPONSE_PARSER(rawResponse, ordered_dict=True)

print("- response_httpVersion: {}".format(ResponseParser.response_httpVersion))
print("- response_statusCode: {}".format(ResponseParser.response_statusCode))
print("- response_statusText: {}".format(ResponseParser.response_statusText))
print("- response_headers: {}".format(ResponseParser.response_headers.dumps(indent=4)))
print("- response_cookies: {}".format(ResponseParser.response_cookies.dumps(indent=4)))
print("- response_body: {}".format(ResponseParser.response_body.dumps(indent=4)))
print(ResponseParser.unparse(update_content_length=True))
```

---
# 👥 Contributors

---
# 📝 CHANGELOG
### [TP-HTTP-Request-Response-Parser v2025.8.30](https://github.com/TPCyberSec/TP-HTTP-Request-Response-Parser/tree/2025.8.30)
- Support for parsing and reconstructing HTTP Request/ Response
- Access all HTTP fields as JSON_DUPLICATE_KEYS objects
- Automatic Content-Length update on unparse

---