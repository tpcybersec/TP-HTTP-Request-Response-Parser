# TP-HTTP-Request-Response-Parser - PyPI
Parse/ Unparse the HTTP Request/ Response

<p align="center">
	<a href="https://github.com/tpcybersec/TP-HTTP-Request-Response-Parser/releases/"><img src="https://img.shields.io/github/release/tpcybersec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/downloads/tpcybersec/TP-HTTP-Request-Response-Parser/total" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/stars/tpcybersec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/github/forks/tpcybersec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="https://github.com/tpcybersec/TP-HTTP-Request-Response-Parser/issues?q=is%3Aopen+is%3Aissue"><img src="https://img.shields.io/github/issues/tpcybersec/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="https://github.com/tpcybersec/TP-HTTP-Request-Response-Parser/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/tpcybersec/TP-HTTP-Request-Response-Parser" height=30></a>
	<br>
	<a href="#"><img src="https://img.shields.io/pypi/v/TP-HTTP-Request-Response-Parser" height=30></a>
	<a href="#"><img src="https://img.shields.io/pypi/dm/TP-HTTP-Request-Response-Parser" height=30></a>
</p>

## Installation
#### From PyPI:
```console
pip install TP-HTTP-Request-Response-Parser
```
#### From Source:
```console
git clone https://github.com/tpcybersec/TP-HTTP-Request-Response-Parser.git --branch <Branch/Tag>
cd TP-HTTP-Request-Response-Parser
python setup.py build
python setup.py install
```

## Basic Usage
```
from TP_HTTP_Request_Response_Parser import TP_HTTP_REQUEST_PARSER, TP_HTTP_RESPONSE_PARSER

# Parsing HTTP Request
rawRequest = """GET /v1/promo/extension HTTP/2
Host: d2y7f743exec8w.cloudfront.net
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Connection: close
Cache-Control: max-age=0

"""

# RequestParser = TP_HTTP_REQUEST_PARSER(open("rawRequest.req").read())
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



# Parsing HTTP Response
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

# ResponseParser = TP_HTTP_RESPONSE_PARSER(open("rawResponse.res").read())
ResponseParser = TP_HTTP_RESPONSE_PARSER(rawResponse, ordered_dict=True)

print("- response_httpVersion: {}".format(ResponseParser.response_httpVersion))
print("- response_statusCode: {}".format(ResponseParser.response_statusCode))
print("- response_statusText: {}".format(ResponseParser.response_statusText))
print("- response_headers: {}".format(ResponseParser.response_headers.dumps(indent=4)))
print("- response_cookies: {}".format(ResponseParser.response_cookies.dumps(indent=4)))
print("- response_body: {}".format(ResponseParser.response_body.dumps(indent=4)))
print(ResponseParser.unparse(update_content_length=True))
```