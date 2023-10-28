class TP_HTTP_REQUEST_PARSER:
	def __init__(self, rawRequest):
		import json_duplicate_keys as jdks
		import re
		from urllib.parse import urlparse

		try:
			self.request_method = re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawRequest, 1)[0])[0].split(" ")[0]
		except Exception as e:
			self.request_method = None

		try:
			self.request_path = urlparse(re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawRequest, 1)[0])[0].split(" ")[1]).path
		except Exception as e:
			self.request_path = None

		self.request_query = jdks.JSON_DUPLICATE_KEYS({})
		try:
			parse_query = urlparse(re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawRequest, 1)[0])[0].split(" ")[1]).query
			if len(parse_query) > 0:
				for param_query in parse_query.split("&"):
					if len(re.split("=", param_query, 1)) == 2:
						self.request_query.set(re.split("=", param_query, 1)[0], re.split("=", param_query, 1)[1])
					else:
						self.request_query.set(re.split("=", param_query, 1)[0], "")
		except Exception as e:
			pass

		try:
			self.request_fragment = urlparse(re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawRequest, 1)[0])[0].split(" ")[1]).fragment
		except Exception as e:
			self.request_fragment = None

		self.request_headers = jdks.JSON_DUPLICATE_KEYS({})
		try:
			for header in re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawRequest, 1)[0])[1:]:
				if re.match("^([^:]+): (.*)$", header):
					self.request_headers.set(re.findall("^([^:]+): (.*)$", header)[0][0], re.findall("^([^:]+): (.*)$", header)[0][1])
		except Exception as e:
			pass

		try:
			self.request_body = re.split("\r\n\r\n|\n\n", rawRequest, 1)[1]
		except Exception as e:
			self.request_body = None





class TP_HTTP_RESPONSE_PARSER:
	def __init__(self, rawResponse):
		import json_duplicate_keys as jdks
		import re

		try:
			self.status_code = int(re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawResponse, 1)[0])[0].split(" ")[1])
		except Exception as e:
			self.status_code = None

		try:
			self.status_text = " ".join(re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawResponse, 1)[0])[0].split(" ")[2:])
		except Exception as e:
			self.status_text = None

		self.response_headers = jdks.JSON_DUPLICATE_KEYS({})
		try:
			for header in re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", rawResponse, 1)[0])[1:]:
				if re.match("^([^:]+): (.*)$", header):
					self.response_headers.set(re.findall("^([^:]+): (.*)$", header)[0][0], re.findall("^([^:]+): (.*)$", header)[0][1])
		except Exception as e:
			pass

		try:
			self.response_body = re.split("\r\n\r\n|\n\n", rawResponse, 1)[1]
		except Exception as e:
			self.response_body = None