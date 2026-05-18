import json_duplicate_keys as jdks
from TP_Generator import Utils
from collections import OrderedDict
import re, platform
import gzip, zlib
from io import BytesIO

try:
	unicode
except NameError:
	unicode = str

if platform.python_version_tuple()[0] == "3":
	from urllib.parse import urlparse, quote as urlencode, unquote as urldecode
else:
	from urlparse import urlparse
	from urllib import quote as urlencode, unquote as urldecode


class TP_HTTP_REQUEST_PARSER:
	def __init__(self, rawRequest, separator="||", parse_index="$", dupSign_start="{{{", dupSign_end="}}}", ordered_dict=False, skipDuplicated=True):
		self.separator = separator; self.parse_index = parse_index; self.dupSign_start = dupSign_start; self.dupSign_end = dupSign_end; self.ordered_dict = ordered_dict; self.skipDuplicated = skipDuplicated

		self.urlencode = {
			"HTTPHeaders": {},
			"HTTPCookies": {},
			"RequestBody": {}
		}

		requestHeader = requestBody = ""
		if type(rawRequest) == bytes:
			rawRequest = self.bytes_to_string(rawRequest)

		requestHeader = re.split("\r\n\r\n|\n\n", rawRequest, 1)[0]
		try:
			requestBody = re.split("\r\n\r\n|\n\n", rawRequest, 1)[1]
		except Exception as e: pass

		## Request Method ##
		try:
			self.request_method = re.split("\r\n|\n", requestHeader)[0].split(" ")[0]
		except Exception as e:
			self.request_method = ""
		##

		## Request Paths ##
		self.request_paths = jdks.loads("[]", ordered_dict=self.ordered_dict)
		try:
			for pathPart in urlparse(re.split("\r\n|\n", requestHeader)[0].split(" ")[1]).path[1:].split("/"):
				JDKSObject = jdks.loads(urldecode(pathPart), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
				if JDKSObject:
					self.request_paths.insert(None, JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
				else:
					self.request_paths.insert(None, pathPart, separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		except Exception as e: pass
		##

		## Request Query ##
		self.request_queryParams = jdks.loads("{}", ordered_dict=self.ordered_dict)
		try:
			parse_query = urlparse(re.split("\r\n|\n", requestHeader)[0].split(" ")[1]).query
			if len(parse_query) > 0:
				for param_query in parse_query.split("&"):
					kv = re.split("=", param_query, 1)
					if len(kv) == 2:
						JDKSObject = jdks.loads(urldecode(kv[1]), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
						if JDKSObject:
							self.request_queryParams.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
						else:
							self.request_queryParams.set(kv[0], kv[1], separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
					else:
						self.request_queryParams.set(kv[0], "", separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		except Exception as e: pass
		##

		## Request Fragment ##
		try:
			self.request_fragment = urlparse(re.split("\r\n|\n", requestHeader)[0].split(" ")[1]).fragment
		except Exception as e:
			self.request_fragment = ""
		##

		## Request HTTP Version ##
		try:
			self.request_httpVersion = re.split("\r\n|\n", requestHeader)[0].split(" ")[2]
		except Exception as e:
			self.request_httpVersion = ""
		##

		## Request Headers ##
		self.request_headers = jdks.loads("{}", ordered_dict=self.ordered_dict)
		try:
			for header in re.split("\r\n|\n", requestHeader)[1:]:
				if re.match("^[^:]+: .*$", header):
					kv = re.findall("^([^:]+): (.*)$", header)[0]
					JDKSObject = jdks.loads(kv[1], dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.request_headers.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
					else:
						JDKSObject = jdks.loads(urldecode(kv[1]), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
						if JDKSObject:
							self.urlencode["HTTPHeaders"][kv[0]] = True
							self.request_headers.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
						else:
							self.request_headers.set(kv[0], kv[1], separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		except Exception as e: pass
		##

		## Request Cookies ##
		self.request_cookies = jdks.loads("{}", ordered_dict=self.ordered_dict)
		if self.request_headers.get("Cookie", case_insensitive=True)["value"] != "JSON_DUPLICATE_KEYS_ERROR":
			for cookie in self.request_headers.get("Cookie", case_insensitive=True)["value"].split(";"):
				kv = cookie.split("=", 1)
				if len(kv) == 2:
					JDKSObject = jdks.loads(kv[1].strip(), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.request_cookies.set(kv[0].strip(), JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
					else:
						JDKSObject = jdks.loads(urldecode(kv[1].strip()), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
						if JDKSObject:
							self.urlencode["HTTPCookies"][kv[0].strip()] = True
							self.request_cookies.set(kv[0].strip(), JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
						else:
							self.request_cookies.set(kv[0].strip(), kv[1].strip(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
				else:
					self.request_cookies.set(kv[0].strip(), "", separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		##

		## Request Body ##
		try:
			reqBody = requestBody
			if len(reqBody) > 0:
				# JSON Body
				JDKSObject = jdks.loads(reqBody, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
				if JDKSObject:
					self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "json", "data": JDKSObject.getObject() })
				else:
					JDKSObject = jdks.loads(urldecode(reqBody), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.urlencode["RequestBody"]["json"] = True
						self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "json", "data": JDKSObject.getObject() })
					# Multipart Body
					# Line index 0: ------WebKitFormBoundarylSMLylneEk9ZsCHL
					# Line index 1: Content-Disposition: form-data; name="param_name_1"
					# Line index 2: 
					# Line index 3: param_value_1
					# Line index 4: ------WebKitFormBoundarylSMLylneEk9ZsCHL
					# Line index 5: Content-Disposition: form-data; name="param_name_1"; filename="test.txt"
					# Line index 6: Content-Type: text/plain
					# ...
					# Line index -4: 
					# Line index -3: param_value_2
					# Line index -2: ------WebKitFormBoundarylSMLylneEk9ZsCHL--
					# Line index -1: 
					elif re.split("\r\n|\n", reqBody)[-1] == "" and re.split("\r\n|\n", reqBody)[0]+"--"==re.split("\r\n|\n", reqBody)[-2]:
						self.urlencode["RequestBody"]["multipart"] = {}
						boundary = re.split("\r\n|\n", reqBody)[0]

						try:
							params = jdks.loads("{}", ordered_dict=self.ordered_dict)

							for multipart_param in re.split("(?:\r?\n)?"+boundary+"(?:--)?\r?\n", reqBody)[1:-1]:
								# name , filename
								if re.match("^Content-Disposition: form-data; name=\".*?\"; filename=\".*?\"$", re.split("\r\n|\n", multipart_param)[0], re.IGNORECASE):
									result = re.findall("^Content-Disposition: form-data; name=\"(.*?)\"; filename=\"(.*?)\"$", re.split("\r\n|\n", multipart_param)[0], re.IGNORECASE)
									name = result[0][0]
									filename = result[0][1]

									params.set(name, {
										"filename": filename,
										"headers": {},
										"value": ""
									}, separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
								# name
								elif re.match("^Content-Disposition: form-data; name=\".*?\"$", re.split("\r\n|\n", multipart_param)[0], re.IGNORECASE):
									result = re.findall("^Content-Disposition: form-data; name=\"(.*?)\"$", re.split("\r\n|\n", multipart_param)[0], re.IGNORECASE)
									name = result[0]

									params.set(name, {
											"headers": {},
											"value": ""
									}, separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
								else:
									continue

								# Headers
								self.urlencode["RequestBody"]["multipart"][name] = { "headers": {} }
								for h in re.split("\r\n|\n", re.split("\r\n\r\n|\n\n", multipart_param, 1)[0])[1:]:
									if re.match("^[^:]+: .*$", h):
										kv = re.findall("^([^:]+): (.*)$", h)[0]
										JDKSObject = jdks.loads(kv[1], dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
										if JDKSObject:
											params.set(name+self.separator+"headers"+self.separator+kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
										else:
											JDKSObject = jdks.loads(urldecode(kv[1]), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
											if JDKSObject:
												self.urlencode["RequestBody"]["multipart"][name]["headers"][kv[0]] = True
												params.set(name+self.separator+"headers"+self.separator+kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
											else:
												params.set(name+self.separator+"headers"+self.separator+kv[0], kv[1], separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)

								# Value
								v = re.split("\r\n\r\n|\n\n", multipart_param, 1)[-1]
								JDKSObject = jdks.loads(v, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
								if JDKSObject:
									params.update(name+self.separator+"value", JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
								else:
									JDKSObject = jdks.loads(urldecode(v), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
									if JDKSObject:
										self.urlencode["RequestBody"]["multipart"][name]["value"] = True
										params.update(name+self.separator+"value", JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
									else:
										params.update(name+self.separator+"value", v, separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)

							self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "multipart", "boundary": boundary[2:], "data": params.getObject() })
						except Exception as e:
							self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "unknown", "data": reqBody })
					elif re.match("^application/x-www-form-urlencoded", self.request_headers.get("Content-Type", case_insensitive=True)["value"]):
						self.urlencode["RequestBody"]["form-urlencoded"] = {}
						params = jdks.loads("{}", ordered_dict=self.ordered_dict)

						for NameValue in reqBody.split("&"):
							kv = re.split("=", NameValue, 1)
							if len(kv) == 2:
								JDKSObject = jdks.loads(kv[1], dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
								if JDKSObject:
									params.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
								else:
									JDKSObject = jdks.loads(urldecode(kv[1]), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
									if JDKSObject:
										self.urlencode["RequestBody"]["form-urlencoded"][kv[0]] = True
										params.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
									else:
										params.set(kv[0], kv[1], separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
							else:
								params.set(kv[0], "", separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)

						self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "form-urlencoded", "data": params.getObject() })
					else:
						if Utils.XML2JSON(reqBody, ordered_dict=self.ordered_dict):
							self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "xml", "data": Utils.XML2JSON(reqBody, ordered_dict=self.ordered_dict) })
						else:
							if Utils.XML2JSON(urldecode(reqBody), ordered_dict=self.ordered_dict):
								self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "xml", "data": Utils.XML2JSON(urldecode(reqBody), ordered_dict=self.ordered_dict) })
								self.urlencode["RequestBody"]["xml"] = True
							else:
								self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "unknown", "data": reqBody })
			else:
				# No body
				self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": None, "data": None })
		except Exception as e:
			# No body, Exception
			self.request_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": None, "data": None })
		##

	def bytes_to_string(self, data):
		# Try plain UTF-8
		try:
			return data.decode("utf8")
		except Exception: pass

		# Try gzip
		try:
			with gzip.GzipFile(fileobj=BytesIO(data)) as f:
				decompressed = f.read()
				return decompressed.decode("utf8")
		except Exception: pass

		# Try raw deflate (zlib wbits=-15)
		try:
			decompressed = zlib.decompress(data, wbits=-15)
			return decompressed.decode("utf8")
		except Exception: pass

		# Try zlib default (wbits=+zlib format)
		try:
			decompressed = zlib.decompress(data)
			return decompressed.decode("utf8")
		except Exception: pass

		# Try latin1 as a fallback for decoding weird encodings (1:1 byte mapping)
		try:
			return data.decode("latin1")
		except Exception: pass

		# Final fallback: replace invalid chars
		return data.decode("utf8", errors="replace")

	def unparse(self, Coding="utf8", update_content_length=False):
		method = path = queryParams = fragment = httpVersion = headers = cookies = body = ""

		if type(self.request_method) == str:
			method = self.request_method
		elif type(self.request_method) == unicode:
			method = self.request_method.decode("utf8").encode("utf8")
		elif type(self.request_method) == bytes:
			method = self.bytes_to_string(self.request_method)
		else:
			method = str(self.request_method)
		method = method.replace(" ", "%20").replace("\r", "%0d").replace("\n", "%0a").replace("\t", "%09").replace("\x0b", "%0b").replace("\x0c", "%0c")

		try:
			if isinstance(self.request_paths, jdks.JSON_DUPLICATE_KEYS):
				for pathPart in self.request_paths.getObject():
					if type(pathPart) in [OrderedDict, dict, list]:
						path += "/"+urlencode(jdks.JSON_DUPLICATE_KEYS(pathPart).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)).replace("/", "%2f")
					elif type(pathPart) == str:
						path += "/"+pathPart.replace("/", "%2f")
					elif type(pathPart) == unicode:
						path += "/"+pathPart.decode("utf8").encode("utf8").replace("/", "%2f")
					elif type(pathPart) == bytes:
						path += "/"+self.bytes_to_string(pathPart).replace("/", "%2f")
					else:
						path += "/"+str(pathPart).replace("/", "%2f")
		except Exception as e: pass
		if len(path) == 0: path = "/"
		path = path.replace(" ", "%20").replace("?", "%3f").replace("#", "%23").replace("\r", "%0d").replace("\n", "%0a").replace("\t", "%09").replace("\x0b", "%0b").replace("\x0c", "%0c")

		try:
			if isinstance(self.request_queryParams, jdks.JSON_DUPLICATE_KEYS):
				query = []
				for k in self.request_queryParams.getObject():
					if type(k) in [unicode, str]:
						Jget = self.request_queryParams.get(k)
						if type(Jget["value"]) in [OrderedDict, dict, list]:
							query.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)).replace("&", "%26")))
						elif type(Jget["value"]) == str:
							query.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=Jget["value"].replace("&", "%26")))
						elif type(Jget["value"]) == unicode:
							query.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=Jget["value"].decode("utf8").encode("utf8").replace("&", "%26")))
						elif type(Jget["value"]) == bytes:
							query.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=self.bytes_to_string(Jget["value"]).replace("&", "%26")))
						else:
							query.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=str(Jget["value"]).replace("&", "%26")))
				queryParams = "&".join(query)
				queryParams = queryParams.replace(" ", "%20").replace("#", "%23").replace("\r", "%0d").replace("\n", "%0a").replace("\t", "%09").replace("\x0b", "%0b").replace("\x0c", "%0c")
		except Exception as e: pass
		if len(queryParams) > 0: queryParams = "?"+queryParams

		if len(self.request_fragment) > 0:
			if type(self.request_fragment) == str:
				fragment = "#"+self.request_fragment
			elif type(self.request_fragment) == unicode:
				fragment = "#"+self.request_fragment.decode("utf8").encode("utf8")
			elif type(self.request_fragment) == bytes:
				fragment = "#"+self.bytes_to_string(self.request_fragment)
			else:
				fragment = "#"+str(self.request_fragment)
			fragment = fragment.replace(" ", "%20").replace("\r", "%0d").replace("\n", "%0a").replace("\t", "%09").replace("\x0b", "%0b").replace("\x0c", "%0c")

		if type(self.request_httpVersion) == str:
			httpVersion = self.request_httpVersion
		elif type(self.request_httpVersion) == unicode:
			httpVersion = self.request_httpVersion.decode("utf8").encode("utf8")
		elif type(self.request_httpVersion) == bytes:
			httpVersion = self.bytes_to_string(self.request_httpVersion)
		else:
			httpVersion = str(self.request_httpVersion)
		httpVersion = httpVersion.replace(" ", "%20").replace("\r", "%0d").replace("\n", "%0a").replace("\t", "%09").replace("\x0b", "%0b").replace("\x0c", "%0c")

		try:
			if isinstance(self.request_body, jdks.JSON_DUPLICATE_KEYS):
				Jget_dataType = self.request_body.get("dataType")
				Jget_data = self.request_body.get("data")
				if Jget_dataType["value"] == "json":
					if "json" in self.urlencode["RequestBody"]:
						body = urlencode(jdks.JSON_DUPLICATE_KEYS(Jget_data["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False))
					else:
						body = jdks.JSON_DUPLICATE_KEYS(Jget_data["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)
				elif Jget_dataType["value"] == "multipart":
					for paramName in Jget_data["value"]:
						try:
							body += "--"+self.request_body.get("boundary")["value"]
							body += '\r\nContent-Disposition: form-data; name="'+jdks.normalize_key(paramName)+'"'
							if "filename" in Jget_data["value"][paramName].keys():
								body += '; filename="'+Jget_data["value"][paramName]["filename"]+'"'

							for h in Jget_data["value"][paramName]["headers"]:
								if type(h) in [unicode, str]:
									if type(Jget_data["value"][paramName]["headers"][h]) in [OrderedDict, dict, list]:
										if jdks.normalize_key(h) in self.urlencode["RequestBody"]["multipart"][paramName]["headers"]:
											body += "\r\n{key}: {value}".format(key=jdks.normalize_key(h), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][paramName]["headers"][h]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)))
										else:
											body += "\r\n{key}: {value}".format(key=jdks.normalize_key(h), value=jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][paramName]["headers"][h]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False))
									elif type(Jget_data["value"][paramName]["headers"][h]) in [unicode, str]:
										body += "\r\n{key}: {value}".format(key=jdks.normalize_key(h), value=Jget_data["value"][paramName]["headers"][h])
									elif type(Jget_data["value"][paramName]["headers"][h]) == bytes:
										body += "\r\n{key}: {value}".format(key=jdks.normalize_key(h), value=self.bytes_to_string(Jget_data["value"][paramName]["headers"][h]))
									else:
										body += "\r\n{key}: {value}".format(key=jdks.normalize_key(h), value=str(Jget_data["value"][paramName]["headers"][h]))

							if type(Jget_data["value"][paramName]["value"]) in [OrderedDict, dict, list]:
								if "value" in self.urlencode["RequestBody"]["multipart"][paramName]:
									body += "\r\n\r\n"+urlencode(jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][paramName]["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False))+"\r\n"
								else:
									body += "\r\n\r\n"+jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][paramName]["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)+"\r\n"
							elif type(Jget_data["value"][paramName]["value"]) in [unicode, str]:
								body += "\r\n\r\n"+Jget_data["value"][paramName]["value"]+"\r\n"
							elif type(Jget_data["value"][paramName]["value"]) == bytes:
								body += "\r\n\r\n"+self.bytes_to_string(Jget_data["value"][paramName]["value"])+"\r\n"
							else:
								body += "\r\n\r\n"+str(Jget_data["value"][paramName]["value"])+"\r\n"
						except Exception as e: 
							body += "\r\n\r\n"

					body += "--"+self.request_body.get("boundary")["value"]+"--\r\n"

					Jget = self.request_headers.get("Content-Type", case_insensitive=True)
					if Jget["value"] == "JSON_DUPLICATE_KEYS_ERROR":
						self.request_headers.set("Content-Type", "multipart/form-data; boundary="+self.request_body.get("boundary")["value"])
					else:
						self.request_headers.update(Jget["name"], "multipart/form-data; boundary="+self.request_body.get("boundary")["value"])
				elif Jget_dataType["value"] == "form-urlencoded":
					body_urlencoded = []
					for k in Jget_data["value"]:
						if type(k) in [unicode, str]:
							if type(Jget_data["value"][k]) in [OrderedDict, dict, list]:
								if jdks.normalize_key(k) in self.urlencode["RequestBody"]["form-urlencoded"]:
									body_urlencoded.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][k]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)).replace("&", "%26")))
								else:
									body_urlencoded.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=jdks.JSON_DUPLICATE_KEYS(Jget_data["value"][k]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False).replace("&", "%26")))
							elif type(Jget_data["value"][k]) in [unicode, str]:
								body_urlencoded.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=Jget_data["value"][k].replace("&", "%26")))
							elif type(Jget_data["value"][k]) == bytes:
								body_urlencoded.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=self.bytes_to_string(Jget_data["value"][k]).replace("&", "%26")))
							else:
								body_urlencoded.append("{key}={value}".format(key=jdks.normalize_key(k).replace("&", "%26").replace("=", "%3d"), value=str(Jget_data["value"][k]).replace("&", "%26")))
					body = "&".join(body_urlencoded)
				elif Jget_dataType["value"] == "xml":
					try:
						if "xml" in self.urlencode["RequestBody"]:
							body = urlencode(Utils.JSON2XML(Jget_data["value"]))
						else:
							body = Utils.JSON2XML(Jget_data["value"])
					except Exception as e:
						if type(Jget_data["value"]) == bytes:
							body = self.bytes_to_string(Jget_data["value"])
						else:
							body = str(Jget_data["value"])
				elif Jget_dataType["value"] == "unknown":
					if type(Jget_data["value"]) == bytes:
						body = self.bytes_to_string(Jget_data["value"])
					else:
						body = str(Jget_data["value"])
		except Exception as e: pass

		if update_content_length:
			self.request_headers.update("Content-Length", len(body.encode(Coding)), allow_new_key=True, case_insensitive=True)

		try:
			if isinstance(self.request_cookies, jdks.JSON_DUPLICATE_KEYS):
				for k in self.request_cookies.getObject():
					if type(k) in [unicode, str]:
						Jget = self.request_cookies.get(k)
						if type(Jget["value"]) in [OrderedDict, dict, list]:
							if jdks.normalize_key(k) in self.urlencode["HTTPCookies"]:
								cookies += "{key}={value}; ".format(key=jdks.normalize_key(k).replace("=", "%3d").replace(";", "%3b"), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)).replace(";", "%3b"))
							else:
								cookies += "{key}={value}; ".format(key=jdks.normalize_key(k).replace("=", "%3d").replace(";", "%3b"), value=jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False).replace(";", "%3b"))
						elif type(Jget["value"]) in [unicode, str]:
							cookies += "{key}={value}; ".format(key=jdks.normalize_key(k).replace("=", "%3d").replace(";", "%3b"), value=Jget["value"].replace(";", "%3b"))
						elif type(Jget["value"]) == bytes:
							cookies += "{key}={value}; ".format(key=jdks.normalize_key(k).replace("=", "%3d").replace(";", "%3b"), value=self.bytes_to_string(Jget["value"]).replace(";", "%3b"))
						else:
							cookies += "{key}={value}; ".format(key=jdks.normalize_key(k).replace("=", "%3d").replace(";", "%3b"), value=str(Jget["value"]).replace(";", "%3b"))

				if len(cookies) > 0:
					cookies = cookies.replace("\r", "%0d").replace("\n", "%0a")
					self.request_headers.update("Cookie", cookies[:-2], allow_new_key=True, case_insensitive=True)
		except Exception as e: pass

		try:
			if isinstance(self.request_headers, jdks.JSON_DUPLICATE_KEYS):
				for k in self.request_headers.getObject():
					if type(k) in [unicode, str]:
						Jget = self.request_headers.get(k)
						if type(Jget["value"]) in [OrderedDict, dict, list]:
							if jdks.normalize_key(k) in self.urlencode["HTTPHeaders"]:
								headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k).replace("\r", "%0d").replace("\n", "%0a"), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)).replace("\r", "%0d").replace("\n", "%0a"))
							else:
								headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k).replace("\r", "%0d").replace("\n", "%0a"), value=jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False).replace("\r", "%0d").replace("\n", "%0a"))
						elif type(Jget["value"]) in [unicode, str]:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k).replace("\r", "%0d").replace("\n", "%0a"), value=Jget["value"].replace("\r", "%0d").replace("\n", "%0a"))
						elif type(Jget["value"]) == bytes:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k).replace("\r", "%0d").replace("\n", "%0a"), value=self.bytes_to_string(Jget["value"]).replace("\r", "%0d").replace("\n", "%0a"))
						else:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k).replace("\r", "%0d").replace("\n", "%0a"), value=str(Jget["value"]).replace("\r", "%0d").replace("\n", "%0a"))
		except Exception as e: pass

		unparseRequest = method+" "+path+queryParams+fragment+" "+httpVersion+headers+"\r\n\r\n"+body
		return unparseRequest




class TP_HTTP_RESPONSE_PARSER:
	def __init__(self, rawResponse, separator="||", parse_index="$", dupSign_start="{{{", dupSign_end="}}}", ordered_dict=False, skipDuplicated=True):
		self.separator = separator; self.parse_index = parse_index; self.dupSign_start = dupSign_start; self.dupSign_end = dupSign_end; self.ordered_dict = ordered_dict; self.skipDuplicated = skipDuplicated

		self.urlencode = {
			"ResponseHeaders": {},
			"ResponseCookies": {},
			"ResponseBody": {}
		}

		responseHeader = responseBody = ""
		if type(rawResponse) == bytes:
			rawResponse = self.bytes_to_string(rawResponse)
		responseHeader = re.split("\r\n\r\n|\n\n", rawResponse, 1)[0]
		try:
			responseBody = re.split("\r\n\r\n|\n\n", rawResponse, 1)[1]
		except Exception as e: pass

		## Response HTTP Version ##
		try:
			self.response_httpVersion = re.split("\r\n|\n", responseHeader)[0].split(" ")[0]
		except Exception as e:
			self.response_httpVersion = ""
		##

		## Response Status Code ##
		try:
			self.response_statusCode = int(re.split("\r\n|\n", responseHeader)[0].split(" ")[1])
		except Exception as e:
			self.response_statusCode = ""
		##

		## Response Status Text ##
		try:
			self.response_statusText = " ".join(re.split("\r\n|\n", responseHeader)[0].split(" ")[2:])
		except Exception as e:
			self.response_statusText = ""
		##

		## Response Headers ##
		self.response_headers = jdks.loads("{}", ordered_dict=self.ordered_dict)
		try:
			for header in re.split("\r\n|\n", responseHeader)[1:]:
				if re.match("^[^:]+: .*$", header):
					kv = re.findall("^([^:]+): (.*)$", header)[0]
					JDKSObject = jdks.loads(kv[1], dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.response_headers.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
					else:
						JDKSObject = jdks.loads(urldecode(kv[1]), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
						if JDKSObject:
							self.urlencode["ResponseHeaders"][kv[0]] = True
							self.response_headers.set(kv[0], JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
						else:
							self.response_headers.set(kv[0], kv[1], separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		except Exception as e: pass
		##

		## Response Cookies ##
		self.response_cookies = jdks.loads("{}", ordered_dict=self.ordered_dict)
		for k,v in self.response_headers.filter_keys("Set-Cookie", ordered_dict=True).getObject().items():
			cookie = v.split(";")[0]
			kv = cookie.split("=", 1)
			if len(kv) == 2:
				JDKSObject = jdks.loads(kv[1].strip(), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
				if JDKSObject:
					self.response_cookies.set(kv[0].strip(), JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
				else:
					JDKSObject = jdks.loads(urldecode(kv[1].strip()), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.urlencode["ResponseCookies"][kv[1].strip()] = True
						self.response_cookies.set(kv[0].strip(), JDKSObject.getObject(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
					else:
						self.response_cookies.set(kv[0].strip(), kv[1].strip(), separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
			else:
				self.response_cookies.set(kv[0].strip(), "", separator=self.separator, parse_index=self.parse_index, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end)
		##

		## Response Body ##
		try:
			resBody = responseBody
			if self.response_headers.get("Content-Length", case_insensitive=True)["value"] == "JSON_DUPLICATE_KEYS_ERROR": self.response_headers.set("Content-Length", len(resBody))

			if len(resBody) > 0:
				# JSON Body
				JDKSObject = jdks.loads(resBody, dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
				if JDKSObject:
					self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "json", "data": JDKSObject.getObject() })
				else:
					JDKSObject = jdks.loads(urldecode(resBody), dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, ordered_dict=self.ordered_dict, skipDuplicated=self.skipDuplicated)
					if JDKSObject:
						self.urlencode["ResponseBody"]["json"] = True
						self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "json", "data": JDKSObject.getObject() })
					else:
						if Utils.XML2JSON(resBody, ordered_dict=self.ordered_dict):
							self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "xml", "data": Utils.XML2JSON(resBody, ordered_dict=self.ordered_dict) })
						else:
							if Utils.XML2JSON(urldecode(resBody), ordered_dict=self.ordered_dict):
								self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "xml", "data": Utils.XML2JSON(urldecode(resBody), ordered_dict=self.ordered_dict) })
								self.urlencode["ResponseBody"]["xml"] = True
							else:
								self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": "unknown", "data": resBody })
			else:
				# No body
				self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": None, "data": None })
		except Exception as e:
			# No body
			self.response_body = jdks.JSON_DUPLICATE_KEYS({ "dataType": None, "data": None })
		##

	def bytes_to_string(self, data):
		# Try plain UTF-8
		try:
			return data.decode("utf8")
		except Exception: pass

		# Try gzip
		try:
			with gzip.GzipFile(fileobj=BytesIO(data)) as f:
				decompressed = f.read()
				return decompressed.decode("utf8")
		except Exception: pass

		# Try raw deflate (zlib wbits=-15)
		try:
			decompressed = zlib.decompress(data, wbits=-15)
			return decompressed.decode("utf8")
		except Exception: pass

		# Try zlib default (wbits=+zlib format)
		try:
			decompressed = zlib.decompress(data)
			return decompressed.decode("utf8")
		except Exception: pass

		# Try latin1 as a fallback for decoding weird encodings (1:1 byte mapping)
		try:
			return data.decode("latin1")
		except Exception: pass

		# Final fallback: replace invalid chars
		return data.decode("utf8", errors="replace")

	def unparse(self, Coding="utf8", update_content_length=False):
		httpVersion = statusCode = statusText = headers = body = ""

		if type(self.response_httpVersion) in [unicode, str]:
			httpVersion = self.response_httpVersion
		elif type(self.response_httpVersion) == bytes:
			httpVersion = self.bytes_to_string(self.response_httpVersion)
		else:
			httpVersion = str(self.response_httpVersion)

		if type(self.response_statusCode) in [unicode, str]:
			statusCode = self.response_statusCode
		elif type(self.response_statusCode) == bytes:
			statusCode = self.bytes_to_string(self.response_statusCode)
		else:
			statusCode = str(self.response_statusCode)

		if type(self.response_statusText) in [unicode, str]:
			statusText = self.response_statusText
		elif type(self.response_statusText) == bytes:
			statusText = self.bytes_to_string(self.response_statusText)
		else:
			statusText = str(self.response_statusText)

		try:
			if isinstance(self.response_body, jdks.JSON_DUPLICATE_KEYS):
				if self.response_body.get("dataType")["value"] == "json":
					if "json" in self.urlencode["ResponseBody"]:
						body = urlencode(jdks.JSON_DUPLICATE_KEYS(self.response_body.get("data")["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False))
					else:
						body = jdks.JSON_DUPLICATE_KEYS(self.response_body.get("data")["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)
				elif self.response_body.get("dataType")["value"] == "xml":
					try:
						if "xml" in self.urlencode["ResponseBody"]:
							body = urlencode(Utils.JSON2XML(self.response_body.get("data")["value"]))
						else:
							body = Utils.JSON2XML(self.response_body.get("data")["value"])
					except Exception as e:
						body = self.response_body.get("data")["value"]
				elif self.response_body.get("dataType")["value"] == "unknown":
					body = self.response_body.get("data")["value"]
		except Exception as e: pass

		if update_content_length:
			self.response_headers.update("Content-Length", len(body.encode(Coding)), allow_new_key=True, case_insensitive=True)

		try:
			if isinstance(self.response_headers, jdks.JSON_DUPLICATE_KEYS):
				for k in self.response_headers.getObject():
					if type(k) in [unicode, str]:
						Jget = self.response_headers.get(k)
						if type(Jget["value"]) in [OrderedDict, dict, list]:
							if jdks.normalize_key(k) in self.urlencode["ResponseHeaders"]:
								headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k), value=urlencode(jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False)))
							else:
								headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k), value=jdks.JSON_DUPLICATE_KEYS(Jget["value"]).dumps(dupSign_start=self.dupSign_start, dupSign_end=self.dupSign_end, separators=(",",":"), ensure_ascii=False))
						elif type(Jget["value"]) in [unicode, str]:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k), value=Jget["value"])
						elif type(Jget["value"]) == bytes:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k), value=self.bytes_to_string(Jget["value"]))
						else:
							headers += "\r\n{key}: {value}".format(key=jdks.normalize_key(k), value=str(Jget["value"]))
		except Exception as e: pass

		unparseResponse = httpVersion+" "+statusCode+" "+statusText+headers+"\r\n\r\n"+body
		return unparseResponse