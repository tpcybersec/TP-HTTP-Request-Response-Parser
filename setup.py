from TP_HTTP_Request_Response_Parser import TP_HTTP_Request_Response_Parser_VERSION
import setuptools

setuptools.setup(
	name="TP-HTTP-Request-Response-Parser",
	version=TP_HTTP_Request_Response_Parser_VERSION,
	author="TP Cyber Security",
	license="MIT",
	author_email="tpcybersec2023@gmail.com",
	description="Parse/ Unparse the HTTP Request/ Response",
	long_description=open("README.md").read(),
	long_description_content_type="text/markdown",
	install_requires=open("requirements.txt").read().split(),
	url="https://github.com/tpcybersec/TP-HTTP-Request-Response-Parser",
	classifiers=[
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 2",
		"Programming Language :: Python :: Implementation :: Jython"
	],
	keywords=["TPCyberSec", "HTTP Request Parser", "HTTP Response Parser"],
	packages=setuptools.find_packages(),
)