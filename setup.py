import setuptools
import datetime

setuptools.setup(
	name="TP-HTTP-Request-Response-Parser",
	version=datetime.datetime.now().strftime("%Y.%m.%d"),
	author="Truoc Phan",
	license="MIT",
	author_email="truocphan112017@gmail.com",
	description="Parse the raw HTTP Request/ Response to the Object",
	long_description=open("README.md").read(),
	long_description_content_type="text/markdown",
	install_requires=open("requirements.txt").read().split(),
	url="https://github.com/truocphan/TP-HTTP-Request-Response-Parser",
	classifiers=[
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 2",
		"Programming Language :: Python :: Implementation :: Jython"
	],
	keywords=["HTTP Request Parser", "HTTP Response Parser"],
	packages=["TP_HTTP_Request_Response_Parser"],
)