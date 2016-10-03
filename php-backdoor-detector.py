#!/usr/bin/python

"""
released under the MIT License
The MIT License (MIT)

Copyright (c) 2016 Yassine Addi

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import os, sys, time, re, requests, socket
from datetime import datetime
from collections import defaultdict
from optparse import OptionParser

__version__ = "1.0.0"
__author__ 	= "Yassine Addi <yassineaddi.dev@gmail.com>"

class Detector:
	shells = ["angel", "b374k", "bv7binary", "c99", "c100", "r57", "webroot", "kacak", "symlink", "h4cker", "webadmin", "gazashell", "locus7shell", "syrianshell", "injection", "cyberwarrior", "ernebypass", "g6shell", "pouyaserver", "saudishell", "simattacker", "sosyeteshell", "tryagshell", "uploadshell", "wsoshell", "weevely", "zehir4shell", "lostdcshell", "commandshell", "mailershell", "cwshell", "iranshell", "indishell", "g6sshell", "sqlshell", "simshell", "tryagshell", "zehirshell", "unknown", "k2ll33d", "b1n4ry"]

	malicious = r"(?si)(preg_replace.*\/e|`.*?\$.*?`|\bpcntl\b|\bassert\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bphp_uname\b|\btcpflood\b|\budpflood\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bgzinflate\b|\bshow_source\b|\bphpinfo\b|\breadfile\b|\bfclose\b|\bfopen\b|\bmkdir\b|\bgzip|\bpython_exec\b|\bstr_rot13\b|\bchmod\b)"

	def __init__(self, directory):
		self.directory = directory
		countFiles = sum([len(files) for p, r, files in os.walk(directory)])
		started = datetime.now()
		self._("Scanning: %s (%s)" % (directory, countFiles))
		self._("Started:  %s" % started)
		self._("="*37 + "\n")
		self._isConnected = self.isConnected()
		extensions = defaultdict(int)
		for dirpath, dirnames, filenames in os.walk(directory):
			for filename in filenames:
				extensions[os.path.splitext(filename)[1].lower()] += 1
		self._("[+] Scanning: %s" % countFiles)
		for key, value in extensions.items():
			self._(" |  %s: %s" % (key.strip(".").upper() if key.split() else "Other", value), "", "\033[93m")
		print("")
		self.run()
		self._("[*] Scan Complete")
		print("")
		self._("="*37)
		ended = datetime.now()
		self._("Ended:    %s" % ended)
		elapsed = ended - started
		elapsed = divmod(elapsed.days * 86400 + elapsed.seconds, 60)
		self._("Elapsed:  %s Minutes, %s Seconds" % (elapsed[0], elapsed[1]))

	def run(self):
		for dirpath, dirnames, filenames in os.walk(self.directory):
		    for filename in filenames:
		    	file = os.path.join(dirpath, filename)
		    	if os.path.splitext(filename)[1].lower().strip(".") == "php":
		    		self.scanPhpFile(file)
		    	else:
		    		self.scanFiles(file)

	def scanFiles(self, file):
		filename = os.path.basename(file)
		with open(file, "r") as f:
			for i, line in enumerate(f.readlines()):
				match = re.findall(r"(?si)(<\?(?:php|=|\s)?)", line)
				if match:
					self.getFileInfo(file, "Possible PHP", [
						" |  PHP Tag: %s" % match[0],
						" |  Line Number: %s" % str(i+1)
					])

	def scanPhpFile(self, file):
		filename = os.path.basename(file)
		for shell in self.shells:
			if shell in filename.lower():
				self.getFileInfo(file, "Suspecious File Name")
		with open(file, "r") as f:
			for i, line in enumerate(f.readlines()):
				match = re.findall(self.malicious, line)
				if match:
					for x in match:
						self.getFileInfo(file, "Suspecious Function", [
							" |  Function Name: %s" % x,
							" |  Line Number: %s" % str(i+1)
						])
				match = re.findall(r"\$[{}'a-zA-Z_\s]+\(.*\)", line)
				if match:
					for x in match:
						self.getFileInfo(file, "Obfuscated Behavior", [
							" |  Behavior: %s" % x,
							" |  Line Number: %s" % str(i+1)
						])
			if self._isConnected:
				res = self.shellray(open(file, "r"))
				if res:
					self.getFileInfo(file, "Malware Detected", [
						" |  Service Provider: https://shellray.com",
						" |  Threat Name: %s" % res["threatname"],
						" |  SHA1: %s" % res["sha1"],
						" |  MD5: %s" % res["md5"],
					])
				res = self.virustotal(open(file, "rb"))
				if res:
					results = [res["scans"][antivirus]["result"] for antivirus in res["scans"] if res["scans"][antivirus]["detected"]]
					self.getFileInfo(file, "Malware Detected", [
						" |  Service Provider: https://www.virustotal.com",
						" |  Detection Ratio: %s / %s" % (res["positives"], res["total"]),
						" |  Results: %s" % ", ".join(results),
					])

	def virustotal(self, file):
		apiKey = ""
		if apiKey == "": return False
		try:
			r = requests.post("https://www.virustotal.com/vtapi/v2/file/scan", data={"apikey": apiKey}, files={"file": file})
			data = r.json()
			if data["response_code"] == 0: return False
			time.sleep(3)
			r = requests.post("https://www.virustotal.com/vtapi/v2/file/report", data={"apikey": apiKey, "resource": data["resource"]})
			try: data = r.json()
			except:return False
			if data["response_code"] == 0 or data["positives"] == 0: return False
			return data
		except requests.ConnectionError: return False

	def shellray(self, file):
		try:
			r = requests.post("https://shellray.com/upload", files={"file": file})
			data = r.json()
			if not data["infected"]: return False
			return data
		except requests.ConnectionError: return False

	def getFileInfo(self, file, alert, alerts = []):
		(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)
		self._("[!] %s: %s" % (alert, os.path.basename(file)))
		if alerts:
			for al in alerts:
				self._(al)
		self._(" |  Full Path: %s" % file)
		self._(" |  Owner: %s" % (str(uid) + ":" + str(gid)))
		self._(" |  Permission: %s" % oct(mode)[-3:])
		self._(" |  Last Accessed: %s" % time.ctime(atime))
		self._(" |  Last Modified: %s" % time.ctime(mtime))
		self._(" |  File Size: %s" % self.sizeOf(size))
		print("")

	def sizeOf(self, size, suffix="B"):
		for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
			if abs(size) < 1024.0:
				return "%3.1f%s%s" % (size, unit, suffix)
				size /= 1024.0
		return "%.1f%s%s" % (size, 'Yi', suffix)

	def _(self, content, color = "", current = False):
		useColor = {
			"red": "\033[91m",
			"green": "\033[92m",
            "yellow": "\033[93m",
            "purple": "\033[95m",
            "blue": "\033[94m",
            "": ""
		}[color]
		if self.supportsColor():
			currentColor = current if current else "\033[91m"
			regex = [
				(r"(\[\+] [a-zA-Z0-9 ]+): .*", "\033[1m\033[93m%s\033[0m"),
				(r"(\[\*] [a-zA-Z0-9 ]+)", "\033[1m\033[92m%s\033[0m"),
				(r"(\[!] [a-zA-Z0-9 ]+): .*", "\033[1m\033[91m%s\033[0m"),
				(r" \|  ([a-zA-Z0-9 ]+): .*", "\033[1m\033[94m%s\033[0m"),
				(r" (\|)  .*: .*", "\033[1m" + currentColor + "%s\033[0m")
			]
			for p, r in regex:
				rg = re.match(p, content)
				content = content.replace(rg.group(1), r % rg.group(1), 1) if rg else content
			print(useColor + content + "\033[0m")
		else: print(content)

	def supportsColor(self):
		plat = sys.platform
		supportedPlatform = plat != "Pocket PC" and (plat != "win32" or "ANSICON" in os.environ)
		isatty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
		if not supportedPlatform or not isatty: return False
		return True

	def isConnected(self):
		try:
			host = socket.gethostbyname("www.google.com")
			s = socket.create_connection((host, 80), 2)
			return True
		except: pass
		return False


usage = "%prog [options] <directory>"
description = "PHP backdoor detector is a Python toolkit that helps you find malicious hidden suspicious PHP scripts and shells in your site files. Copyright (c) %s" % __author__
version = "%s" % __version__
parser = OptionParser(usage=usage, description=description, version=version)
(opts, args) = parser.parse_args(sys.argv[1:])
if not args: parser.error("No directory supplied")
for directory in args:
	Detector(directory)
