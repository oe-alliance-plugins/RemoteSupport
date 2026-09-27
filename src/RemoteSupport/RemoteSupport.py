# Helpers for remote support sessions with sshx, see plugin.py.
#
# The session runs detached from enigma2 and keeps its state in SESSION_DIR, so a supporter who
# restarts the GUI does not lock himself out. /tmp is cleared by a reboot, which ends the session anyway.
#
# Run as a program this module provides:
#   shell    The shell sshx starts for every terminal. It waits until the participants are approved on
#            the receiver, runs the shell on its own pty, tees the raw output to SESSION_DIR so the
#            session can be mirrored on the TV and appends a readable transcript to the session log.
#            While somebody new waits for the approval (LOCK_FILE), input is discarded.
#   watcher  The sshx client does not learn who joins a session, only the web clients do. So the
#            receiver joins its own session like a browser and logs joins, leaves, renames and chat.
#   grab     The grab command of the support shells. Without a filename the grab is shown as an image
#            in the terminal (the web clients of sshx support inline images) and saved next to the
#            session log, otherwise /usr/bin/grab runs as usual.
#
# Typing in a terminal, joins, leaves and chat touch ACTIVITY_FILE, so enigma2 can end a forgotten session.

from base64 import b64decode, b64encode
from codecs import getincrementaldecoder
from fcntl import ioctl
from glob import glob
from os import O_APPEND, O_CREAT, O_WRONLY, X_OK, access, close, environ, execv, fstat, ftruncate, getpid, kill, open as osOpen, read, remove, rename, utime, write
from os.path import basename, dirname, exists, join
from pty import fork
from re import compile
from select import select
from signal import SIGHUP, SIGINT, SIGTERM, SIGWINCH, signal
from socket import gethostname
from subprocess import run
from sys import argv, stdout
from termios import TCSAFLUSH, TIOCGWINSZ, TIOCSWINSZ, tcgetattr, tcsetattr
from time import sleep, strftime, time
from tty import setraw

SESSION_DIR = "/tmp/sshx-e2"
SHELL_WRAPPER = join(SESSION_DIR, "shell")
SSHX_PID_FILE = join(SESSION_DIR, "sshx.pid")
SSHX_OUTPUT_FILE = join(SESSION_DIR, "sshx.out")
SSHX_ERROR_FILE = join(SESSION_DIR, "sshx.err")
WATCHER_PID_FILE = join(SESSION_DIR, "watcher.pid")
WATCHER_OUTPUT_FILE = join(SESSION_DIR, "watcher.out")
LOG_PATH_FILE = join(SESSION_DIR, "logpath")
APPROVED_FILE = join(SESSION_DIR, "approved")  # The uids of the approved participants.
LOCK_FILE = join(SESSION_DIR, "locked")  # Somebody waits for the approval, the session is read-only.
LINK_FILE = join(SESSION_DIR, "link")
CONNECTED_FILE = join(SESSION_DIR, "connected")  # uid, name and whether the name is final, per participant.
ACTIVITY_FILE = join(SESSION_DIR, "activity")
CHAT_FILE = join(SESSION_DIR, "chat")  # A message enigma2 wants to send to the participants.
CREATE_FILE = join(SESSION_DIR, "create")  # enigma2 wants a new terminal.
GRABBED_FILE = join(SESSION_DIR, "grabbed")  # A grab enigma2 announces on the TV.
BIN_DIR = join(SESSION_DIR, "bin")  # Commands of the support shells, first in PATH.
SHELL_RC = join(SESSION_DIR, "shellrc")
GRAB = "/usr/bin/grab"
GRAB_SUFFIX = "-sshx-grab-"
IMAGE_START = b"\x1b]1337;File="  # Inline image of the iTerm2 protocol.
BASH = "/bin/bash"
GRAB_OPTIONS = {option: option for option in ("-o", "-v", "-d", "-n", "-l", "-b", "-p", "-q", "-s", "-h")}  # Flags of /usr/bin/grab.
GRAB_VALUE_OPTIONS = {option: option for option in ("-i", "-r", "-j")}  # Options of /usr/bin/grab with a number.
TERMINAL = compile(r".*/term-(\d+)")
TERMINAL_LOG_LIMIT = 262144

APPROVAL_TIMEOUT = 60  # Longer than the question on the TV, which may wait behind other notifications.
ESCAPES = compile(r"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)?|[()*+].|[=>78DEHMNOc])")
SALT = b"This is a non-random salt for sshx.io, since we want to stretch the security of 83-bit keys!"
PING_INTERVAL = 15
JOIN_DELAY = 5  # The server names new users "User <n>" until their browser sets the chosen name.
ACTIVITY_INTERVAL = 10
DEFAULT_NAME = compile(r"^User \d+$")


class RemoteSupportShell:
	def __init__(self):
		self.sessionLog = readFile(LOG_PATH_FILE)
		self.base = join(SESSION_DIR, f"term-{getpid()}")
		self.name = f"T{getpid()}"
		self.decoder = getincrementaldecoder("utf-8")(errors="replace")
		self.line = []
		self.cursor = 0
		self.pid = -1
		self.master = -1
		self.lastActivity = 0
		self.locked = False
		self.imageRest = b""
		self.teeRest = b""
		self.log = osOpen(f"{self.base}.log", O_WRONLY | O_CREAT | O_APPEND, 0o600)

	def run(self):
		self.logLine("--- Terminal opened ---")
		signal(SIGHUP, terminate)
		try:
			if self.waitForApproval():
				self.runShell()
			else:
				sleep(2)  # Let the supporter read the message.
		except Terminated:  # Closed before the approval.
			pass
		self.logLine("--- Terminal closed ---")
		close(self.log)
		for extension in (".log", ".size"):
			try:
				remove(f"{self.base}{extension}")
			except OSError:
				pass

	def waitForApproval(self):
		if approved():
			self.logLine("Access already approved")
			return True
		self.show("Waiting for approval on the receiver...")
		request = f"{self.base}.request"
		denied = f"{self.base}.denied"
		open(request, "w").close()
		try:
			end = time() + APPROVAL_TIMEOUT
			while time() < end:
				if approved():
					self.show("Access approved.")
					return True
				if exists(denied):
					self.show("Access denied.")
					return False
				if select([0], [], [], 0.5)[0] and not read(0, 1024):  # Input is discarded until approved.
					return False
			self.show("No approval received.")
			return False
		finally:
			for path in (request, denied):
				try:
					remove(path)
				except OSError:
					pass

	def runShell(self):
		shell = BASH if access(BASH, X_OK) else "/bin/sh"
		environ["SHELL"] = shell
		environ.setdefault("HOME", "/home/root")
		self.pid, self.master = fork()
		if self.pid == 0:  # The rc file reads the login profiles and puts our commands first in PATH.
			if shell == BASH:
				execv(shell, [shell, "--rcfile", SHELL_RC, "-i"])
			environ["ENV"] = SHELL_RC
			execv(shell, [shell, "-i"])
		self.resize()
		signal(SIGWINCH, self.resize)
		signal(SIGHUP, terminate)
		signal(SIGTERM, terminate)
		attributes = tcgetattr(0)
		setraw(0)
		try:
			while True:
				ready = select([0, self.master], [], [], 0.5)[0]
				inject = f"{self.base}.inject"
				if exists(inject):  # A grab from the web interface.
					with open(inject, "rb") as fd:
						data = fd.read()
					remove(inject)
					writeAll(1, data)
					self.tee(data)
					self.transcript(data)
				if self.master in ready:
					try:
						data = read(self.master, 4096)
					except OSError:
						data = b""
					if not data:
						break
					writeAll(1, data)
					self.tee(data)
					self.transcript(data)
				if 0 in ready:
					data = read(0, 4096)
					if not data:
						break
					if exists(LOCK_FILE):
						if not self.locked:  # Shown to everybody, the chat still works.
							self.locked = True
							writeAll(1, b"\r\n[Input is blocked until the receiver approves the new user]\r\n")
						continue
					self.locked = False
					writeAll(self.master, data)
					if time() - self.lastActivity >= ACTIVITY_INTERVAL:
						self.lastActivity = time()
						touchActivity()
		except Terminated:
			pass
		finally:
			try:
				kill(self.pid, SIGHUP)
				tcsetattr(0, TCSAFLUSH, attributes)
			except OSError:
				pass
			if "".join(self.line).strip():
				self.logLine("".join(self.line).rstrip())

	def tee(self, data):  # For Live Watch, which can not show images.
		data, self.teeRest = replaceImages(self.teeRest + data)
		if fstat(self.log).st_size > TERMINAL_LOG_LIMIT:
			ftruncate(self.log, 0)
		writeAll(self.log, data)

	def resize(self, *args):
		try:
			size = ioctl(0, TIOCGWINSZ, bytes(8))
			ioctl(self.master, TIOCSWINSZ, size)
			rows, cols = size[0] | size[1] << 8, size[2] | size[3] << 8
			with open(f"{self.base}.size", "w") as fd:
				fd.write(f"{cols} {rows}")
		except OSError:
			pass

	def show(self, text):
		writeAll(1, f"{text}\n".encode("utf-8"))  # The cooked pty adds the carriage return.
		writeAll(self.log, f"{text}\r\n".encode("utf-8"))
		self.logLine(text)

	def logLine(self, text):
		appendLog(self.sessionLog, f"{strftime('%H:%M:%S')} [{self.name}] {text}")

	def transcript(self, data):  # Minimal line editing so the log shows what was visible.
		data, self.imageRest = replaceImages(self.imageRest + data, placeholder=False)  # The grab command logs where it saved the image.
		for char in ESCAPES.sub("", self.decoder.decode(data)):
			if char == "\n":
				text = "".join(self.line).rstrip()
				if text:  # Full screen programs redraw with many empty lines.
					self.logLine(text)
				self.line = []
				self.cursor = 0
			elif char == "\r":
				self.cursor = 0
			elif char == "\b":
				self.cursor = max(0, self.cursor - 1)
			elif char >= " " or char == "\t":
				if self.cursor < len(self.line):
					self.line[self.cursor] = char
				else:
					self.line.append(char)
				self.cursor += 1


class RemoteSupportWatcher:
	def __init__(self):
		self.sessionLog = readFile(LOG_PATH_FILE)
		self.link = readFile(LINK_FILE)
		self.socket = None
		self.uid = None
		self.users = {}  # uid: name of announced users.
		self.pending = {}  # uid: (name, time) of users that still have the default name.
		self.participants = {}  # uid: latest name of everybody who joined.
		self.created = 0

	def run(self):
		from cbor2 import loads  # Not at module level as enigma2 imports this module and the packages may be missing.
		from websocket import WebSocketTimeoutException, create_connection
		server, sessionPart = self.link.split("/s/", 1)
		sessionId, key = sessionPart.split("#", 1)
		key = key.split(",", 1)[0]  # A write password would follow the key.
		if not server.startswith("https://"):
			self.logLine("Unable to watch the users: the sshx server does not use HTTPS")
			raise SystemExit(1)
		self.socket = create_connection(f"wss://{server[len('https://'):]}/api/s/{sessionId}", timeout=1)
		self.send({"authenticate": [encryptedZeros(key), None]})
		self.send({"setName": argv[2] if len(argv) > 2 else gethostname()})
		lastPing = time()
		while True:
			try:
				data = self.socket.recv()
			except WebSocketTimeoutException:
				data = None
			if data == "":  # The server closed the connection.
				break
			message = loads(data) if isinstance(data, bytes) else None
			chat = readFile(CHAT_FILE)
			if chat:
				try:
					remove(CHAT_FILE)
				except OSError:
					pass
				self.send({"chat": chat})
			if exists(CREATE_FILE):
				try:
					remove(CREATE_FILE)
				except OSError:
					pass
				self.created += 1
				self.send({"create": [40 * self.created, 40 * self.created]})  # Cascaded on the canvas of the web clients.
			if time() - lastPing >= PING_INTERVAL:
				self.send({"ping": int(time() * 1000)})
				lastPing = time()
			if isinstance(message, dict):
				self.handle(message)
			for uid in [uid for uid, (name, since) in self.pending.items() if time() - since >= JOIN_DELAY]:
				name = self.pending.pop(uid)[0]
				self.announce(uid, name)
				self.writeConnected()

	def send(self, message):
		from cbor2 import dumps
		self.socket.send_binary(dumps(message))

	def handle(self, message):
		if "hello" in message:
			self.uid = message["hello"][0]
		elif "invalidAuth" in message:
			self.logLine("Unable to watch the users: invalid session key")
			raise SystemExit(1)
		elif "users" in message:
			for uid, user in message["users"]:
				self.update(uid, user)
		elif "userDiff" in message:
			uid, user = message["userDiff"]
			self.update(uid, user)
		elif "hear" in message:
			uid, name, text = message["hear"]
			if uid != self.uid:  # Our own messages are no activity.
				self.logLine(f"Chat from {name}: {text}")
				touchActivity()
		elif "error" in message:
			self.logLine(f"sshx server error: {message['error']}")

	def update(self, uid, user):
		if uid != self.uid:
			touchActivity()
		self.updateUser(uid, user)
		self.writeConnected()

	def writeConnected(self):  # enigma2 asks for the approval of every participant.
		try:
			with open(CONNECTED_FILE, "w") as fd:
				fd.write("".join(f"{uid}\t{name}\t1\n" for uid, name in self.users.items()))
				fd.write("".join(f"{uid}\t{name}\t0\n" for uid, (name, since) in self.pending.items()))
		except OSError:
			pass

	def updateUser(self, uid, user):
		if uid == self.uid:
			return
		newName = user.get("name") if user else None
		if uid in self.pending:
			if newName and DEFAULT_NAME.match(newName):
				return
			pendingName = self.pending.pop(uid)[0]
			self.announce(uid, newName or pendingName)
			if newName is not None:
				return
		oldName = self.users.get(uid)
		if newName == oldName:
			return
		if newName is None:
			del self.users[uid]
			self.logLine(f"User left: {oldName}")
		elif oldName is None:
			if DEFAULT_NAME.match(newName):
				self.pending[uid] = (newName, time())
			else:
				self.announce(uid, newName)
		else:
			self.users[uid] = newName
			self.logLine(f"User renamed: {oldName} -> {newName}")
			self.participants[uid] = newName
			self.logParticipants()

	def announce(self, uid, name):
		self.users[uid] = name
		self.logLine(f"User joined: {name}")
		self.participants[uid] = name
		self.logParticipants()

	def logParticipants(self):
		self.logLine(f"Users: {', '.join(dict.fromkeys(self.participants.values()))}")

	def logLine(self, text):
		print(f"[RemoteSupport] {text}", flush=True)
		appendLog(self.sessionLog, f"{strftime('%Y-%m-%d %H:%M:%S')} {text}")


def encryptedZeros(key):  # Proves the knowledge of the key the same way the sshx web client does.
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
	from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
	aesKey = Argon2id(salt=SALT, length=16, iterations=2, lanes=1, memory_cost=19 * 1024).derive(key.encode("utf-8"))
	encryptor = Cipher(algorithms.AES(aesKey), modes.CTR(bytes(16))).encryptor()
	return encryptor.update(bytes(16)) + encryptor.finalize()


def replaceImages(data, placeholder=True):  # Returns data with a placeholder for every inline image and an unfinished rest.
	result = b""
	while True:
		start = data.find(IMAGE_START)
		if start < 0:
			return result + data, b""
		ends = [index for index in (data.find(b"\x07", start), data.find(b"\x1b\\", start)) if index >= 0]
		if not ends:
			return result + data[:start], data[start:][-4194304:]
		end = min(ends)
		params = {key: value for key, value in (param.split(b"=", 1) for param in data[start + len(IMAGE_START):end].split(b":", 1)[0].split(b";") if b"=" in param)}
		try:
			label = b64decode(params.get(b"name", b"")).decode("utf-8", "replace")
		except ValueError:
			label = ""
		result += data[:start] + (f"[{label or 'image'}]".encode("utf-8") if placeholder else b"")
		data = data[end + (1 if data[end:end + 1] == b"\x07" else 2):]


def imageSize(data):
	if data[:8] == b"\x89PNG\r\n\x1a\n":
		return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
	index = 2
	while index + 9 < len(data) and data[index] == 0xFF:  # JPEG segments up to the frame header.
		marker = data[index + 1]
		length = int.from_bytes(data[index + 2:index + 4], "big")
		if marker in (0xC0, 0xC1, 0xC2, 0xC3):
			return int.from_bytes(data[index + 7:index + 9], "big"), int.from_bytes(data[index + 5:index + 7], "big")
		index += 2 + length
	return 0, 0


def grabCommand(args):  # The grab command of the support shells, see the top of this file.
	target = None
	if args[:1] == ["--to"] and len(args) > 1:  # From the web interface, into this terminal.
		match = TERMINAL.fullmatch(args[1])
		if not match:
			return
		target, args = join(SESSION_DIR, f"term-{int(match.group(1))}"), args[2:]
	wait = 0
	options = []
	passThrough = False
	fileName = None
	index = 0
	while index < len(args):
		arg = args[index]
		if arg == "-w" and index + 1 < len(args) and args[index + 1].isdigit():
			wait = int(args[index + 1])
			index += 2
			continue
		if arg in GRAB_VALUE_OPTIONS and index + 1 < len(args) and args[index + 1].isdigit():
			options += [GRAB_VALUE_OPTIONS[arg], str(int(args[index + 1]))]
			index += 2
			continue
		if arg in GRAB_OPTIONS:
			options.append(GRAB_OPTIONS[arg])
			passThrough = passThrough or arg in ("-s", "-h")
		elif not arg.startswith("-") and not fileName:
			fileName = arg
			passThrough = True
		else:
			print(f"grab: unknown option {arg}, see grab -h")
			return
		index += 1
	if passThrough and target is None:
		if "-h" in options:
			run([GRAB, "-h"])
			print("\nIn the remote support session without a filename the grab is shown here and saved with the session log.\n-w (seconds) wait before grabbing")
			return
		execv(GRAB, [GRAB] + options + ([fileName] if fileName else []))
	for seconds in range(wait, 0, -1):
		stdout.write(f"\rgrab in {seconds} s ")
		stdout.flush()
		sleep(1)
	if wait:
		stdout.write("\r              \r")
	osd = "-o" in options
	video = "-v" in options
	if "-p" not in options and "-j" not in options:
		options += ["-p"] if osd else ["-j", "80"]  # PNG keeps the transparency of the OSD.
	if "-r" not in options:
		options += ["-r", "1920"]
	data = run([GRAB, "-q", "-s"] + options, capture_output=True).stdout
	if not data:
		print("grab failed")
		return
	width, height = imageSize(data)
	label = f"grab{' -o' if osd else ''}{' -v' if video else ''} {width}x{height} {strftime('%H:%M:%S')}"
	path = saveGrab(data)
	escape = IMAGE_START + b"name=" + b64encode(label.encode("utf-8")) + f";size={len(data)};inline=1:".encode() + b64encode(data) + b"\x07\r\n"
	if target:
		with open(f"{target}.inject.tmp", "wb") as fd:
			fd.write(escape + (f"{savedText(path)}\r\n".encode() if path else b""))
		rename(f"{target}.inject.tmp", f"{target}.inject")
	else:
		stdout.buffer.write(escape)
		stdout.flush()
		if path:
			print(savedText(path))
		try:
			with open(GRABBED_FILE, "w") as fd:
				fd.write(label)
		except OSError:
			pass


def savedText(path):  # Numbered like in the viewers of the session logs.
	number = len(glob(f"{path[:path.rindex(GRAB_SUFFIX) + len(GRAB_SUFFIX)]}*"))
	return f"Screenshot {number} saved: {path}"


def saveGrab(data):  # Next to the session log, so it is listed, downloaded and deleted with it.
	sessionLog = readFile(LOG_PATH_FILE)
	if not sessionLog.endswith("-sshx-session.log"):
		return None
	extension = "png" if data[:4] == b"\x89PNG" else "jpg"
	path = join(dirname(sessionLog), f"{basename(sessionLog)[:-len('-sshx-session.log')]}{GRAB_SUFFIX}{strftime('%H%M%S')}.{extension}")
	try:
		with open(path, "wb") as fd:
			fd.write(data)
		return path
	except OSError:
		return None


def approved():
	return exists(APPROVED_FILE) and not exists(LOCK_FILE)


def touchActivity():
	try:
		open(ACTIVITY_FILE, "a").close()
		utime(ACTIVITY_FILE)
	except OSError:
		pass


def readFile(path):
	try:
		with open(path) as fd:
			return fd.read().strip()
	except OSError:
		return ""


def appendLog(path, line):
	if path:
		try:
			fd = osOpen(path, O_WRONLY | O_CREAT | O_APPEND, 0o600)
			writeAll(fd, f"{line}\n".encode("utf-8"))
			close(fd)
		except OSError:
			pass


def writeAll(fd, data):
	while data:
		data = data[write(fd, data):]


class Terminated(Exception):
	pass


def terminate(*args):
	raise Terminated


if __name__ == "__main__":
	if argv[1:2] == ["shell"]:
		RemoteSupportShell().run()
	elif argv[1:2] == ["grab"]:
		grabCommand(argv[2:])
	elif argv[1:2] == ["watcher"]:
		for signalNumber in (SIGHUP, SIGINT, SIGTERM):
			signal(signalNumber, terminate)
		try:
			RemoteSupportWatcher().run()
		except Terminated:
			pass
