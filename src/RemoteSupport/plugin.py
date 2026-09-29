from codecs import getincrementaldecoder
from glob import glob
from importlib import invalidate_caches
from importlib.util import find_spec
from os import chmod, makedirs, remove, stat
from os.path import basename, dirname, exists, join
from re import search
from select import POLLIN
from shlex import quote
from shutil import rmtree
from signal import SIGHUP, SIGINT, SIGTERM
from socket import AF_UNIX, SOCK_DGRAM, gethostname, socket
from time import strftime, strptime, time

from enigma import RT_HALIGN_LEFT, RT_VALIGN_CENTER, RT_VALIGN_TOP, eCanvas, eListbox, eListboxPythonMultiContent, eRect, eSocketNotifier, eTimer, gFont, gRGB, getDesktop

from Components.ActionMap import HelpableActionMap
from Components.config import config
from Components.Console import Console
from Components.GUIComponent import GUIComponent
from Components.Label import Label
from Components.MenuList import MenuList
from Components.MultiContent import MultiContentEntryRectangle, MultiContentEntryText
from Components.Pixmap import MultiPixmap
from Components.Sources.StaticText import StaticText
from Components.SystemInfo import BoxInfo
from Plugins.Plugin import PluginDescriptor
try:  # The picture player shows the screenshots of a session.
	from Plugins.Extensions.PicturePlayer.ui import Pic_Full_View as PictureViewer
except ImportError:
	PictureViewer = None
from Screens.MessageBox import MessageBox
from Screens.NetworkServices import NetworkLogScreen
from Screens.Screen import Screen
from Tools.Directories import SCOPE_PLUGINS, fileReadLine, fileReadLines, fileWriteLine, resolveFilename
from Tools.Notifications import AddModalNotification, notificationCenter
from skin import parseColor, parseFont
from . import RemoteSupport as RemoteSupportTools, _, ngettext
from .RemoteSupport import ACTIVITY_FILE, APPROVED_FILE, CHAT_FILE, CREATE_FILE, GRAB_SUFFIX, GRABBED_FILE, HANDOVER_FILE, IDLE_TIMEOUT, LINK_FILE, LOCK_FILE, LOG_PATH_FILE, NOTIFY_SOCKET, SESSION_DIR, SESSION_ENDED, SESSION_LOG_SUFFIX, SHELL_WRAPPER, SSHX_ERROR_FILE, SSHX_OUTPUT_FILE, SSHX_PID_FILE, STOP_TIMEOUT, WATCHER_OUTPUT_FILE, WATCHER_PID_FILE, currentApprovals, hangupShells, participants, prepareShell, runningPid, shareUrl, signalPid, sshxBinary, terminalLogs

MODULE_NAME = "RemoteSupport"

REQUIRED_MODULES = ("websocket", "cbor2", "cryptography.hazmat.primitives.kdf.argon2", "qrcode", "pyte")
USERS = (" Users: ", " Participants: ")  # The latter in logs of older versions.
APPROVAL_QUESTION_TIMEOUT = 30
HANDOVER_APPROVAL_WINDOW = 30  # Who is connected this long after taking over a session with approved terminals keeps the access.
INDICATOR_ACTIVITY = 3  # Seconds a terminal counts as active after its last output.
MAX_DECLINES = 3  # Without anybody approved the session is useless, so it ends after this many refusals.
IDLE_WARNING = 300
FONT_WIDTH_RATIO = 0.6  # Glyph advance of the monospaced console font relative to its size.
LINE_HEIGHT_RATIO = 1.25  # Line height of the console font relative to its size.
# Background jobs of a non-interactive shell ignore SIGINT, but sshx needs it to close the session cleanly.
SIGINT_RESET_LAUNCHER = "import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execv(sys.argv[1], sys.argv[1:])"


def modulesInstalled():  # The watcher needs them, also for a session started outside of enigma2 with sshx in RAM.
	def installed(module):
		try:
			return find_spec(module) is not None
		except ImportError:  # The parent package of a dotted module name is missing.
			return False

	invalidate_caches()
	return all(installed(module) for module in REQUIRED_MODULES)


def incomplete():  # The plugin package depends on sshx and these modules, somebody may have removed one anyway.
	return not sshxBinary() or not modulesInstalled()


def withdrawQuestion(callback):  # Closes a question on the TV without answering it, or removes it from the queue.
	center = notificationCenter
	if center.modalDialog and center.modalDialog.shown and center.modalCallback == callback:
		center.modalCallback = None
		center.modalDialog.stopTimer("Question withdrawn")
		center.onModalAnswer(False)
	else:
		center.modalQueue[:] = [entry for entry in center.modalQueue if entry[6] != callback]


consoles = []


def startDetached(command, pidFile, outputFile, errorFile=None):
	# The shell exits at once, so the program is not bound to enigma2's pipes or lifetime.
	# The console must stay referenced until then, its destructor kills the process group.
	def finished(data, retVal, extraArgs):
		consoles.remove(console)

	console = Console()
	consoles.append(console)
	errorRedirect = f"2>{quote(errorFile)}" if errorFile else "2>&1"
	console.ePopen(["/bin/sh", "/bin/sh", "-c", f"{command} </dev/null >{quote(outputFile)} {errorRedirect} & echo $! >{quote(pidFile)}"], finished)


class SshxSession:
	STATE_STOPPED = 0
	STATE_STARTING = 1
	STATE_RUNNING = 2
	STATE_STOPPING = 3
	STATE_ERROR = 4

	def __init__(self):
		self.state = self.STATE_STOPPED
		self.url = None
		self.error = ""
		self.callbacks = []
		self.logPath = None
		self.session = None
		self.approvalPending = False
		self.question = ""
		self.askedUids = set()
		self.askedNames = []
		self.declinedUids = set()  # Not approved before anybody was, asked again on a new terminal.
		self.declinedRequests = set()
		self.declines = 0
		self.handoverApproved = 0
		self.idleWarned = False
		self.indicator = None
		self.ownScreens = set()
		self.stopTime = 0
		self.startTime = 0
		self.monitorTimer = eTimer()
		self.monitorTimer.callback.append(self.monitor)
		self.socket = None
		self.notifier = None

	def listen(self):  # remotesupport announces a session started while enigma2 runs and asks to end it.
		try:
			if exists(NOTIFY_SOCKET):  # Left by an enigma2 that did not end cleanly.
				remove(NOTIFY_SOCKET)
			self.socket = socket(AF_UNIX, SOCK_DGRAM)
			self.socket.setblocking(False)
			self.socket.bind(NOTIFY_SOCKET)
			chmod(NOTIFY_SOCKET, 0o600)
		except OSError as err:
			print(f"[{MODULE_NAME}] Error {err.errno}: Unable to listen on '{NOTIFY_SOCKET}'!  ({err.strerror})")
			return
		self.notifier = eSocketNotifier(self.socket.fileno(), POLLIN)
		self.notifier.callback.append(self.notified)

	def notified(self, what):
		while True:
			try:
				message = self.socket.recv(4096).decode("utf-8", "replace")
			except OSError:  # Nothing more to read.
				return
			command, separator, argument = message.partition(" ")
			if command == "handover" and not self.isActive() and exists(HANDOVER_FILE) and self.sshxPid():
				self.adopt(self.session)
			elif command == "stop" and self.state == self.STATE_RUNNING:
				self.stop(argument or "Session stopped on the command line")

	def isActive(self):
		return self.state in (self.STATE_STARTING, self.STATE_RUNNING, self.STATE_STOPPING)

	def isApproved(self):
		return bool(self.approvedUids())

	def approvedUids(self):
		return set(fileReadLines(APPROVED_FILE, default=[], source=MODULE_NAME)) - {""}

	def sshxPid(self):
		return runningPid(SSHX_PID_FILE, "sshx")

	def adopt(self, session):  # Takes over a session that survived a restart of enigma2 or was started on the command line.
		self.session = session
		if self.sshxPid():
			self.logPath = fileReadLine(LOG_PATH_FILE, default="", source=MODULE_NAME) or None
			self.url = fileReadLine(LINK_FILE, default="", source=MODULE_NAME) or None
			if not self.logPath:
				self.logPath = self.newLogPath()
				fileWriteLine(LOG_PATH_FILE, self.logPath, source=MODULE_NAME)
			if exists(HANDOVER_FILE):
				lines = fileReadLines(HANDOVER_FILE, default=[], source=MODULE_NAME) + ["", ""]
				origin = lines[0]
				if lines[1] == "approved":
					self.handoverApproved = time()
				remove(HANDOVER_FILE)
				self.logEvent(f"Session taken over from the {origin}" if origin else "Session taken over")
			else:
				self.logEvent("Session taken over after a restart of the GUI")
			try:  # New terminals wait for the approval of the participants in enigma2.
				prepareShell()
			except OSError as err:
				print(f"[{MODULE_NAME}] Error {err.errno}: Unable to prepare the support shell!  ({err.strerror})")
			if not exists(ACTIVITY_FILE):
				RemoteSupportTools.touchActivity()
			self.setState(self.STATE_RUNNING if self.url else self.STATE_STARTING)
			self.monitorTimer.start(1000)
			if self.url:
				self.startWatcher()
		elif exists(SESSION_DIR):
			self.logPath = fileReadLine(LOG_PATH_FILE, default="", source=MODULE_NAME) or None
			self.cleanup("it ended while the GUI was not running")

	def start(self):
		if self.isActive():
			return
		if incomplete():  # The screens say why and offer no start.
			return
		binary = sshxBinary()
		self.killStale()
		rmtree(SESSION_DIR, ignore_errors=True)
		self.logPath = self.newLogPath()
		try:
			makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
			prepareShell()
		except OSError as err:
			print(f"[{MODULE_NAME}] Error {err.errno}: Unable to prepare the support session!  ({err.strerror})")
			self.setState(self.STATE_ERROR, err.strerror)
			return
		fileWriteLine(LOG_PATH_FILE, self.logPath, source=MODULE_NAME)
		name = f"{BoxInfo.getItem('displaybrand')} {BoxInfo.getItem('displaymodel')} ({gethostname()})"
		self.logEvent(f"Remote support session started on {name}")
		self.url = None
		self.error = ""
		self.setState(self.STATE_STARTING)
		home = "/home/root" if exists("/home/root") else "/"
		startDetached(f"cd {quote(home)} && exec /usr/bin/python3 -c {quote(SIGINT_RESET_LAUNCHER)} {quote(binary)} --quiet --shell {quote(SHELL_WRAPPER)} --name {quote(name)}", SSHX_PID_FILE, SSHX_OUTPUT_FILE, SSHX_ERROR_FILE)
		self.startTime = time()
		self.monitorTimer.start(500)

	def newLogPath(self):
		logDir = config.crash.debug_path.value
		makedirs(logDir, mode=0o755, exist_ok=True)
		return join(logDir, f"{strftime('%Y%m%d_%H%M%S')}{SESSION_LOG_SUFFIX}")

	def stop(self, reason="Session stopped by the user"):
		if self.state in (self.STATE_STARTING, self.STATE_RUNNING):
			self.setState(self.STATE_STOPPING)
			self.logEvent(reason)
			hangupShells()
			pid = self.sshxPid()
			if pid:
				signalPid(pid, SIGINT)  # Lets sshx close the session on the server.
			self.stopTime = time()

	def monitor(self):
		pid = self.sshxPid()
		if self.state == self.STATE_STARTING:
			match = search(r"https?://\S+", "\n".join(fileReadLines(SSHX_OUTPUT_FILE, default=[], source=MODULE_NAME)))
			if match:
				self.url = match.group(0)
				fileWriteLine(LINK_FILE, self.url, source=MODULE_NAME)
				chmod(LINK_FILE, 0o600)
				self.logEvent(f"Session link: {self.url.split('#')[0]}")  # Without the encryption key.
				RemoteSupportTools.touchActivity()
				self.startWatcher()
				self.setState(self.STATE_RUNNING)
				self.monitorTimer.start(1000)
			elif not pid and time() - self.startTime > 3:  # The pid file is written by the detached shell.
				self.cleanup("unable to start sshx", error=True)
		elif self.state == self.STATE_RUNNING:
			if pid:
				self.checkParticipants()
				self.checkIdle()
				self.checkGrabbed()
				self.updateIndicator()
			else:
				self.cleanup("sshx exited unexpectedly", error=True)
		elif self.state == self.STATE_STOPPING:
			if not pid:
				self.cleanup()
			elif time() - self.stopTime > STOP_TIMEOUT:
				signalPid(pid, SIGTERM)  # sshx did not close the session in time.

	def cleanup(self, reason=None, error=False):
		self.monitorTimer.stop()
		for callback in (self.approvalCallback, self.idleCallback):  # Questions about the ended session.
			withdrawQuestion(callback)
		errors = [line.strip() for line in fileReadLines(SSHX_ERROR_FILE, default=[], source=MODULE_NAME) if line.strip()]
		self.stopWatcher()
		rmtree(SESSION_DIR, ignore_errors=True)
		if error and errors:
			reason = f"{reason} ({errors[-1]})"
		self.logEvent(f"{SESSION_ENDED}: {reason}" if reason else SESSION_ENDED)
		self.url = None
		self.approvalPending = False  # A late answer is ignored as the session is gone.
		self.askedUids = set()
		self.declinedUids = set()
		self.declinedRequests = set()
		self.declines = 0
		self.handoverApproved = 0
		self.idleWarned = False
		if error:
			self.setState(self.STATE_ERROR, errors[-1] if errors else reason)
		else:
			self.setState(self.STATE_STOPPED)

	def killStale(self):
		hangupShells()
		for pidFile, name in ((SSHX_PID_FILE, "sshx"), (WATCHER_PID_FILE, "RemoteSupport")):
			pid = runningPid(pidFile, name)
			if pid:
				signalPid(pid, SIGTERM)

	def startWatcher(self):
		if not modulesInstalled() or runningPid(WATCHER_PID_FILE, "RemoteSupport"):
			return
		name = f"{gethostname()} ({BoxInfo.getItem('imageversion')})"  # The image version helps the supporter.
		startDetached(f"exec /usr/bin/python3 {quote(RemoteSupportTools.__file__)} watcher {quote(name)}", WATCHER_PID_FILE, WATCHER_OUTPUT_FILE)

	def stopWatcher(self):
		pid = runningPid(WATCHER_PID_FILE, "RemoteSupport")
		if pid:
			signalPid(pid, SIGTERM)

	def checkParticipants(self):  # Everybody who joins has to be approved, meanwhile the session is read-only.
		if self.handoverApproved:  # The terminals were approved before the takeover, the participants there keep the access.
			connected = participants()
			if connected or time() - self.handoverApproved > HANDOVER_APPROVAL_WINDOW:
				self.handoverApproved = 0
				if connected:
					approvedUids = self.approvedUids() | {uid for uid, name, final in connected}
					with open(APPROVED_FILE, "w") as fd:
						fd.write("".join(f"{uid}\n" for uid in sorted(approvedUids)))
					self.logEvent(f"Access for {', '.join(name for uid, name, final in connected)} kept from before the takeover")
		approvedUids = currentApprovals()
		waiting = [(uid, name, final) for uid, name, final in participants() if uid not in approvedUids]
		if waiting and not exists(LOCK_FILE):
			fileWriteLine(LOCK_FILE, "1", source=MODULE_NAME)
		elif not waiting and exists(LOCK_FILE):
			remove(LOCK_FILE)
		waitingUids = {uid for uid, name, final in waiting}
		if self.approvalPending:
			if waitingUids == self.askedUids:
				return
			withdrawQuestion(self.approvalCallback)  # Somebody joined or left meanwhile.
			self.approvalPending = False
			self.setState(self.state)
		if not waiting or not all(final for uid, name, final in waiting):  # The browser sets the name a few seconds after joining.
			return
		requests = set(glob(join(SESSION_DIR, "term-*.request")))
		if not approvedUids and waitingUids <= self.declinedUids and not requests - self.declinedRequests:
			return
		self.askedUids = waitingUids
		self.askedNames = [name for uid, name, final in waiting]
		if len(waiting) == 1:
			question = _("'%s' joined the support session.") % waiting[0][1]
		else:
			question = _("New in the support session: %s") % ", ".join(self.askedNames)
		if approvedUids:
			question += "\n" + _("Until you answer, nobody can type in the terminals. Do you want to allow the access? If not, the session is ended for everybody.")
		else:
			question += "\n" + _("Do you want to allow the access? Then the supporter can open terminals on this receiver.")
		self.logEvent(f"Waiting for the approval of {', '.join(self.askedNames)}")
		self.approvalPending = True
		self.question = question
		AddModalNotification(text=question, timeout=APPROVAL_QUESTION_TIMEOUT, default=False, windowTitle=title(), callback=self.approvalCallback)
		self.setState(self.state)

	def approvalCallback(self, answer):
		self.answerRequest(answer, "on the receiver")

	def answerFromWeb(self, answer):
		if self.approvalPending:
			withdrawQuestion(self.approvalCallback)
			self.answerRequest(answer, "in the web interface")

	def answerRequest(self, answer, where):
		self.approvalPending = False
		if self.state != self.STATE_RUNNING:
			return
		names = ", ".join(self.askedNames)
		approvedUids = self.approvedUids()
		if answer:
			with open(APPROVED_FILE, "w") as fd:
				fd.write("".join(f"{uid}\n" for uid in sorted(approvedUids | self.askedUids)))
			RemoteSupportTools.touchActivity()
			self.logEvent(f"Access for {names} approved {where}")
			self.checkParticipants()
		elif approvedUids:  # sshx can not remove a single participant.
			self.stop(f"Session stopped as the access for {names} was not approved {where}")
		elif self.declines + 1 >= MAX_DECLINES:
			self.stop(f"Session stopped as the access for {names} was not approved {MAX_DECLINES} times, the last time {where}")
		else:
			self.declines += 1
			requests = glob(join(SESSION_DIR, "term-*.request"))
			for path in requests:
				fileWriteLine(f"{path[:-8]}.denied", "1", source=MODULE_NAME)
			self.declinedUids |= self.askedUids
			self.declinedRequests = set(requests)
			self.logEvent(f"Access for {names} not approved {where} ({self.declines} of {MAX_DECLINES}), asked again when a terminal is opened")
		self.setState(self.state)

	def checkGrabbed(self):  # The TV shows that the supporter took a grab.
		label = fileReadLine(GRABBED_FILE, default="", source=MODULE_NAME)
		if label:
			remove(GRABBED_FILE)
			notificationCenter.showInfo(_("The supporter took a screenshot."))

	def grabForWeb(self, osdOnly):  # Into the terminal used last, returns an error text.
		logs = [path for path in terminalLogs() if not exists(f"{path[:-4]}.request")]
		if self.state != self.STATE_RUNNING or not logs:
			return _("Open a terminal first, the screenshot is shown there.")
		target = max(logs, key=lambda path: stat(path).st_mtime)[:-4]
		startDetached(f"exec /usr/bin/python3 {quote(RemoteSupportTools.__file__)} grab --to {quote(target)}{' -o' if osdOnly else ''}", join(SESSION_DIR, "grab.pid"), "/dev/null")
		return ""

	def idleTime(self):
		try:
			return max(0, time() - stat(ACTIVITY_FILE).st_mtime)
		except OSError:
			return 0

	def idleLeft(self):
		return max(0, int(IDLE_TIMEOUT - self.idleTime()))

	def checkIdle(self):
		idle = self.idleTime()
		if idle >= IDLE_TIMEOUT:  # Also when the question is still queued behind other notifications.
			self.stop(f"Session stopped as nobody used it for {IDLE_TIMEOUT // 60} minutes")
		elif idle >= IDLE_TIMEOUT - IDLE_WARNING:
			if not self.idleWarned:
				self.idleWarned = True
				minutes = int(idle) // 60
				self.logEvent(f"Nobody used the session for {minutes} minutes, asking on the receiver whether to end it")
				fileWriteLine(CHAT_FILE, f"This support session ends in {IDLE_WARNING // 60} minutes as nobody uses it. Type in a terminal to keep it open.", source=MODULE_NAME)
				AddModalNotification(text=_("Nobody used the remote support session for %d minutes. Do you want to end it?") % minutes, timeout=IDLE_WARNING, default=True, windowTitle=title(), callback=self.idleCallback)
		elif self.idleWarned:  # Used again, the question is obsolete.
			self.idleWarned = False
			withdrawQuestion(self.idleCallback)

	def idleCallback(self, answer):
		if self.state != self.STATE_RUNNING:
			return
		if answer:
			self.stop(f"Session stopped as nobody used it for {int(self.idleTime()) // 60} minutes")
		else:
			RemoteSupportTools.touchActivity()
			self.idleWarned = False
			self.logEvent("Session kept open on the receiver")

	def logEvent(self, text):
		if self.logPath:
			try:
				with open(self.logPath, "a") as fd:
					fd.write(f"{strftime('%Y-%m-%d %H:%M:%S')} {text}\n")
			except OSError as err:
				print(f"[{MODULE_NAME}] Error {err.errno}: Unable to write session log '{self.logPath}'!  ({err.strerror})")

	def setState(self, state, error=None):
		self.state = state
		if error is not None:
			self.error = error
		self.updateIndicator()
		for callback in self.callbacks:
			callback()

	def updateIndicator(self):  # Like the mute symbol, but not over our screens, they show the state.
		visible = self.state in (self.STATE_STARTING, self.STATE_RUNNING) and not self.ownScreens
		if visible and self.indicator is None and self.session:
			self.indicator = self.session.instantiateDialog(RemoteSupportIndicator)
		if self.indicator:
			if visible:
				logs = terminalLogs()
				active = any(time() - stat(path).st_mtime < INDICATOR_ACTIVITY for path in logs)
				self.indicator.update(active, len(logs), len(participants()))
				self.indicator.show()
			else:
				self.indicator.hide()

	def ownScreen(self, screen, shown):
		if shown:
			self.ownScreens.add(id(screen))  # Screens are not hashable.
		else:
			self.ownScreens.discard(id(screen))
		self.updateIndicator()


sshxSession = SshxSession()


def hideIndicatorWith(screen):
	screen.onShow.append(lambda: sshxSession.ownScreen(screen, True))
	screen.onHide.append(lambda: sshxSession.ownScreen(screen, False))
	screen.onClose.append(lambda: sshxSession.ownScreen(screen, False))
	if screen.shown:  # Opened screens of other modules are already shown.
		sshxSession.ownScreen(screen, True)


class RemoteSupportIndicator(Screen):  # Shown like the mute symbol while a support session runs.
	skin = f"""
	<screen name="RemoteSupportIndicator" position="92,600" size="90,80" zPosition="10" backgroundColor="transparent" flags="wfNoBorder" resolution="1280,720">
		<widget name="icon" position="0,0" size="90,80" pixmaps="{resolveFilename(SCOPE_PLUGINS, 'SystemPlugins/RemoteSupport/indicator_passive.png')},{resolveFilename(SCOPE_PLUGINS, 'SystemPlugins/RemoteSupport/indicator_active.png')}" transparent="1" alphatest="blend" scale="1" />
		<widget name="users" position="9,27" size="18,24" font="Regular;15" horizontalAlignment="center" verticalAlignment="center" foregroundColor="#00101010" backgroundColor="#00808080" transparent="1" zPosition="1" />
		<widget name="usersActive" position="9,27" size="18,24" font="Regular;15" horizontalAlignment="center" verticalAlignment="center" foregroundColor="#00101010" backgroundColor="#0028be46" transparent="1" zPosition="1" />
		<widget name="terminals" position="63,27" size="18,24" font="Regular;15" horizontalAlignment="center" verticalAlignment="center" foregroundColor="#00101010" backgroundColor="#00808080" transparent="1" zPosition="1" />
		<widget name="terminalsActive" position="63,27" size="18,24" font="Regular;15" horizontalAlignment="center" verticalAlignment="center" foregroundColor="#00101010" backgroundColor="#0028be46" transparent="1" zPosition="1" />
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session)
		self["icon"] = MultiPixmap()  # Grey, green while a terminal is active.
		for name in ("terminals", "users"):  # A skin can color the numbers per state.
			self[name] = Label()
			self[f"{name}Active"] = Label()
		self.lastState = None  # Not "shown", Screen uses that name.

	def update(self, active, terminals, users):
		if (active, terminals, users) != self.lastState:
			self.lastState = (active, terminals, users)
			self["icon"].setPixmapNum(1 if active else 0)
			for name, count in (("terminals", terminals), ("users", users)):
				for widget, visible in ((name, not active), (f"{name}Active", active)):
					self[widget].setText(str(count))
					self[widget].setVisible(visible)


def colorKey(source, position, width, background=None):  # A color button of the skin, hidden without text.
	return f'\t<widget source="{source}" render="Label" position="{position}" size="{width},40" backgroundColor="{background or source}" conditional="{source}" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">\n\t\t<convert type="ConditionalShowHide" />\n\t</widget>'


def sessionGrabs(path):  # The grabs of a session are saved next to its log.
	return sorted(glob(f"{path[:-len(SESSION_LOG_SUFFIX)]}{GRAB_SUFFIX}*"))


def deleteSessionLogs(paths):  # The log of the running session is kept.
	for path in paths:
		if sshxSession.isActive() and path == sshxSession.logPath:
			continue
		for file in [path] + sessionGrabs(path):
			try:
				remove(file)
			except OSError as err:
				print(f"[{MODULE_NAME}] Error {err.errno}: Unable to delete '{file}'!  ({err.strerror})")


def sessionLogs():  # [(start time, last participants, path, running)], newest first.
	logs = []
	for path in sorted(glob(join(config.crash.debug_path.value, f"*{SESSION_LOG_SUFFIX}")), reverse=True):
		stamp = basename(path)[:-len(SESSION_LOG_SUFFIX)]
		try:
			stamp = strftime("%Y-%m-%d %H:%M:%S", strptime(stamp, "%Y%m%d_%H%M%S"))
		except ValueError:
			pass
		participants = [line.split(marker, 1)[1] for line in fileReadLines(path, default=[], source=MODULE_NAME) for marker in USERS if marker in line]
		logs.append((stamp, participants[-1] if participants else "", path, sshxSession.isActive() and path == sshxSession.logPath))
	return logs


def title():
	return _("Remote Support")


def sessionStart(reason, session=None, **kwargs):
	if session:
		sshxSession.adopt(session)
		sshxSession.listen()
		try:  # OpenWebif offers the pages of plugins in its menu, it starts after all other plugins.
			from Plugins.Extensions.WebInterface.WebChilds.Toplevel import addExternalChild
		except ImportError:
			return
		from .web import RemoteSupportWeb
		addExternalChild(("remotesupport", RemoteSupportWeb(), title(), "1", True, "_self"))  # Shown in the content area.


class QRCodeWidget(GUIComponent):
	GUI_WIDGET = eCanvas

	def __init__(self):
		GUIComponent.__init__(self)
		self.text = None

	def postWidgetCreate(self, instance):
		self.hide()

	def setText(self, text):
		if text != self.text:
			self.text = text
			self.draw()

	def draw(self):
		if self.instance is None:
			return
		if not self.text:
			self.hide()
			return
		from qrcode import QRCode, constants  # Not at module level as the package may be missing.
		qrCode = QRCode(error_correction=constants.ERROR_CORRECT_M, border=0)
		qrCode.add_data(self.text)
		qrCode.make(fit=True)
		matrix = qrCode.get_matrix()
		size = self.instance.size()
		self.instance.setSize(size)  # Allocates the canvas pixmap.
		width, height = size.width(), size.height()
		modules = len(matrix) + 8  # Quiet zone of 4 modules on each side.
		scale = min(width, height) // modules
		offsetX = (width - scale * len(matrix)) // 2
		offsetY = (height - scale * len(matrix)) // 2
		self.instance.fillRect(eRect(0, 0, width, height), gRGB(0x00FFFFFF))
		black = gRGB(0x00000000)
		for y, row in enumerate(matrix):
			x = 0
			while x < len(row):
				if row[x]:
					start = x
					while x < len(row) and row[x]:
						x += 1
					self.instance.fillRect(eRect(offsetX + start * scale, offsetY + y * scale, (x - start) * scale, scale), black)
				else:
					x += 1
		self.show()


def consoleFontSize(width, height, columns, lines):  # The largest monospaced font that fits the terminal into the area.
	return max(4, min(int(height / lines / LINE_HEIGHT_RATIO), int(width / columns / FONT_WIDTH_RATIO)))


class TerminalTiles(GUIComponent):  # The small terminals as one list, the selected one gets the backgroundColorSelected.
	GUI_WIDGET = eListbox

	def __init__(self):
		GUIComponent.__init__(self)
		self.l = eListboxPythonMultiContent()
		self.headerFont = gFont("Regular", 16)
		self.margin = 3  # Transparent around the frame, also the width of the frame.
		self.headerColor = 0x00FFC000
		self.textColor = 0x00FFFFFF
		self.frameColor = 0x00606060
		self.activeColor = 0x00FFFFFF
		self.selectionColor = 0x00FFC000
		self.tileColor = 0x00000000
		self.fontSize = None
		self.tiles = None
		self.width = None

	def applySkin(self, desktop, parent):
		attributes = []
		for attribute, value in self.skinAttributes or []:
			if attribute == "headerFont":
				self.headerFont = parseFont(value, parent.scale)
			elif attribute == "fieldMargins":
				self.margin = int(int(value) * parent.scale[1][0] / parent.scale[1][1])
			elif attribute in ("headerColor", "frameColor", "activeColor", "tileColor"):
				setattr(self, attribute, parseColor(value).argb())
			else:
				if attribute == "foregroundColor":
					self.textColor = parseColor(value).argb()
				elif attribute == "backgroundColorSelected":
					self.selectionColor = parseColor(value).argb()
				attributes.append((attribute, value))
		self.skinAttributes = attributes
		result = GUIComponent.applySkin(self, desktop, parent)
		self.l.setFont(0, self.headerFont)
		return result

	def postWidgetCreate(self, instance):
		instance.setContent(self.l)
		instance.allowNativeKeys(False)  # The screen moves the selection.

	def preWidgetRemove(self, instance):
		instance.setContent(None)

	def setTiles(self, tiles):  # [(header, pyte screen, shown large)]
		size = self.l.getItemSize()
		margin = self.margin
		headerHeight = self.headerFont.pointSize * 5 // 4
		width = size.width() - margin * 6
		height = size.height() - margin * 5 - headerHeight
		if tiles:
			fontSize = min(consoleFontSize(width, height, screen.columns, screen.lines) for header, screen, active in tiles)
			if fontSize != self.fontSize:
				self.fontSize = fontSize
				self.l.setFont(1, gFont("Console", fontSize))
				self.tiles = None
		tiles = [(header, "\n".join(line.rstrip() for line in screen.display), active) for header, screen, active in tiles]
		if (size.width(), tiles) != (self.width, self.tiles):  # The item gets narrower when the scrollbar appears.
			self.width = size.width()
			self.tiles = tiles
			self.l.setList([[
				header,  # Entries starting with None are not selectable.
				MultiContentEntryRectangle(pos=(margin, margin), size=(size.width() - margin * 2, size.height() - margin * 2), backgroundColor=self.activeColor if active else self.frameColor, backgroundColorSelected=self.selectionColor),
				MultiContentEntryRectangle(pos=(margin * 2, margin * 2), size=(size.width() - margin * 4, size.height() - margin * 4), backgroundColor=self.tileColor, backgroundColorSelected=self.tileColor),
				MultiContentEntryText(pos=(margin * 3, margin * 2), size=(width, headerHeight), font=0, flags=RT_HALIGN_LEFT | RT_VALIGN_CENTER, text=header, color=self.headerColor, color_sel=self.headerColor, backcolor=self.tileColor, backcolor_sel=self.tileColor),
				MultiContentEntryText(pos=(margin * 3, margin * 2 + headerHeight), size=(width, height), font=1, flags=RT_HALIGN_LEFT | RT_VALIGN_TOP, text=text, color=self.textColor, color_sel=self.textColor, backcolor=self.tileColor, backcolor_sel=self.tileColor)
			] for header, text, active in tiles])

	def setSelection(self, index, enabled):
		if self.instance:
			self.instance.setSelectionEnable(enabled)
			# The listbox keeps the row of the selection it had at the last paint, so there is one move per call.
			current = self.instance.getCurrentIndex()
			top = self.instance.getTopIndex()
			rows = max(1, self.instance.size().height() // max(1, self.l.getItemSize().height()))
			maxTop = max(0, len(self.tiles or ()) - rows)
			if index == current and top <= maxTop:
				return
			if abs(index - current) == 1:  # Like a key press.
				self.instance.moveSelection(self.instance.moveDown if index > current else self.instance.moveUp)
			elif index < rows:  # Shows the first tiles.
				self.instance.moveSelectionTo(index)
			elif top > maxTop or index - (current - top) > maxTop:  # Empty rows below, also after a new list, the next call jumps from the end.
				self.instance.moveSelection(self.instance.moveBottom)
			else:
				self.instance.moveSelectionTo(index)


class RemoteSupportManager(Screen):
	skin = """
	<screen name="RemoteSupportManager" title="Remote Support" position="center,center" size="1100,560" resolution="1280,720">
		<widget name="status" position="10,10" size="690,35" font="Regular;28" />
		<widget name="description" position="10,55" size="690,300" font="Regular;22" />
		<widget name="counts" position="10,280" size="690,50" font="Regular;20" foregroundColor="#00ffc000" />
		<widget name="url" position="10,365" size="690,60" font="Regular;22" foregroundColor="#00ffc000" />
		<widget name="linkwarning" position="10,425" size="690,90" font="Regular;20" foregroundColor="#00ff6060" />
		<widget name="qrcode" position="720,10" size="370,370" />
		<widget name="qrhint" position="720,385" size="370,52" font="Regular;20" horizontalAlignment="center" verticalAlignment="top" />
		<widget source="key_red" render="Label" position="0,e-40" size="180,40" backgroundColor="key_red" conditional="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_green" render="Label" position="190,e-40" size="180,40" backgroundColor="key_green" conditional="key_green" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_yellow" render="Label" position="380,e-40" size="180,40" backgroundColor="key_yellow" conditional="key_yellow" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_blue" render="Label" position="570,e-40" size="180,40" backgroundColor="key_blue" conditional="key_blue" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-80,e-40" size="80,40" backgroundColor="key_back" conditional="key_help" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session, enableHelp=True)
		self.setTitle(title())
		actions = _("Remote Support Actions")
		closeHelp = _("Close, the session continues")
		self["status"] = Label()
		self["description"] = Label()
		self["counts"] = Label()
		self["url"] = Label()
		self["linkwarning"] = Label()
		self["qrcode"] = QRCodeWidget()
		self["qrhint"] = Label()
		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText()
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText(_("Session Logs"))
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions"], {
			"cancel": (self.close, closeHelp),
			"close": (self.keyCloseRecursive, _("Exit all menus, the session continues")),
			"red": (self.close, closeHelp),
			"blue": (self.keyBlue, _("Show the logs of previous support sessions"))
		}, prio=0, description=actions)
		self["sessionActions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions"], {
			"ok": (self.keyGreen, _("Start or stop the support session")),
			"green": (self.keyGreen, _("Start or stop the support session"))
		}, prio=0, description=actions)
		self["watchActions"] = HelpableActionMap(self, ["ColorActions"], {
			"yellow": (self.keyYellow, _("Watch the support session on the TV"))
		}, prio=0, description=actions)
		self.onLayoutFinish.append(self.updateState)
		hideIndicatorWith(self)
		sshxSession.callbacks.append(self.updateState)
		self.countsTimer = eTimer()  # Terminals open and close without a state change.
		self.countsTimer.callback.append(self.updateCounts)
		self.countsTimer.start(1000)
		self.onLayoutFinish.append(self.updateCounts)
		self.onClose.append(self.cleanup)

	def cleanup(self):
		self.countsTimer.stop()
		if self.updateState in sshxSession.callbacks:
			sshxSession.callbacks.remove(self.updateState)

	def updateCounts(self):
		text = ""
		if sshxSession.state == SshxSession.STATE_RUNNING:
			names = [name for uid, name, final in participants()]
			terminals = len(terminalLogs())
			text = ngettext("%d user connected", "%d users connected", len(names)) % len(names)
			if names:
				text = f"{text} ({', '.join(names)})"
			text += "\n" + ngettext("%d terminal open", "%d terminals open", terminals) % terminals
		if self["counts"].getText() != text:
			self["counts"].setText(text)

	def updateState(self):
		state = sshxSession.state
		url = sshxSession.url if state == SshxSession.STATE_RUNNING else None
		if not sshxSession.isActive() and incomplete():
			status = _("Remote support is not available")
			description = _("A package the plugin needs is missing (sshx or a Python module). Please reinstall the Remote Support plugin.")
			green = ""
		elif state == SshxSession.STATE_STARTING:
			status = _("Starting support session...")
			description = _("Connecting to the sshx server, please wait.")
			green = _("Stop")
		elif state == SshxSession.STATE_RUNNING:
			if sshxSession.isApproved():
				status = _("Support session is running, access approved")
				access = _("Approved users can open terminals. Everybody who joins later has to be approved as well.")
			else:
				status = _("Support session is running")
				access = _("When somebody joins the session, you have to approve the access with the remote control or in OpenWebif.")
			keepRunning = _("The session keeps running when you close this screen. Press YELLOW to watch what the supporter is doing and GREEN to end the session.")
			idle = _("When nobody uses it for %d minutes, you are asked whether to end it.") % ((IDLE_TIMEOUT - IDLE_WARNING) // 60)
			description = _("Scan the QR code with your phone and send the link to your supporter from there.") + f" {access}\n\n{keepRunning} {idle}"
			green = _("Stop")
		elif state == SshxSession.STATE_STOPPING:
			status = _("Stopping support session...")
			description = ""
			green = ""
		else:
			status = _("No support session active")
			description = _("Press GREEN to start a support session. You will get a link and a QR code for your supporter, who then gets a terminal on this receiver in their web browser.")
			if state == SshxSession.STATE_ERROR and sshxSession.error:
				description += "\n\n" + _("Last error:") + f" {sshxSession.error}"
			green = _("Start")
		self["status"].setText(status)
		self["description"].setText(description)
		self["url"].setText(url or "")
		self["linkwarning"].setText(_("Do not post the link or a screenshot of it in public forums: everybody who has it can try to join and sees the terminals until you deny the access.") if url else "")
		self["qrhint"].setText(_("Scan with your phone to send the link to your supporter") if url else "")
		self["qrcode"].setText(shareUrl(url) if url else "")
		self["key_green"].setText(green)
		self["sessionActions"].setEnabled(green != "")
		self["key_yellow"].setText(_("Watch Session") if url else "")
		self["watchActions"].setEnabled(url is not None)

	def keyCloseRecursive(self):
		self.close(True)

	def keyGreen(self):
		warning = _("After you approved the access on the TV, the supporter has full root access to your receiver as long as the session is running. Only share the link with people you trust!")
		if sshxSession.state in (SshxSession.STATE_STARTING, SshxSession.STATE_RUNNING):
			self.session.openWithCallback(self.stopCallback, MessageBox, _("Do you really want to end the support session?"), default=True)
		elif not sshxSession.isActive() and not incomplete():
			self.session.openWithCallback(self.startCallback, MessageBox, f"{warning}\n\n" + _("Do you want to start a support session?"), default=False)

	def startCallback(self, answer):
		if answer:
			sshxSession.start()

	def stopCallback(self, answer):
		if answer:
			sshxSession.stop()

	def keyYellow(self):
		if sshxSession.state == SshxSession.STATE_RUNNING:
			self.session.open(RemoteSupportViewer)

	def keyBlue(self):
		self.session.openWithCallback(lambda recursive=False: recursive and self.close(True), RemoteSupportLogs)


class RemoteSupportLogs(Screen):
	skin = """
	<screen name="RemoteSupportLogs" title="Session Logs" position="center,center" size="900,560" resolution="1280,720">
		<widget name="list" position="10,10" size="880,450" font="Regular;22" itemHeight="30" scrollbarMode="showOnDemand" />
		<widget source="key_red" render="Label" position="0,e-40" size="180,40" backgroundColor="key_red" conditional="key_red" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_green" render="Label" position="190,e-40" size="180,40" backgroundColor="key_green" conditional="key_green" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_yellow" render="Label" position="380,e-40" size="180,40" backgroundColor="key_yellow" conditional="key_yellow" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_blue" render="Label" position="570,e-40" size="180,40" backgroundColor="key_blue" conditional="key_blue" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
		<widget source="key_help" render="Label" position="e-80,e-40" size="80,40" backgroundColor="key_back" conditional="key_help" font="Regular;20" foregroundColor="key_text" horizontalAlignment="center" verticalAlignment="center">
			<convert type="ConditionalShowHide" />
		</widget>
	</screen>"""

	def __init__(self, session):
		Screen.__init__(self, session, enableHelp=True)
		self.setTitle(_("Session Logs"))
		actions = _("Session Log Actions")
		self["list"] = MenuList([])
		self["key_red"] = StaticText()
		self["key_green"] = StaticText()
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText()
		self["actions"] = HelpableActionMap(self, ["OkCancelActions"], {
			"cancel": (self.close, _("Close the session logs")),
			"close": (self.keyCloseRecursive, _("Close and exit all menus"))
		}, prio=0, description=actions)
		self["showActions"] = HelpableActionMap(self, ["OkCancelActions", "ColorActions"], {
			"ok": (self.keyShow, _("Show the selected session log")),
			"green": (self.keyShow, _("Show the selected session log"))
		}, prio=0, description=actions)
		self["deleteActions"] = HelpableActionMap(self, ["ColorActions"], {
			"red": (self.keyDelete, _("Delete the selected session log"))
		}, prio=0, description=actions)
		self["deleteAllActions"] = HelpableActionMap(self, ["ColorActions"], {
			"blue": (self.keyDeleteAll, _("Delete all finished session logs"))
		}, prio=0, description=actions)
		self["screenshotActions"] = HelpableActionMap(self, ["ColorActions"], {
			"yellow": (self.keyScreenshots, _("Show the screenshots of the session"))
		}, prio=0, description=actions)
		self["list"].onSelectionChanged.append(self.updateButtons)
		self.onLayoutFinish.append(self.loadLogs)
		hideIndicatorWith(self)

	def loadLogs(self, selectedPath=None):
		logs = []
		self.names = {}  # For the questions, without the additions of the list.
		for stamp, users, path, running in sessionLogs():
			text = f"{stamp} ({users})" if users else stamp
			self.names[path] = text
			grabs = len(sessionGrabs(path))
			if grabs:
				text += " - " + ngettext("%d screenshot", "%d screenshots", grabs) % grabs
			logs.append((f"{text} - " + _("running") if running else text, path))
		self["list"].setList(logs)
		paths = [path for text, path in logs]
		if selectedPath in paths:
			self["list"].setCurrentIndex(paths.index(selectedPath))
		self.updateButtons()

	def deletablePaths(self):  # The log of a running session is kept.
		return [path for text, path in self["list"].getList() if not (sshxSession.isActive() and path == sshxSession.logPath)]

	def updateButtons(self):
		current = self["list"].getCurrent()
		deletable = self.deletablePaths()
		self["key_green"].setText(_("Show") if current else "")
		self["showActions"].setEnabled(current is not None)
		self["key_red"].setText(_("Delete") if current and current[1] in deletable else "")
		self["deleteActions"].setEnabled(current is not None and current[1] in deletable)
		self["key_blue"].setText(_("Delete All") if deletable else "")
		self["deleteAllActions"].setEnabled(bool(deletable))
		screenshots = bool(current and sessionGrabs(current[1]) and PictureViewer)
		self["key_yellow"].setText(_("Screenshots") if screenshots else "")
		self["screenshotActions"].setEnabled(screenshots)

	def keyCloseRecursive(self):
		self.close(True)

	def keyShow(self):
		current = self["list"].getCurrent()
		if current:
			hideIndicatorWith(self.session.openWithCallback(lambda recursive=False: self.close(True) if recursive else self.loadLogs(current[1]), RemoteSupportLog, title=_("Session Log") + f" {current[0]}", skinName="RemoteSupportLog", logPath=current[1], tailLog=False))

	def keyScreenshots(self):  # The picture player of the image, LEFT/RIGHT browse, INFO shows the details.
		current = self["list"].getCurrent()
		if current and PictureViewer:
			grabs = sessionGrabs(current[1])
			if grabs:
				hideIndicatorWith(self.session.open(PictureViewer, [((path, False), None) for path in grabs], 0, dirname(grabs[0])))

	def keyDelete(self):
		current = self["list"].getCurrent()
		if current:
			name = self.names.get(current[1], current[0])
			grabs = len(sessionGrabs(current[1]))
			if grabs == 1:
				question = _("Do you really want to delete the session log '%s' and its screenshot?") % name
			elif grabs:
				question = _("Do you really want to delete the session log '%s' and its %d screenshots?") % (name, grabs)
			else:
				question = _("Do you really want to delete the session log '%s'?") % name
			self.session.openWithCallback(lambda answer: answer and self.deleteLogs([current[1]]), MessageBox, question, default=False)

	def keyDeleteAll(self):
		deletable = self.deletablePaths()
		grabs = sum(len(sessionGrabs(path)) for path in deletable)
		question = _("Do you really want to delete all %d session logs?") % len(deletable)
		if grabs == 1:
			question += "\n" + _("Their screenshot is deleted as well.")
		elif grabs:
			question += "\n" + _("Their %d screenshots are deleted as well.") % grabs
		self.session.openWithCallback(lambda answer: answer and self.deleteLogs(deletable), MessageBox, question, default=False)

	def deleteLogs(self, paths):
		deleteSessionLogs(paths)
		self.loadLogs()


class RemoteSupportLog(NetworkLogScreen):  # Only adds a fallback skin as the default skin has none for NetworkLogScreen.
	skin = """
	<screen name="RemoteSupportLog" position="center,center" size="1200,640" resolution="1280,720">
		<widget name="infotext" position="10,10" size="1180,620" font="Console;18" />
	</screen>"""


class RemoteTerminal:
	def __init__(self, base):
		self.base = base
		self.offset = 0
		self.lastActivity = 0
		self.paused = False  # Output is kept back while the view is scrolled back.
		self.pending = b""
		from pyte import HistoryScreen, Stream  # Not at module level as the package may be missing.

		class TerminalScreen(HistoryScreen):
			def set_margins(self, *args, **kwargs):  # pyte 0.8.2 also calls it for CSI ? r (restore private modes), which has no margins.
				if not kwargs.get("private"):
					HistoryScreen.set_margins(self, *args)

		self.screen = TerminalScreen(80, 24, history=1000, ratio=0.5)
		self.stream = Stream(self.screen)
		self.stream.use_utf8 = False  # pyte ignores the switch to the line drawing characters in UTF-8 mode, which mc uses for its frames.
		self.decoder = getincrementaldecoder("utf-8")(errors="replace")  # So the UTF-8 is decoded here.

	def update(self):
		size = fileReadLine(f"{self.base}.size", default="", source=MODULE_NAME).split()
		if len(size) == 2 and size[0].isdigit() and size[1].isdigit():
			cols, rows = int(size[0]), int(size[1])
			if (cols, rows) != (self.screen.columns, self.screen.lines):
				self.screen.resize(rows, cols)
		try:
			status = stat(f"{self.base}.log")
			length = status.st_size
			if length < self.offset:  # The log was truncated.
				self.offset = 0
				self.screen.reset()
				self.decoder.reset()
			if length == self.offset:
				return False
			with open(f"{self.base}.log", "rb") as fd:
				fd.seek(self.offset)
				data = fd.read(length - self.offset)
		except OSError:
			return False
		self.offset += len(data)
		self.lastActivity = status.st_mtime  # Also right for output written before the view was opened.
		if self.paused:
			self.pending += data
		else:
			self.feed(data)
		return True

	def feed(self, data):  # Output pyte can not handle must not end enigma2, the view only misses it.
		try:
			self.stream.feed(self.decoder.decode(data))
		except Exception as err:
			print(f"[{MODULE_NAME}] Error: Unable to show the output of terminal {basename(self.base)}!  ({type(err).__name__}: {err})")

	def scrolledBack(self):
		return len(self.screen.history.bottom)

	def scroll(self, up):
		if up:
			self.paused = True
			self.screen.prev_page()
		elif self.scrolledBack():
			self.screen.next_page()

	def resume(self):
		while self.scrolledBack():
			self.screen.next_page()
		self.paused = False
		if self.pending:
			self.feed(self.pending)
			self.pending = b""


def viewerSkin():
	lines = [
		'<screen name="RemoteSupportViewer" title="Support Session" position="0,0" size="1280,720" resolution="1280,720" backgroundColor="#10000000" flags="wfNoBorder">',
		'\t<widget source="Title" render="Label" position="20,5" size="660,35" font="Regular;28" foregroundColor="#00ffffff" backgroundColor="#10000000" />',
		'\t<widget name="header" position="20,42" size="540,28" font="Regular;22" foregroundColor="#00ffc000" backgroundColor="#10000000" />',
		'\t<widget name="connected" position="570,42" size="380,28" font="Regular;22" horizontalAlignment="right" foregroundColor="#00ffffff" backgroundColor="#10000000" />',
		'\t<widget name="largeFocus" position="15,70" size="940,596" backgroundColor="#00ffc000" zPosition="1" />',
		'\t<eLabel position="17,72" size="936,592" backgroundColor="#00606060" zPosition="0" />',
		'\t<widget name="terminal" position="20,75" size="930,586" font="Console;18" noWrap="1" padding="10" backgroundColor="#00000000" zPosition="3" />',
		'\t<widget name="tiles" position="970,70" size="295,596" itemHeight="149" fieldMargins="2" headerFont="Regular;16" headerColor="#00ffc000" frameColor="#00606060" activeColor="#00ffffff" tileColor="#00000000" foregroundColor="#00ffffff" backgroundColor="#10000000" backgroundColorSelected="#00ffc000" scrollbarMode="showOnDemand" scrollbarScroll="byLine" scrollbarOffset="10" transparent="1" />',
	]
	lines += [
		colorKey("key_red", "20,e-45", 180),
		colorKey("key_green", "210,e-45", 180),
		colorKey("key_yellow", "400,e-45", 180),
		colorKey("key_blue", "590,e-45", 180),
		colorKey("key_help", "e-100,e-45", 80, "key_back"),
		'</screen>',
	]
	return "\n".join(lines)


class RemoteSupportViewer(Screen):
	skin = viewerSkin()

	def __init__(self, session):
		Screen.__init__(self, session, enableHelp=True)
		self.setTitle(_("Support Session"))
		actions = _("Support Session Actions")
		closeHelp = _("Close, the session continues")
		self["header"] = Label()
		self["connected"] = Label()
		self["terminal"] = Label()
		self["largeFocus"] = Label()
		self["tiles"] = TerminalTiles()
		self["key_red"] = StaticText(_("Close"))
		self["key_green"] = StaticText()
		self["key_yellow"] = StaticText()
		self["key_blue"] = StaticText()
		self["actions"] = HelpableActionMap(self, ["OkCancelActions", "NavigationActions", "ColorActions"], {
			"cancel": (self.close, closeHelp),
			"close": (self.close, closeHelp),
			"red": (self.close, closeHelp),
			"ok": (self.keyShowLarge, _("Show the terminal large / back")),
			"up": (self.keyUp, _("Previous terminal / scroll back")),
			"down": (self.keyDown, _("Next terminal / scroll forward")),
			"left": (self.keyLeft, _("Scroll in the large terminal")),
			"right": (self.keyRight, _("Move back to the terminal list"))
		}, prio=0, description=actions)
		self["closeActions"] = HelpableActionMap(self, ["ColorActions"], {
			"green": (self.keyCloseTerminal, _("Close the large terminal"))
		}, prio=0, description=actions)
		self["automaticActions"] = HelpableActionMap(self, ["ColorActions"], {
			"yellow": (self.keyAutomatic, _("Show the most active terminal large"))
		}, prio=0, description=actions)
		self["newActions"] = HelpableActionMap(self, ["ColorActions"], {
			"blue": (self.keyNewTerminal, _("Open a new terminal for the supporter"))
		}, prio=0, description=actions)
		self.terminals = {}
		self.pinned = None  # Terminal chosen for the large view, None follows the activity.
		self.previous = None  # Terminal shown large before the pinned one, OK on the pinned one returns to it.
		self.selected = None
		self.focusLarge = True  # The large view has the focus, UP/DOWN scroll it.
		self.frozen = None  # Terminal kept in the large view while it is scrolled back.
		self.fontSizes = {}
		self.texts = {}
		self.timer = eTimer()
		self.timer.callback.append(self.poll)
		self.onLayoutFinish.append(self.poll)
		hideIndicatorWith(self)
		self.onClose.append(self.timer.stop)
		sshxSession.callbacks.append(self.sessionChanged)
		self.onClose.append(lambda: sshxSession.callbacks.remove(self.sessionChanged))

	def sessionChanged(self):
		if sshxSession.state != SshxSession.STATE_RUNNING:
			self.close()

	def poll(self):
		bases = {path[:-4] for path in terminalLogs()}
		for base in self.terminals.keys() - bases:
			del self.terminals[base]
		for base in bases:
			if base not in self.terminals:
				self.terminals[base] = RemoteTerminal(base)
		for terminal in self.terminals.values():
			terminal.update()
		if self.pinned not in self.terminals:
			self.pinned = None
		if self.frozen not in self.terminals:
			self.frozen = None
		if self.selected not in self.terminals:
			self.selected = self.largeTerminal()
		self.render()
		self.timer.start(250, True)

	def orderedTerminals(self):
		return sorted(self.terminals, key=lambda base: int(basename(base)[5:]))

	def largeTerminal(self):
		if self.frozen:
			return self.frozen
		if self.pinned:
			return self.pinned
		return max(self.terminals, key=lambda base: self.terminals[base].lastActivity) if self.terminals else None

	def render(self):
		order = self.orderedTerminals()
		large = self.largeTerminal()
		if large is None:
			self.setWidget("header", _("Waiting for the supporter to open a terminal..."))
			self.setWidget("terminal", "")
		else:
			screen = self.terminals[large].screen
			mode = _("pinned") if self.pinned else _("automatic")
			scrolled = self.terminals[large].scrolledBack()
			if scrolled:
				mode += " - " + _("scrolled back %d lines") % scrolled
			self.setWidget("header", _("Terminal %d (%dx%d) - %s") % (order.index(large) + 1, screen.columns, screen.lines, mode))
			self.showTerminal("terminal", self.terminals[large])
		tiles = []
		for position, base in enumerate(order):
			screen = self.terminals[base].screen
			tiles.append((_("Terminal %d (%dx%d)") % (position + 1, screen.columns, screen.lines), screen, base == large))
		self["tiles"].setTiles(tiles)
		self["tiles"].setSelection(order.index(self.selected) if self.selected in order else 0, not self.focusLarge)
		connected = [name for uid, name, final in participants()]
		self.setWidget("connected", _("Connected: %s") % ", ".join(connected) if connected else "")
		self["largeFocus"].setVisible(self.focusLarge and large is not None)
		self["key_green"].setText(_("Close Terminal") if large else "")
		self["closeActions"].setEnabled(large is not None)
		self["key_yellow"].setText(_("Automatic") if self.pinned else "")
		self["automaticActions"].setEnabled(self.pinned is not None)
		canCreate = sshxSession.isApproved() and not exists(LOCK_FILE) and not exists(CREATE_FILE)  # New shells wait while somebody is not approved.
		self["key_blue"].setText(_("New Terminal") if canCreate else "")
		self["newActions"].setEnabled(canCreate)

	def setWidget(self, name, text):
		if self.texts.get(name) != text:
			self.texts[name] = text
			self[name].setText(text)

	def showTerminal(self, name, terminal):
		screen = terminal.screen
		size = self[name].instance.size()
		padding = self[name].instance.getPadding()  # left, top, right and bottom as an eRect.
		width = size.width() - padding.left() - padding.width()
		height = size.height() - padding.top() - padding.height()
		fontSize = consoleFontSize(width, height, screen.columns, screen.lines)
		if self.fontSizes.get(name) != fontSize:
			self.fontSizes[name] = fontSize
			self[name].instance.setFont(gFont("Console", fontSize))
		self.setWidget(name, "\n".join(line.rstrip() for line in screen.display))

	def moveSelection(self, step):
		order = self.orderedTerminals()
		if order:
			index = order.index(self.selected) if self.selected in order else 0
			self.selected = order[(index + step) % len(order)]
			self.render()

	def unfreeze(self):
		if self.frozen in self.terminals:
			self.terminals[self.frozen].resume()
		self.frozen = None

	def keyUp(self):
		large = self.largeTerminal()
		if self.focusLarge and large:
			self.frozen = large
			self.terminals[large].scroll(up=True)
			self.render()
		elif not self.focusLarge:
			self.moveSelection(-1)

	def keyDown(self):
		large = self.largeTerminal()
		if self.focusLarge and large:
			self.terminals[large].scroll(up=False)
			if not self.terminals[large].scrolledBack():
				self.unfreeze()
			self.render()
		elif not self.focusLarge:
			self.moveSelection(1)

	def keyLeft(self):
		self.focusLarge = True
		self.render()

	def keyRight(self):
		self.unfreeze()
		self.focusLarge = False
		self.render()

	def keyShowLarge(self):  # The terminal gets the focus, OK again switches to the previous one.
		large = self.largeTerminal()
		target = self.previous if self.focusLarge else self.selected
		if target in self.terminals and target != large:
			self.unfreeze()
			self.previous = large
			self.pinned = target
		elif large is None:
			return
		else:
			target = large
		self.selected = target
		self.focusLarge = True
		self.render()

	def keyCloseTerminal(self):
		large = self.largeTerminal()
		if large:
			number = self.orderedTerminals().index(large) + 1
			self.session.openWithCallback(lambda answer: answer and self.closeTerminal(large), MessageBox, _("Do you want to close terminal %d? The supporter loses it together with everything running in it.") % number, default=False)

	def closeTerminal(self, base):
		if base in self.terminals:
			sshxSession.logEvent(f"Terminal T{basename(base)[5:]} closed on the receiver")
			signalPid(int(basename(base)[5:]), SIGHUP)  # The wrapper ends the shell and sshx closes the terminal.
			del self.terminals[base]
		self.keyAutomatic()

	def keyNewTerminal(self):
		fileWriteLine(CREATE_FILE, "1", source=MODULE_NAME)
		sshxSession.logEvent("Terminal opened on the receiver")
		self.unfreeze()
		self.pinned = None  # The new terminal shows its prompt, so the automatic mode shows it.
		self.focusLarge = True
		self.render()

	def keyAutomatic(self):
		self.unfreeze()
		self.pinned = None
		self.focusLarge = True
		self.render()


def openRemoteSupport(session, **kwargs):
	session.open(RemoteSupportManager)


def Plugins(**kwargs):
	return [
		PluginDescriptor(where=PluginDescriptor.WHERE_SESSIONSTART, fnc=sessionStart),
		PluginDescriptor(name=title(), description=_("Share a remote terminal session with a supporter."), where=PluginDescriptor.WHERE_PLUGINMENU, icon="plugin-fhd.png" if getDesktop(0).size().width() >= 1920 else "plugin.png", fnc=openRemoteSupport)
	]
