# The remote support page in OpenWebif. It controls the same session as the screen on the TV.

from json import dumps
from os.path import basename

from twisted.web import resource

from . import _
from .plugin import IDLE_WARNING, SshxSession, deleteSessionLogs, incomplete, participants, sessionGrabs, sessionLogs, sshxSession

STATES = {
	SshxSession.STATE_STOPPED: "stopped",
	SshxSession.STATE_STARTING: "starting",
	SshxSession.STATE_RUNNING: "running",
	SshxSession.STATE_STOPPING: "stopping",
	SshxSession.STATE_ERROR: "error"
}

FRAGMENT = """<div id="remotesupport" class="col-xs-12">
<style>
#remotesupport { --rs-muted: #888; --rs-border: rgba(128, 128, 128, .4); }
#remotesupport .rs-head { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
#remotesupport .rs-head h2 { margin: 0; }
#remotesupport .rs-status { flex: 1; color: var(--rs-muted); }
:where(#remotesupport) button { font: inherit; padding: 6px 16px; border: 1px solid var(--rs-border); border-radius: 4px; cursor: pointer; }
#remotesupport .rs-question { display: none; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; padding: 10px 12px; border-radius: 4px; background: #ffc000; color: #000; }
#remotesupport .rs-question span { flex: 1; min-width: 200px; }
#remotesupport .rs-main { display: flex; gap: 16px; }
#remotesupport .rs-side { flex: 0 0 240px; }
#remotesupport .rs-side > div { margin-bottom: 14px; }
#remotesupport .rs-label { color: var(--rs-muted); font-size: 12px; }
#remotesupport .rs-link-warning { margin-top: 6px; color: #c62828; font-size: 13px; }
#remotesupport .rs-link { word-break: break-all; }
#remotesupport .rs-qr svg { width: 100%; height: auto; display: block; }
#remotesupport .rs-idle { color: #c62828; }
#remotesupport .rs-info { white-space: pre-line; max-width: 720px; }
#remotesupport iframe { flex: 1; min-width: 0; height: calc(100vh - 280px); min-height: 420px; border: 1px solid var(--rs-border); border-radius: 4px; background: #000; }
#remotesupport .rs-logs { margin-top: 20px; }
#remotesupport .rs-logs table { border-collapse: collapse; width: 100%; }
#remotesupport .rs-logs td:first-child, #remotesupport .rs-logs td:nth-last-child(-n+2) { white-space: nowrap; }
#remotesupport .rs-delete-all { margin-top: 10px; }
#remotesupport .rs-logs td { padding: 4px 12px 4px 0; border-bottom: 1px solid var(--rs-border); }
#remotesupport .rs-open { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; min-height: 240px; padding: 24px; border: 1px solid var(--rs-border); border-radius: 4px; text-align: center; }
.rs-viewer img { display: block; background: #000; max-width: 100%; max-height: calc(100vh - 220px); margin: 0 auto; }
.rs-viewer-bar { display: flex; align-items: center; gap: 12px; margin-top: 10px; }
.rs-viewer-bar span { flex: 1; text-align: center; }
.rs-log-text { max-height: calc(100vh - 220px); min-height: 200px; overflow: auto; margin: 0; white-space: pre-wrap; font: 12px/1.5 monospace; }
#remotesupport .card.rs-full { position: fixed; inset: 0; z-index: 2000; margin: 0; border-radius: 0; display: flex; flex-direction: column; overflow: hidden; }
#remotesupport .rs-classic { padding: 12px; }
#remotesupport .rs-classic .body { padding-top: 12px; }
#remotesupport .rs-classic *, #remotesupport .rs-full * { margin-left: 0; margin-right: 0; }  /* OpenWebif Classic centers everything. */
#remotesupport .rs-full .body { flex: 1; min-height: 0; display: flex; flex-direction: column; }
#remotesupport .rs-full .rs-main { flex: 1; min-height: 0; }
#remotesupport .rs-full .rs-side { overflow: auto; }
#remotesupport .rs-full iframe { height: auto; min-height: 0; }
#remotesupport .rs-full .rs-logs { display: none; }
@media (max-width: 800px) { #remotesupport .rs-main { flex-direction: column; } #remotesupport .rs-side { flex: none; } #remotesupport iframe { height: 70vh; } }
</style>
<div class="card">
<div class="header"><div class="rs-head"><h2><i class="material-icons material-icons-centered">support_agent</i><span class="rs-title"></span></h2><span class="rs-status"></span><button class="rs-start btn btn--skinned waves-effect"></button><button class="rs-full-window btn btn-default waves-effect"></button><button class="rs-stop btn btn-default waves-effect"></button></div></div>
<div class="body">
<div class="rs-question"><span class="rs-question-text"></span><button class="rs-approve btn btn--skinned waves-effect"></button><button class="rs-deny btn btn-default waves-effect"></button></div>
<div class="rs-info"></div>
<div class="rs-main">
<div class="rs-side">
<div><div class="rs-label rs-link-label"></div><a class="rs-link" target="_blank" rel="noopener"></a><div class="rs-link-warning"></div></div>
<div class="rs-qr"></div>
<div><div class="rs-label rs-connected-label"></div><div class="rs-connected"></div></div>
<div><button class="rs-grab-all btn btn--skinned waves-effect"></button> <button class="rs-grab-osd btn btn--skinned waves-effect"></button><div class="rs-grab-hint rs-label"></div></div>
<div class="rs-tab rs-label"><span class="rs-tab-text"></span> <a class="rs-tab-link" target="_blank" rel="noopener"></a></div>
<div class="rs-idle"></div>
</div>
<iframe allow="clipboard-read; clipboard-write"></iframe>
<div class="rs-open"><span class="rs-open-text"></span><a class="rs-open-link btn btn--skinned waves-effect" target="_blank" rel="noopener"></a></div>
</div>
<div class="rs-logs"><div class="rs-label rs-logs-label"></div><table><tbody class="rs-logs-list"></tbody></table><button class="rs-delete-all btn btn-default waves-effect"></button></div>
</div>
</div>
<script>
(function () {  // Runs again each time OpenWebif loads the page into its content area.
	const T = {TEXTS};
	const root = document.getElementById("remotesupport");
	const find = name => root.querySelector(".rs-" + name);
	const frame = root.querySelector("iframe");
	const embed = window.isSecureContext;  // sshx needs Web Crypto, which a page loaded over HTTP does not get.
	let frameUrl = null;
	let shownLogs = null;
	let running = false;

	function qrSvg(matrix) {
		const size = matrix.length + 8;
		let path = "";
		matrix.forEach((row, y) => { for (let x = 0; x < row.length; x++) if (row[x] === "1") path += `M${x + 4},${y + 4}h1v1h-1z`; });
		return `<svg viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
	}

	function grabTime(name) {
		return name.replace(/^.*-sshx-grab-(\\d\\d)(\\d\\d)(\\d\\d)\\..*$/, "$1:$2:$3");
	}

	function canShow() {  // Without OpenWebif the links open or download the files.
		return window.jQuery && (jQuery.fn.modal || jQuery.fn.dialog);
	}

	function dialog(title, box, closed) {  // Bootstrap modal in OpenWebif, jQuery UI dialog in Classic.
		if (jQuery.fn.modal) {
			const widget = jQuery('<div class="modal fade" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><button type="button" class="close" data-dismiss="modal">&times;</button><h4 class="modal-title"></h4></div><div class="modal-body"></div></div></div></div>');
			widget.find(".modal-title").text(title);
			widget.find(".modal-body").append(box);
			widget.on("hidden.bs.modal", () => { closed(); widget.remove(); }).appendTo(document.body).modal("show");
			return widget;
		}
		box.dialog({
			title: title,
			modal: true,
			width: Math.min(window.innerWidth - 32, 1000),
			close: () => { closed(); box.dialog("destroy").remove(); }
		});
		return box.dialog("widget");
	}

	function center(box) {  // Centered again with the size of the content.
		if (!jQuery.fn.modal) {
			box.dialog("option", "position", {my: "center", at: "center", of: window});
		}
	}

	function viewer(log, page) {  // The log first, then the screenshots.
		if (!canShow()) {
			return true;
		}
		const box = jQuery('<div class="rs-viewer"><pre class="rs-log-text"></pre><img alt=""><div class="rs-viewer-bar"><button class="btn btn-default waves-effect">\u25c0</button><span></span><a class="btn btn-default waves-effect"></a><button class="btn btn-default waves-effect">\u25b6</button></div></div>');
		const text = box.find("pre")[0];
		const image = box.find("img");
		const buttons = box.find("button");
		const files = [log.name].concat(log.grabs);
		let timer = null;
		async function load() {  // The log of a running session is read again and follows its end.
			const follow = log.running && text.scrollTop + text.clientHeight >= text.scrollHeight - 4;
			try {
				const response = await fetch("/remotesupport/log/" + encodeURIComponent(log.name), {cache: "no-store"});
				if (response.ok) {
					text.textContent = await response.text();
				}
			} catch (e) {
			}
			if (follow) {
				text.scrollTop = text.scrollHeight;
			}
			if (timer !== false) {
				center(box);
				timer = log.running ? setTimeout(load, 2000) : null;
			}
		}
		function showPage(next) {
			page = (next + files.length) % files.length;
			const url = (page ? "/remotesupport/grab/" : "/remotesupport/log/") + encodeURIComponent(files[page]);
			text.style.display = page ? "none" : "";
			image.toggle(page > 0);
			if (page) {
				image.attr("src", url);
			}
			box.find("span").text(page ? `${T.screenshot} ${page}/${log.grabs.length} \u2013 ${grabTime(files[page])}` : T.sessionLog);
			box.find("a").attr({href: url, download: files[page]}).text(T.download);
			center(box);
		}
		buttons.toggle(files.length > 1);
		buttons.first().on("click", () => showPage(page - 1));
		buttons.last().on("click", () => showPage(page + 1));
		image.on("load", () => center(box));
		dialog(`${T.sessionLog} \u2013 ${log.start}`, box, () => { clearTimeout(timer); timer = false; }).on("keydown", event => {
			if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
				showPage(page + (event.key === "ArrowLeft" ? -1 : 1));
				event.preventDefault();
			}
		});
		showPage(page);
		load();
		return false;
	}

	function show(name, visible, display) {
		find(name).style.display = visible ? (display || "") : "none";
	}

	function render(s) {
		running = s.state === "running";
		show("full-window", running && embed);
		if (!running) {
			fullWindow(false);
		}
		find("status").textContent = s.incomplete ? T.notAvailable : T.states[s.state] + (running && s.approved ? " \\u2013 " + T.approved : "");
		show("start", ["stopped", "error"].includes(s.state) && !s.incomplete);
		show("stop", ["starting", "running"].includes(s.state));
		show("question", s.question, "flex");
		find("question-text").textContent = s.question;
		let info = T.description;
		if (s.incomplete) info += "\\n\\n" + T.incomplete;
		if (s.error) info += "\\n\\n" + T.lastError + " " + s.error;
		find("info").textContent = info;
		show("info", !running);
		show("main", running, "flex");
		if (running) {
			find("link").textContent = find("link").href = s.url;
			find("connected").textContent = s.connected.length ? s.connected.join(", ") : T.nobody;
			find("idle").textContent = s.idleLeft !== null && s.idleLeft <= T.idleWarning ? T.idle.replace("%d", Math.ceil(s.idleLeft / 60)) : "";
			if (frameUrl !== s.url) {
				frameUrl = s.url;
				find("open-link").href = find("tab-link").href = s.url;
				if (embed) {
					frame.src = s.url;
				}
				find("qr").innerHTML = qrSvg(s.qr);
			}
		} else if (frameUrl) {
			frameUrl = null;
			frame.removeAttribute("src");
		}
		const logs = JSON.stringify(s.logs);
		if (logs !== shownLogs) {
			shownLogs = logs;
			const list = find("logs-list");
			list.textContent = "";
			for (const log of s.logs) {
				const row = list.insertRow();
				row.insertCell().textContent = log.start + (log.running ? " \u2013 " + T.running : "");
				row.insertCell().textContent = log.participants;
				const grabs = row.insertCell();
				log.grabs.forEach((grab, index) => {
					const link = document.createElement("a");
					link.href = "/remotesupport/grab/" + encodeURIComponent(grab);
					link.target = "_blank";
					link.textContent = grabTime(grab);
					link.onclick = () => viewer(log, index + 1);
					grabs.appendChild(link);
					grabs.appendChild(document.createTextNode(" "));
				});
				const showLink = document.createElement("a");
				showLink.href = "/remotesupport/log/" + encodeURIComponent(log.name);
				showLink.target = "_blank";
				showLink.textContent = T.show;
				showLink.onclick = () => viewer(log, 0);
				row.insertCell().appendChild(showLink);
				const cell = row.insertCell();
				if (!log.running) {
					const remove = document.createElement("a");
					remove.href = "#";
					remove.textContent = T.delete;
					const question = log.grabs.length ? (log.grabs.length == 1 ? T.deleteQuestionGrab : T.deleteQuestionGrabs.replace("%d", log.grabs.length)) : T.deleteQuestion;
					remove.onclick = () => { confirm(question.replace("%s", log.start)) && post("deletelog/" + encodeURIComponent(log.name)); return false; };
					cell.appendChild(remove);
				}
			}
			find("logs-label").textContent = s.logs.length ? T.logs : T.noLogs;
			show("delete-all", s.logs.some(log => !log.running));
		}
	}

	async function refresh() {
		if (!document.body.contains(root)) {  // OpenWebif shows another page.
			document.documentElement.style.overflow = "";
			return;
		}
		try {
			render(await (await fetch("/remotesupport/status", {cache: "no-store"})).json());
		} catch (e) {
			find("status").textContent = T.offline;
		}
		setTimeout(refresh, 2000);
	}

	async function post(action) {
		const response = await fetch("/remotesupport/" + action, {method: "POST", headers: {"X-Requested-With": "RemoteSupport"}});
		render(await response.json());
	}

	const card = root.querySelector(".card");
	if (getComputedStyle(card).backgroundColor === "rgba(0, 0, 0, 0)") {  // OpenWebif Classic has no cards but jQuery UI widgets.
		card.classList.add("ui-widget-content");
		root.querySelector(".header").classList.add("ui-widget-header");
		card.classList.add("rs-classic");
		find("status").style.color = "inherit";
	}
	find("title").textContent = T.title;
	find("start").textContent = T.start;
	find("stop").textContent = T.stop;
	find("approve").textContent = T.approve;
	find("deny").textContent = T.deny;
	find("link-label").textContent = T.link;
	find("link-warning").textContent = T.linkWarning;
	find("connected-label").textContent = T.connectedLabel;
	find("open-link").textContent = T.openSession;
	find("open-text").textContent = T.insecure;
	frame.style.display = embed ? "" : "none";
	show("open", !embed, "flex");
	show("tab", embed);  // Some browsers block the storage of the embedded page, then it stays blank.
	find("tab-text").textContent = T.blankFrame;
	find("tab-link").textContent = T.openTab;
	function fullWindow(on) {  // Over the whole browser window, the frame stays in place, so sshx keeps its connection.
		card.classList.toggle("rs-full", on);
		document.documentElement.style.overflow = on ? "hidden" : "";  // No scrollbar of the page behind it.
		find("full-window").textContent = on ? T.normalSize : T.fullWindow;
	}
	find("full-window").onclick = () => fullWindow(!card.classList.contains("rs-full"));
	document.addEventListener("keydown", function leave(event) {
		if (!document.body.contains(root)) {
			document.removeEventListener("keydown", leave);
			document.documentElement.style.overflow = "";
		} else if (event.key === "Escape" && card.classList.contains("rs-full") && !document.querySelector(".modal.in, .ui-widget-overlay")) {
			fullWindow(false);
		}
	});
	fullWindow(false);
	find("start").onclick = () => confirm(T.warning + "\\n\\n" + T.startQuestion) && post("start");
	find("stop").onclick = () => confirm(T.stopQuestion) && post("stop");
	find("approve").onclick = () => post("approve");
	find("delete-all").textContent = T.deleteAll;
	async function grab(osd) {
		const response = await fetch("/remotesupport/grab?osd=" + (osd ? "1" : "0"), {method: "POST", headers: {"X-Requested-With": "RemoteSupport"}});
		const result = await response.json();
		find("grab-hint").textContent = result.error || T.grabDone;
		if (!result.error) render(result);
	}
	find("grab-all").textContent = T.grabAll;
	find("grab-osd").textContent = T.grabOsd;
	find("grab-all").onclick = () => grab(false);
	find("grab-osd").onclick = () => grab(true);
	find("delete-all").onclick = () => confirm(T.deleteAllQuestion) && post("deletelogs");
	find("deny").onclick = () => post("deny");
	show("main", false);
	refresh();
})();
</script>
</div>
"""

# Opened directly instead of in OpenWebif.
PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Remote Support</title>
<style>body { margin: 0; padding: 8px 16px; font: 15px/1.4 sans-serif; color-scheme: light dark; } .material-icons { display: none; }</style>
</head>
<body>
{FRAGMENT}</body>
</html>
"""


class RemoteSupportWeb(resource.Resource):
	isLeaf = True

	def __init__(self):
		resource.Resource.__init__(self)
		self.qrUrl = None
		self.qrMatrix = []

	def render_GET(self, request):
		request.setHeader(b"Cache-Control", b"no-store")
		if request.postpath[:1] == [b"status"]:
			return self.json(request)
		if request.postpath[:1] in ([b"log"], [b"grab"]):
			return self.download(request, request.postpath[1].decode("utf-8", "replace") if len(request.postpath) > 1 else "")
		request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
		fragment = FRAGMENT.replace("{TEXTS}", dumps(self.texts()))
		if request.getHeader(b"X-Requested-With") != b"XMLHttpRequest":  # Not loaded into the content area of OpenWebif.
			fragment = PAGE.replace("{FRAGMENT}", fragment)
		return fragment.encode("utf-8")

	def render_POST(self, request):
		if request.getHeader(b"X-Requested-With") != b"RemoteSupport":  # A form of another site can not set it.
			request.setResponseCode(403)
			return b""
		action = request.postpath[:1]
		if action == [b"start"]:
			sshxSession.start()
		elif action == [b"stop"]:
			sshxSession.stop()
		elif action in ([b"approve"], [b"deny"]):
			sshxSession.answerFromWeb(action == [b"approve"])
		elif action == [b"deletelog"]:  # Only listed session logs, the name is not used as a path.
			name = request.postpath[1].decode("utf-8", "replace") if len(request.postpath) > 1 else ""
			deleteSessionLogs([path for stamp, participants, path, running in sessionLogs() if basename(path) == name])
		elif action == [b"deletelogs"]:
			deleteSessionLogs([path for stamp, participants, path, running in sessionLogs()])
		elif action == [b"grab"]:
			error = sshxSession.grabForWeb(request.args.get(b"osd", [b""])[0] == b"1")
			if error:
				request.setResponseCode(409)
				request.setHeader(b"Content-Type", b"application/json; charset=utf-8")
				return dumps({"error": error}).encode("utf-8")
		else:
			request.setResponseCode(404)
			return b""
		return self.json(request)

	def json(self, request):
		state = sshxSession.state
		url = sshxSession.url if state == SshxSession.STATE_RUNNING else None
		status = {
			"state": STATES.get(state, "stopped"),
			"error": sshxSession.error if state == SshxSession.STATE_ERROR else "",
			"url": url,
			"qr": self.qrCode(url),
			"approved": sshxSession.isApproved(),
			"question": sshxSession.question if sshxSession.approvalPending else "",
			"connected": [name for uid, name, final in participants()] if url else [],
			"incomplete": state in (SshxSession.STATE_STOPPED, SshxSession.STATE_ERROR) and incomplete(),
			"idleLeft": sshxSession.idleLeft() if url else None,
			"logs": [{"name": basename(path), "start": stamp, "participants": participants, "running": running, "grabs": [basename(grab) for grab in sessionGrabs(path)]} for stamp, participants, path, running in sessionLogs()]
		}
		request.setHeader(b"Content-Type", b"application/json; charset=utf-8")
		return dumps(status).encode("utf-8")

	def download(self, request, name):  # Only the listed session logs and their grabs can be downloaded.
		paths = [file for stamp, participants, path, running in sessionLogs() for file in [path] + sessionGrabs(path) if basename(file) == name]
		try:
			with open(paths[0], "rb") as fd:
				data = fd.read()
		except (IndexError, OSError):
			request.setResponseCode(404)
			return b""
		contentType = {"png": b"image/png", "jpg": b"image/jpeg"}.get(name.rsplit(".", 1)[-1], b"text/plain; charset=utf-8")
		request.setHeader(b"Content-Type", contentType)
		request.setHeader(b"Content-Disposition", f'attachment; filename="{name}"'.encode("utf-8"))
		return data

	def qrCode(self, url):
		if url and url != self.qrUrl:
			from qrcode import QRCode, constants  # Not at module level as the package may be missing.
			qrCode = QRCode(error_correction=constants.ERROR_CORRECT_M, border=0)
			qrCode.add_data(url)
			qrCode.make(fit=True)
			self.qrUrl = url
			self.qrMatrix = ["".join("1" if module else "0" for module in row) for row in qrCode.get_matrix()]
		return self.qrMatrix if url else []

	def texts(self):
		return {
			"title": _("Remote Support"),
			"states": {
				"stopped": _("No support session active"),
				"error": _("No support session active"),
				"starting": _("Starting support session..."),
				"running": _("Support session is running"),
				"stopping": _("Stopping support session...")
			},
			"approved": _("access approved"),
			"notAvailable": _("Remote support is not available"),
			"start": _("Start"),
			"stop": _("Stop"),
			"approve": _("Allow"),
			"deny": _("Deny"),
			"description": _("Start a support session to get a link for your supporter, who then gets a terminal on this receiver in their web browser. The session is the same as in the Remote Support screen on the TV, you can watch and use it here."),
			"incomplete": _("A package the plugin needs is missing (sshx or a Python module). Please reinstall the Remote Support plugin."),
			"lastError": _("Last error:"),
			"link": _("Link for your supporter"),
			"linkWarning": _("Do not post the link or a screenshot of it in public forums: everybody who has it can try to join and sees the terminals until you deny the access."),
			"connectedLabel": _("Connected"),
			"nobody": _("Nobody"),
			"idle": _("Nobody uses the session, it ends in %d minutes."),
			"idleWarning": IDLE_WARNING,
			"offline": _("The receiver does not answer."),
			"insecure": _("The session can only be shown here when OpenWebif is opened with HTTPS."),
			"openSession": _("Open the session"),
			"blankFrame": _("The terminal stays blank?"),
			"openTab": _("Open the session in its own tab, the new user has to be approved as well."),
			"logs": _("Session logs"),
			"noLogs": _("No session logs"),
			"download": _("Download"),
			"show": _("Show"),
			"sessionLog": _("Session log"),
			"screenshot": _("Screenshot"),
			"fullWindow": _("Full window"),
			"normalSize": _("Normal size"),
			"grabAll": _("Grab ALL"),
			"grabOsd": _("Grab OSD"),
			"grabDone": _("The screenshot is shown in the terminal used last."),
			"delete": _("Delete"),
			"deleteAll": _("Delete All"),
			"deleteQuestion": _("Do you really want to delete the session log '%s'?"),
			"deleteQuestionGrab": _("Do you really want to delete the session log '%s' and its screenshot?"),
			"deleteQuestionGrabs": _("Do you really want to delete the session log '%s' and its %d screenshots?"),
			"deleteAllQuestion": _("Do you really want to delete all session logs and their screenshots? The log of a running session is kept."),
			"running": _("running"),
			"warning": _("After you approved the access on the TV, the supporter has full root access to your receiver as long as the session is running. Only share the link with people you trust!"),
			"startQuestion": _("Do you want to start a support session?"),
			"stopQuestion": _("Do you really want to end the support session?")
		}
