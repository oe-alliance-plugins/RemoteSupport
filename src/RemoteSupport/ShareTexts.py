# The texts of the share page docs/link.html, the QR code leads there. Not used by the plugin, the
# strings are only here to be translated in the .po files. CI/sharetexts.py writes docs/texts.js from them.


def _(text):
	return text


SHARE_TEXTS = {
	"title": _("Remote Support"),
	# TRANSLATORS: Keep {distro}, it is replaced by the distribution of the receiver, e.g. OpenATV.
	"titleDistro": _("Remote Support for {distro}"),
	"send": _("Send this link to your supporter:"),
	"intro": _("Here is the link to the support session of my receiver:"),
	# TRANSLATORS: Keep {receiver} and {distro}, they are replaced by the receiver and its distribution, e.g. pulse4kmini and OpenATV.
	"introReceiver": _("Here is the link to the support session of my {receiver} ({distro}):"),
	"share": _("Share"),
	"mail": _("E-mail"),
	"copy": _("Copy"),
	"copied": _("Copied"),
	"pasteDiscord": _("Copied, paste it in Discord"),
	"doNotOpen": _("Do not open the link yourself, you would join the session as a new user."),
	"warning": _("Do not post the link or a screenshot of it in public forums: everybody who has it can try to join and sees the terminals until you deny the access."),
	"missing": _("The link is incomplete. Scan the QR code on the TV again.")
}
