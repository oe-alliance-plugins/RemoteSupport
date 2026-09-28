from gettext import bindtextdomain, dgettext, dngettext, gettext, ngettext as fallbackNgettext

from Components.Language import language
from Tools.Directories import SCOPE_PLUGINS, resolveFilename

PluginLanguageDomain = "RemoteSupport"
PluginLanguagePath = "SystemPlugins/RemoteSupport/locale"

__version__ = "1.2"


def localeInit():
	bindtextdomain(PluginLanguageDomain, resolveFilename(SCOPE_PLUGINS, PluginLanguagePath))


def _(text):
	translated = dgettext(PluginLanguageDomain, text)
	return translated if translated != text else gettext(text)


def ngettext(singular, plural, count):
	translated = dngettext(PluginLanguageDomain, singular, plural, count)
	return translated if translated not in (singular, plural) else fallbackNgettext(singular, plural, count)


localeInit()
language.addCallback(localeInit)
