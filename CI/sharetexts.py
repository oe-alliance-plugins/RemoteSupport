# Writes docs/texts.js, the translated texts of the share page, from src/RemoteSupport/ShareTexts.py and the .po files.

from ast import Assign, Call, Constant, Dict, Name, parse
from gettext import GNUTranslations
from glob import glob
from json import dumps
from os.path import basename, dirname, join, realpath
from subprocess import run
from tempfile import TemporaryDirectory

ROOT = dirname(dirname(realpath(__file__)))
SOURCE = join(ROOT, "src", "RemoteSupport", "ShareTexts.py")
LOCALE = join(ROOT, "src", "RemoteSupport", "locale")
TARGET = join(ROOT, "docs", "texts.js")


def englishTexts():  # Parsed, not imported, the plugin package needs enigma2.
	with open(SOURCE, encoding="utf-8") as source:
		tree = parse(source.read())
	for node in tree.body:
		if isinstance(node, Assign) and isinstance(node.targets[0], Name) and node.targets[0].id == "SHARE_TEXTS" and isinstance(node.value, Dict):
			return {key.value: value.args[0].value for key, value in zip(node.value.keys, node.value.values) if isinstance(key, Constant) and isinstance(value, Call) and isinstance(value.args[0], Constant)}
	raise SystemExit(f"SHARE_TEXTS not found in {SOURCE}")


def main():
	english = englishTexts()
	texts = {"en": english}
	with TemporaryDirectory() as temp:
		for po in sorted(glob(join(LOCALE, "*.po"))):
			language = basename(po)[:-3]
			mo = join(temp, f"{language}.mo")
			run(["msgfmt", po, "-o", mo], check=True)  # Leaves out fuzzy translations.
			with open(mo, "rb") as file:
				translation = GNUTranslations(file)
			translated = {key: translation.gettext(text) for key, text in english.items() if translation.gettext(text) != text}
			if translated:
				texts[language.lower()] = translated
	with open(TARGET, "w", encoding="utf-8", newline="\n") as target:
		target.write("// Written by CI/sharetexts.py from src/RemoteSupport/ShareTexts.py and the .po files, do not edit.\n")
		target.write("const TEXTS = " + dumps(texts, ensure_ascii=False, indent="\t", sort_keys=True) + ";\n")


if __name__ == "__main__":
	main()
