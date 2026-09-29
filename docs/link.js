function decode(text) {  // Scanners may encode the fragment.
	try {
		return decodeURIComponent(text);
	} catch (error) {
		return text;
	}
}
window.addEventListener("hashchange", () => location.reload());  // A new QR code may open in the same tab.
const parts = location.hash.slice(1).split(",");
const language = decode(parts[0]).toLowerCase();
const [distro, receiver] = [decode(parts[1] || ""), decode(parts[2] || "")];
const url = decode(parts.slice(3).join(","));
const locale = language.replace("-", "_");
const translation = [locale, locale.split("_")[0]].find(code => TEXTS[code]) || "en";
const texts = { ...TEXTS.en, ...TEXTS[translation] };  // English for what is not translated.
document.documentElement.lang = translation.replace("_", "-");
const title = (distro ? texts.titleDistro.replace("{distro}", distro) : texts.title) + (receiver ? ` (${receiver})` : "");
document.title = title;
document.getElementById("title").textContent = title;
document.querySelectorAll("[data-text]").forEach(element => { element.textContent = texts[element.dataset.text]; });
if (/^https:\/\/\S+$/.test(url)) {
	const intro = receiver && distro ? texts.introReceiver.replace("{receiver}", receiver).replace("{distro}", distro) : texts.intro;
	const message = `${intro} ${url}`;
	const encoded = encodeURIComponent(message);
	document.getElementById("link").textContent = url;
	document.getElementById("telegram").href = `https://t.me/share/url?url=${encodeURIComponent(url)}&text=${encodeURIComponent(intro)}`;
	document.getElementById("whatsapp").href = `https://wa.me/?text=${encoded}`;
	document.getElementById("sms").href = `sms:?&body=${encoded}`;
	document.getElementById("mail").href = `mailto:?subject=${encodeURIComponent(title)}&body=${encoded}`;
	const shareButton = document.getElementById("share");
	if (navigator.share) {
		shareButton.hidden = false;
		shareButton.onclick = () => navigator.share({ text: message }).catch(() => {});
	}
	const copyMessage = done => navigator.clipboard.writeText(message).then(done, () => {});
	document.getElementById("copy").onclick = event => copyMessage(() => { event.target.textContent = texts.copied; });
	document.getElementById("discord").onclick = event => copyMessage(() => {  // Discord can not take a text, it is pasted there.
		event.target.textContent = texts.pasteDiscord;
		setTimeout(() => { location.href = "https://discord.com/channels/@me"; }, 1500);
	});
	document.getElementById("session").hidden = false;
} else {
	document.getElementById("missing").hidden = false;
}
