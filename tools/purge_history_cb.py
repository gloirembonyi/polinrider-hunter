# POLINRIDER-HUNTER-DETECTOR: names campaign artefacts to strip them. Not malware.
# git filter-repo --file-info-callback body: strips PolinRider payloads from EVERY historical
# version of every file. Called once per (path, blob); return (None, mode, blob_id) to drop the file
# from that commit (filter-repo: name None, mode kept), or (path, mode, blob_id) to keep / replace it.
import re

ARTIFACTS = {b"branch_structure.json", b"config.bat", b"temp_auto_push.bat",
             b"temp_interactive_push.bat", b"spellright.dict"}
FAKE_FONT = (b".lfk", b".llf", b".lkf")
TEXT_EXT = (b".js", b".mjs", b".cjs", b".ts", b".tsx", b".jsx", b".json", b".env", b".mts", b".cts",
            b".vue", b".svelte", b".html")
# Appended payload: real code, then a long whitespace run, then >=200 chars of code to end of line.
PAD_TAIL = re.compile(rb"(?<=\S)[ \t]{20,}\S.{199,}$", re.M)
# Dropper line: the line *starts* with the pad (api.js shape).
PAD_LINE = re.compile(rb"^[ \t]{200,}\S.{999,}$\n?", re.M)
HOOK = re.compile(rb"node\s+(?:\./)?(?:api\.js|public/fonts/[\w.-]+)\s*(?:&&|;)\s*")
CREATE_REQUIRE = re.compile(rb"\Aimport \{ createRequire \} from 'module';\r?\n(?:\r?\n)?const require = createRequire\(import\.meta\.url\);\r?\n(?:\r?\n)?")
# NestJS variant: `import 'dotenv/config'` + a self-invoking block that atob()s AUTH_API_KEY into a
# URL, fetches it and eval()s the answer. Removed only with all three tells present, so an honest
# dotenv import is left alone.
IIFE = re.compile(rb"(?:import ['\"]dotenv/config['\"];?\r?\n(?:\r?\n)?)?\(async \(\) => \{(?:(?!\}\)\(\);).)*?atob\(process\.env\.AUTH_API_KEY\)(?:(?!\}\)\(\);).)*?eval\(\w+\);(?:(?!\}\)\(\);).)*?\}\)\(\);[ \t]*\r?\n?", re.S)
# ...and the committed .env that feeds it: the key line goes, other lines stay.
AUTH_KEY_LINE = re.compile(rb"^AUTH_API_KEY=.*(?:\r?\n|$)", re.M)

base = filename.rsplit(b"/", 1)[-1]
low = base.lower()
if base in ARTIFACTS or low.endswith(FAKE_FONT):
    return (None, mode, blob_id)
if not (low.endswith(TEXT_EXT) or low == b".env" or low.startswith(b".env")):
    return (filename, mode, blob_id)
data = value.get_contents_by_identifier(blob_id)
if b"\0" in data:
    return (filename, mode, blob_id)
new = data
if low == b"tasks.json" and b"folderOpen" in new and (b"node " in new or b"/fonts/" in new):
    return (None, mode, blob_id)
if re.search(rb"[ \t]{200,}\S", new):
    new = PAD_LINE.sub(b"", new)
    new = PAD_TAIL.sub(b"", new)
    if new != data:
        new = CREATE_REQUIRE.sub(b"", new)
if low == b"package.json":
    new = HOOK.sub(b"", new)
if b"AUTH_API_KEY" in new:
    if low.startswith(b".env"):
        new = AUTH_KEY_LINE.sub(b"", new)
    elif b"atob(" in new and b"eval(" in new:
        new = IIFE.sub(b"", new)
if new == data:
    return (filename, mode, blob_id)
if not new.strip():
    return (None, mode, blob_id)  # the whole file was payload
return (filename, mode, value.insert_file_with_contents(new))
