//! PolinRider indicators of compromise, and the matcher that finds them.
//!
//! Everything here is byte-oriented on purpose. Payloads are appended to source
//! files that may be any encoding and any line ending, and the healer needs an
//! exact byte offset to cut at, so we never decode to `String`.

/// How much we trust a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Unambiguous PolinRider. Safe to remove automatically.
    Critical,
    /// Consistent with PolinRider but plausible in honest code. Report, never auto-cut.
    Suspicious,
}

/// The shape of a single indicator.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// Case-sensitive literal byte sequence.
    Lit(&'static str),
    /// ASCII-case-insensitive literal byte sequence.
    LitCi(&'static str),
    /// `global.i` then optional spaces/tabs then `=`.
    ///
    /// The variant that evaded every previous gate wrote `global.i = '...'`
    /// with spaces, while the old patterns matched only `global.i=`.
    GlobalIAssign,
    /// Campaign tag: `A8-` or `A9-` followed by four digits (`A9-4221`, `A8-2941`).
    CampaignId,
    /// `allowAutomaticTasks` set to an *enabling* value.
    ///
    /// The setting existing is not the problem - projects hardened against the
    /// folderOpen variant set it to "off" on purpose, and flagging that would
    /// punish exactly the right behaviour. Only `true` / `"on"` arms a task.
    AutoTasksEnabled,
    /// A run of at least N spaces/tabs followed by a non-whitespace byte.
    ///
    /// This is the variant-agnostic one. Every sample so far hides its payload
    /// behind ~500 characters of padding so the code sits off the right edge of
    /// the editor and stays invisible in review. A future variant can change
    /// every string it contains but not this, without giving up its camouflage.
    Padding(usize),
}

pub struct Ioc {
    pub id: &'static str,
    pub sev: Severity,
    pub why: &'static str,
    pub kind: Kind,
}

/// The indicator table.
///
/// Order does not matter; the matcher reports hits sorted by file offset.
pub static IOCS: &[Ioc] = &[
    // ---- stage-1 loader internals -------------------------------------------------
    Ioc {
        id: "eth-dead-drop-sender",
        sev: Severity::Critical,
        why: "hardcoded Ethereum sender the loader reads its C2 address from",
        kind: Kind::LitCi("0xa322e5f3"),
    },
    Ioc {
        id: "payload-header",
        sev: Severity::Critical,
        why: "X-Payload-B64 response header carrying the XOR-encrypted stage 2",
        kind: Kind::LitCi("x-payload-b64"),
    },
    Ioc {
        id: "stage2-path-cls",
        sev: Severity::Critical,
        why: "stage-2 download path /0x/cls",
        kind: Kind::Lit("/0x/cls"),
    },
    Ioc {
        id: "stage2-path-ls",
        sev: Severity::Critical,
        why: "stage-2 download path /0x/ls",
        kind: Kind::Lit("/0x/ls"),
    },
    Ioc {
        id: "global-i-assign",
        sev: Severity::Critical,
        why: "loader campaign marker `global.i = ...` (matches with or without spaces)",
        kind: Kind::GlobalIAssign,
    },
    Ioc {
        id: "campaign-id",
        sev: Severity::Critical,
        why: "PolinRider campaign tag A8-nnnn / A9-nnnn",
        kind: Kind::CampaignId,
    },
    // ---- obfuscator artefacts -----------------------------------------------------
    Ioc {
        id: "global-bang",
        sev: Severity::Critical,
        why: "obfuscated variant entry point global['!']",
        kind: Kind::Lit("global['!']"),
    },
    Ioc {
        id: "shuffle-decoder",
        sev: Severity::Critical,
        why: "string-shuffle decoder function _$_1e42",
        kind: Kind::Lit("_$_1e42"),
    },
    Ioc {
        id: "shuffle-modulus",
        sev: Severity::Critical,
        why: "modulus 4573868 used by the string-shuffle decoder",
        kind: Kind::Lit("4573868"),
    },
    Ioc {
        id: "hex-string-array",
        sev: Severity::Critical,
        why: "javascript-obfuscator hex string-array accessor parseInt(_0x",
        kind: Kind::Lit("parseInt(_0x"),
    },
    // ---- the src/main.ts dropper --------------------------------------------------
    Ioc {
        id: "auth-api-key",
        sev: Severity::Critical,
        why: "AUTH_API_KEY, the base64 C2 URL the eval dropper decodes",
        kind: Kind::Lit("AUTH_API_KEY"),
    },
    Ioc {
        id: "eval-proxyinfo",
        sev: Severity::Critical,
        why: "eval(proxyInfo) — remote code execution in the dropper",
        kind: Kind::Lit("eval(proxyInfo)"),
    },
    Ioc {
        id: "atob-env",
        sev: Severity::Critical,
        why: "atob(process.env...) decoding a C2 URL out of the environment",
        kind: Kind::Lit("atob(process.env."),
    },
    Ioc {
        id: "c2-vercel",
        sev: Severity::Critical,
        why: "known C2 host auth-confirm-eight.vercel.app",
        kind: Kind::LitCi("auth-confirm-eight"),
    },
    // ---- the VS Code autorun variant ----------------------------------------------
    Ioc {
        id: "font-payload",
        sev: Severity::Critical,
        why: "payload disguised as a webfont and executed by node",
        kind: Kind::Lit("node ./public/fonts"),
    },
    // ---- second obfuscator variant (April 2026) -----------------------------------
    //
    // Same four-layer shuffle cipher, same blockchain dead drop, every unique
    // string rotated. Both variants are live, and at least one victim carried
    // markers from each in different files.
    Ioc {
        id: "obf-marker-v1",
        sev: Severity::Critical,
        why: "first-variant obfuscator marker rmcej%otb%",
        kind: Kind::Lit("rmcej%otb%"),
    },
    Ioc {
        id: "obf-marker-v2",
        sev: Severity::Critical,
        why: "second-variant obfuscator marker Cot%3t=shtP",
        kind: Kind::Lit("Cot%3t=shtP"),
    },
    Ioc {
        id: "shuffle-seed-v1a",
        sev: Severity::Critical,
        why: "first-variant shuffle seed 2857687",
        kind: Kind::Lit("2857687"),
    },
    Ioc {
        id: "shuffle-seed-v1b",
        sev: Severity::Critical,
        why: "first-variant secondary shuffle seed 2667686",
        kind: Kind::Lit("2667686"),
    },
    Ioc {
        id: "shuffle-seed-v2a",
        sev: Severity::Critical,
        why: "second-variant shuffle seed 1111436",
        kind: Kind::Lit("1111436"),
    },
    Ioc {
        id: "shuffle-seed-v2b",
        sev: Severity::Critical,
        why: "second-variant secondary shuffle seed 3896884",
        kind: Kind::Lit("3896884"),
    },
    Ioc {
        id: "global-v-marker",
        sev: Severity::Critical,
        why: "second-variant injection marker global['_V'] - the version tag it stamps",
        kind: Kind::Lit("global['_V']"),
    },
    // ---- blockchain dead drops beyond Ethereum ------------------------------------
    Ioc {
        id: "tron-dead-drop-1",
        sev: Severity::Critical,
        why: "TRON dead-drop account the loader reads its C2 from",
        kind: Kind::Lit("TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"),
    },
    Ioc {
        id: "tron-dead-drop-2",
        sev: Severity::Critical,
        why: "secondary TRON dead-drop account",
        kind: Kind::Lit("TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"),
    },
    Ioc {
        id: "aptos-dead-drop-1",
        sev: Severity::Critical,
        why: "Aptos transaction carrying an encrypted payload",
        kind: Kind::LitCi("0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e"),
    },
    Ioc {
        id: "aptos-dead-drop-2",
        sev: Severity::Critical,
        why: "second Aptos transaction carrying an encrypted payload",
        kind: Kind::LitCi("0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"),
    },
    // ---- XOR keys for the second stage --------------------------------------------
    Ioc {
        id: "xor-key-1",
        sev: Severity::Critical,
        why: "hardcoded XOR key used to decrypt stage 2",
        kind: Kind::Lit("2[gWfGj;<:-93Z^C"),
    },
    Ioc {
        id: "xor-key-2",
        sev: Severity::Critical,
        why: "second hardcoded XOR key used to decrypt stage 2",
        kind: Kind::Lit("m6:tTh^D)cBz?NM]"),
    },
    Ioc {
        id: "xor-key-3",
        sev: Severity::Critical,
        why: "XOR key from the Ethereum/NullReceiver variant",
        kind: Kind::Lit("q4FZkxX{!h,Sr3=@"),
    },
    Ioc {
        id: "xor-key-4",
        sev: Severity::Critical,
        why: "second XOR key from the Ethereum/NullReceiver variant",
        kind: Kind::Lit("y-p_>d$0B&@^1aQk"),
    },
    // ---- the tasks.json / HTTP C2 vector ------------------------------------------
    Ioc {
        id: "c2-vercel-default-config",
        sev: Severity::Critical,
        why: "HTTP C2 host used by the .vscode/tasks.json vector",
        kind: Kind::LitCi("default-configuration.vercel.app"),
    },
    Ioc {
        id: "c2-vercel-260120",
        sev: Severity::Critical,
        why: "HTTP C2 host used by the .vscode/tasks.json vector",
        kind: Kind::LitCi("260120.vercel.app"),
    },
    Ioc {
        id: "c2-vercel-vscode",
        sev: Severity::Critical,
        why: "vscode-settings HTTP C2 host family",
        kind: Kind::LitCi("vscode-settings-bootstrap.vercel.app"),
    },
    Ioc {
        id: "c2-vercel-vscode-2",
        sev: Severity::Critical,
        why: "vscode-settings HTTP C2 host family",
        kind: Kind::LitCi("vscode-settings-config.vercel.app"),
    },
    Ioc {
        id: "c2-vercel-vscode-3",
        sev: Severity::Critical,
        why: "vscode-bootstrapper HTTP C2 host",
        kind: Kind::LitCi("vscode-bootstrapper.vercel.app"),
    },
    Ioc {
        id: "c2-vercel-vscode-4",
        sev: Severity::Critical,
        why: "vscode-load-config HTTP C2 host",
        kind: Kind::LitCi("vscode-load-config.vercel.app"),
    },
    Ioc {
        id: "stakinggame-task-uuid",
        sev: Severity::Critical,
        why: "constant UUID in the StakingGame lure's .vscode/tasks.json",
        kind: Kind::LitCi("e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"),
    },
    // ---- trojanized packages -------------------------------------------------------
    //
    // Typosquats of Tailwind/PostCSS utilities. Seeing one of these in a
    // package.json or a lockfile is how the loader arrives in the first place.
    Ioc {
        id: "pkg-tailwindcss-style-animate",
        sev: Severity::Critical,
        why: "trojanized npm package tailwindcss-style-animate",
        kind: Kind::LitCi("tailwindcss-style-animate"),
    },
    Ioc {
        id: "pkg-tailwind-mainanimation",
        sev: Severity::Critical,
        why: "trojanized npm package tailwind-mainanimation",
        kind: Kind::LitCi("tailwind-mainanimation"),
    },
    Ioc {
        id: "pkg-tailwind-autoanimation",
        sev: Severity::Critical,
        why: "trojanized npm package tailwind-autoanimation",
        kind: Kind::LitCi("tailwind-autoanimation"),
    },
    Ioc {
        id: "pkg-tailwindcss-typography-style",
        sev: Severity::Critical,
        why: "trojanized npm package tailwindcss-typography-style",
        kind: Kind::LitCi("tailwindcss-typography-style"),
    },
    Ioc {
        id: "pkg-tailwindcss-style-modify",
        sev: Severity::Critical,
        why: "trojanized npm package tailwindcss-style-modify",
        kind: Kind::LitCi("tailwindcss-style-modify"),
    },
    Ioc {
        id: "pkg-tailwindcss-animate-style",
        sev: Severity::Critical,
        why: "trojanized npm package tailwindcss-animate-style",
        kind: Kind::LitCi("tailwindcss-animate-style"),
    },
    // ---- corroborating: other chains' public RPC ----------------------------------
    Ioc {
        id: "rpc-tron",
        sev: Severity::Suspicious,
        why: "TRON API endpoint used to read the dead drop",
        kind: Kind::LitCi("api.trongrid.io"),
    },
    Ioc {
        id: "rpc-aptos",
        sev: Severity::Suspicious,
        why: "Aptos fullnode endpoint used to read the dead drop",
        kind: Kind::LitCi("fullnode.mainnet.aptoslabs.com"),
    },
    Ioc {
        id: "rpc-bsc",
        sev: Severity::Suspicious,
        why: "BNB Smart Chain RPC used to read the dead drop",
        kind: Kind::LitCi("bsc-dataseed.binance.org"),
    },
    Ioc {
        id: "rpc-bsc-2",
        sev: Severity::Suspicious,
        why: "BNB Smart Chain RPC used to read the dead drop",
        kind: Kind::LitCi("bsc-rpc.publicnode.com"),
    },
    // ---- structural ---------------------------------------------------------------
    Ioc {
        id: "padding-run",
        sev: Severity::Critical,
        why: "long space/tab pad hiding appended code off the right edge of the editor",
        kind: Kind::Padding(200),
    },
    // ---- corroborating, not conclusive --------------------------------------------
    Ioc {
        id: "eth-rpc-block",
        sev: Severity::Suspicious,
        why: "Ethereum block lookup — how the loader resolves its C2",
        kind: Kind::Lit("eth_getBlockByNumber"),
    },
    Ioc {
        id: "eth-rpc-nonce",
        sev: Severity::Suspicious,
        why: "Ethereum nonce lookup used to binary-search the dead-drop tx",
        kind: Kind::Lit("eth_getTransactionCount"),
    },
    Ioc {
        id: "rpc-publicnode",
        sev: Severity::Suspicious,
        why: "public Ethereum RPC endpoint used by the loader",
        kind: Kind::LitCi("ethereum-rpc.publicnode.com"),
    },
    Ioc {
        id: "rpc-drpc",
        sev: Severity::Suspicious,
        why: "public Ethereum RPC endpoint used by the loader",
        kind: Kind::LitCi("eth.drpc.org"),
    },
    Ioc {
        id: "rpc-1rpc",
        sev: Severity::Suspicious,
        why: "public Ethereum RPC endpoint used by the loader",
        kind: Kind::LitCi("1rpc.io/eth"),
    },
    Ioc {
        id: "rpc-blastapi",
        sev: Severity::Suspicious,
        why: "public Ethereum RPC endpoint used by the loader",
        kind: Kind::LitCi("eth-mainnet.public.blastapi.io"),
    },
    Ioc {
        id: "hidden-spawn",
        sev: Severity::Suspicious,
        why: "windowsHide — how stage 2 is spawned without a visible console",
        kind: Kind::Lit("windowsHide"),
    },
    Ioc {
        id: "vscode-autorun",
        sev: Severity::Suspicious,
        why: "task runs on folderOpen; the autorun variant arms itself this way",
        kind: Kind::Lit("folderOpen"),
    },
    Ioc {
        id: "vscode-allow-autorun",
        sev: Severity::Suspicious,
        why: "task.allowAutomaticTasks is enabled, which arms a folderOpen task",
        kind: Kind::AutoTasksEnabled,
    },
];

/// An extended-regex approximation of the critical set, for `git grep`.
///
/// `git grep` runs inside the object database, which lets us audit every branch
/// without checking anything out. It cannot call our matcher, so it gets this
/// equivalent pattern; anything it flags is then confirmed with the real matcher
/// against the blob contents.
pub const GIT_GREP_ERE: &str = concat!(
    "0xa322[Ee]5f3",
    "|[Xx]-[Pp]ayload-[Bb]64",
    "|/0x/cls|/0x/ls",
    "|global\\.i[[:space:]]*=",
    "|A[89]-[0-9]{4}",
    "|global\\['!'\\]",
    "|_\\$_1e42",
    "|4573868",
    "|parseInt\\(_0x",
    "|AUTH_API_KEY",
    "|eval\\(proxyInfo\\)",
    "|atob\\(process\\.env\\.",
    "|auth-confirm-eight",
    "|node \\./public/fonts",
    "|( {200,}|\t{200,})[^[:space:]]",
);

/// The id of the structural indicator, whose severity is context-dependent.
pub const PADDING_IOC: &str = "padding-run";

/// Indicators that are only meaningful next to another one.
///
/// `windowsHide` and a `folderOpen` task are both entirely normal in honest
/// tooling - editor extensions and dev scripts use them constantly. As the sole
/// finding in a file they are noise; alongside a real indicator they are useful
/// context about how the payload runs. So they are reported only in company.
pub const CORROBORATING: &[&str] = &[
    "hidden-spawn",
    "vscode-autorun",
    // Every blockchain RPC call and endpoint. A crypto wallet extension, a web3
    // library or a dApp legitimately contains all of these - a real sweep of one
    // home directory flagged two browser wallets and nothing else. Beside a
    // payload marker they explain how the loader reaches its C2; on their own
    // they only describe software that talks to a blockchain.
    "eth-rpc-block",
    "eth-rpc-nonce",
    "rpc-publicnode",
    "rpc-drpc",
    "rpc-1rpc",
    "rpc-blastapi",
    "rpc-tron",
    "rpc-aptos",
    "rpc-bsc",
    "rpc-bsc-2",
];

#[derive(Debug, Clone)]
pub struct Hit {
    pub ioc: &'static str,
    pub sev: Severity,
    pub why: &'static str,
    /// Byte offset where the match begins.
    pub start: usize,
    /// Byte offset one past the end of the match.
    pub end: usize,
    /// 1-based line the match begins on.
    pub line: usize,
}

/// True if `data` contains the detector opt-out marker.
///
/// This file is the obvious first customer: it lists every string we hunt for,
/// so without the marker below the hunter would quarantine its own source.
/// Marker: POLINRIDER-HUNTER-DETECTOR
pub fn contains_marker(data: &[u8], marker: &str) -> bool {
    find_lit(data, marker.as_bytes()).is_some()
}

/// Find every indicator in `data`, sorted by offset.
pub fn scan(data: &[u8]) -> Vec<Hit> {
    let mut hits = scan_inner(data, false);
    hits.sort_by_key(|h| h.start);
    for h in hits.iter_mut() {
        h.line = line_of(data, h.start);
    }
    hits
}

/// True if `data` carries at least one critical indicator.
///
/// Stops at the first one, which is what makes the healer's verify-after-cut
/// loop cheap.
pub fn has_critical(data: &[u8]) -> bool {
    scan_inner(data, true)
        .iter()
        .any(|h| h.sev == Severity::Critical)
}

/// The matcher.
///
/// This used to run one `windows().position()` search per indicator - 25
/// separate passes over every byte of every file. On a background service
/// walking a developer's whole home directory that is most of the CPU cost, for
/// no benefit.
///
/// Now: one pass. Each indicator is bucketed by the byte it can start with
/// (both cases, for the case-insensitive ones), so at any given position we
/// only test the one or two indicators that could possibly match there. The
/// padding heuristic keeps its own pass because it starts on whitespace, which
/// would otherwise put it in the busiest bucket in the table.
///
/// `stop_early` returns as soon as a critical indicator is found.
fn scan_inner(data: &[u8], stop_early: bool) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();

    let hit_of = |k: usize, start: usize, end: usize| Hit {
        ioc: IOCS[k].id,
        sev: IOCS[k].sev,
        why: IOCS[k].why,
        start,
        end,
        line: 0,
    };

    // Structural check, one pass of its own.
    for (k, ioc) in IOCS.iter().enumerate() {
        if let Kind::Padding(n) = ioc.kind {
            if let Some((s, e)) = find_padding(data, n) {
                hits.push(hit_of(k, s, e));
                if stop_early && ioc.sev == Severity::Critical {
                    return hits;
                }
            }
        }
    }

    // Everything else, one pass.
    let buckets = index();
    let mut done = [false; 64];
    debug_assert!(IOCS.len() <= 64);
    for i in 0..data.len() {
        let bucket = &buckets[data[i] as usize];
        if bucket.is_empty() {
            continue;
        }
        for &k in bucket {
            if done[k] {
                continue;
            }
            if let Some((s, e)) = match_at(data, i, IOCS[k].kind) {
                done[k] = true;
                hits.push(hit_of(k, s, e));
                if stop_early && IOCS[k].sev == Severity::Critical {
                    return hits;
                }
            }
        }
    }
    hits
}

/// Indicators bucketed by the byte they can begin with.
fn index() -> &'static [Vec<usize>; 256] {
    use std::sync::OnceLock;
    static IDX: OnceLock<[Vec<usize>; 256]> = OnceLock::new();
    IDX.get_or_init(|| {
        let mut by: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        for (k, ioc) in IOCS.iter().enumerate() {
            for b in first_bytes(ioc.kind) {
                by[b as usize].push(k);
            }
        }
        by
    })
}

/// Which bytes can this indicator start on? Empty means "not in the table".
fn first_bytes(kind: Kind) -> Vec<u8> {
    match kind {
        Kind::Lit(s) => s.as_bytes().first().copied().into_iter().collect(),
        Kind::LitCi(s) => match s.as_bytes().first().copied() {
            Some(b) => {
                let lower = b.to_ascii_lowercase();
                let upper = b.to_ascii_uppercase();
                if lower == upper {
                    vec![lower]
                } else {
                    vec![lower, upper]
                }
            }
            None => vec![],
        },
        Kind::GlobalIAssign => vec![b'g'],
        Kind::CampaignId => vec![b'A'],
        Kind::AutoTasksEnabled => vec![b'a'],
        // Starts on a space or tab; given its own pass instead.
        Kind::Padding(_) => vec![],
    }
}

fn starts_with_at(data: &[u8], i: usize, needle: &[u8]) -> bool {
    data.len() >= i + needle.len() && &data[i..i + needle.len()] == needle
}

fn starts_with_ci_at(data: &[u8], i: usize, needle: &[u8]) -> bool {
    data.len() >= i + needle.len()
        && data[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Does `kind` match starting exactly at `i`? (A test, not a search.)
fn match_at(data: &[u8], i: usize, kind: Kind) -> Option<(usize, usize)> {
    match kind {
        Kind::Lit(s) => starts_with_at(data, i, s.as_bytes()).then(|| (i, i + s.len())),
        Kind::LitCi(s) => starts_with_ci_at(data, i, s.as_bytes()).then(|| (i, i + s.len())),
        Kind::GlobalIAssign => {
            let pat = b"global.i";
            if !starts_with_at(data, i, pat) {
                return None;
            }
            let mut j = i + pat.len();
            while j < data.len() && (data[j] == b' ' || data[j] == b'\t') {
                j += 1;
            }
            // `==` is a comparison, not the loader's assignment.
            if j < data.len() && data[j] == b'=' && data.get(j + 1) != Some(&b'=') {
                Some((i, j + 1))
            } else {
                None
            }
        }
        Kind::CampaignId => {
            if i + 7 > data.len()
                || data[i] != b'A'
                || (data[i + 1] != b'8' && data[i + 1] != b'9')
                || data[i + 2] != b'-'
                || !data[i + 3..i + 7].iter().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            // The tag stands alone - `global.i = 'A8-2941'`. The same seven
            // characters occur inside GUIDs and constant tables, where they are
            // surrounded by more hex. Windows' own pscon.py and shellcon.py
            // tripped this before the boundary check existed.
            let boundary = |b: u8| !(b.is_ascii_hexdigit() || b == b'-' || b == b'_');
            let before_ok = i == 0 || boundary(data[i - 1]);
            let after_ok = i + 7 >= data.len() || boundary(data[i + 7]);
            if before_ok && after_ok {
                Some((i, i + 7))
            } else {
                None
            }
        }
        Kind::AutoTasksEnabled => {
            let pat = b"allowAutomaticTasks";
            if !starts_with_at(data, i, pat) {
                return None;
            }
            let end = (i + pat.len() + 24).min(data.len());
            let tail = &data[i + pat.len()..end];
            if find_lit(tail, b"true").is_some() || find_lit_ci(tail, b"\"on\"").is_some() {
                Some((i, i + pat.len()))
            } else {
                None
            }
        }
        Kind::Padding(_) => None,
    }
}

fn find_lit(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn find_lit_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    // Compare the first byte before the rest. `windows(n).position(|w| zip.all)`
    // walks the whole needle at every single offset, which on a megabyte of
    // minified JavaScript is an enormous amount of work to discover a mismatch
    // that the first byte would have settled.
    let lower = needle[0].to_ascii_lowercase();
    let upper = needle[0].to_ascii_uppercase();
    let last = hay.len() - needle.len();
    for i in 0..=last {
        let b = hay[i];
        if b != lower && b != upper {
            continue;
        }
        if hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, c)| a.eq_ignore_ascii_case(c))
        {
            return Some(i);
        }
    }
    None
}

/// `global.i` + optional spaces/tabs + `=`.
#[cfg(test)]
fn find_global_i_assign(data: &[u8]) -> Option<(usize, usize)> {
    let pat = b"global.i";
    let mut from = 0usize;
    while let Some(rel) = find_lit(&data[from..], pat) {
        let start = from + rel;
        let mut j = start + pat.len();
        while j < data.len() && (data[j] == b' ' || data[j] == b'\t') {
            j += 1;
        }
        // `==` is a comparison, not the loader's assignment.
        if j < data.len() && data[j] == b'=' && data.get(j + 1) != Some(&b'=') {
            return Some((start, j + 1));
        }
        from = start + 1;
    }
    None
}

/// `A8-1234` / `A9-1234`.
#[cfg(test)]
fn find_campaign_id(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 7 {
        return None;
    }
    for i in 0..=data.len() - 7 {
        if data[i] == b'A'
            && (data[i + 1] == b'8' || data[i + 1] == b'9')
            && data[i + 2] == b'-'
            && data[i + 3..i + 7].iter().all(|b| b.is_ascii_digit())
        {
            return Some((i, i + 7));
        }
    }
    None
}

/// A run of >= `min` spaces/tabs followed by a non-whitespace byte.
///
/// Returns the offset of the *start of the run*, which is exactly where the
/// healer should cut: it removes the camouflage along with the payload.
fn find_padding(data: &[u8], min: usize) -> Option<(usize, usize)> {
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == b' ' || data[i] == b'\t' {
            let start = i;
            while i < data.len() && (data[i] == b' ' || data[i] == b'\t') {
                i += 1;
            }
            let run = i - start;
            let next_is_code = i < data.len() && data[i] != b'\r' && data[i] != b'\n';
            if run >= min && next_is_code {
                return Some((start, i));
            }
        } else {
            i += 1;
        }
    }
    None
}

fn line_of(data: &[u8], offset: usize) -> usize {
    1 + data[..offset.min(data.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaced_global_i_is_caught() {
        // The exact form that evaded every previous gate.
        assert!(has_critical(b"export default config;   global.i = 'A8-2941';"));
    }

    #[test]
    fn tight_global_i_is_caught() {
        assert!(has_critical(b"global.i=\"A9-4221\";"));
    }

    #[test]
    fn comparison_is_not_an_assignment() {
        assert!(find_global_i_assign(b"if (global.i == 3) {}").is_none());
    }

    #[test]
    fn padding_needs_trailing_code() {
        let mut trailing = b"const a = 1;".to_vec();
        trailing.extend(std::iter::repeat(b' ').take(400));
        // Trailing whitespace alone is untidy, not malicious.
        assert!(find_padding(&trailing, 200).is_none());
        trailing.extend_from_slice(b"payload()");
        assert!(find_padding(&trailing, 200).is_some());
    }

    #[test]
    fn padding_cut_point_is_the_run_start() {
        let mut v = b"};".to_vec();
        let pad = 300;
        v.extend(std::iter::repeat(b'\t').take(pad));
        v.extend_from_slice(b"evil()");
        let (start, _) = find_padding(&v, 200).unwrap();
        assert_eq!(start, 2);
    }

    /// Does a scan of `data` report the given indicator?
    fn reports(data: &[u8], ioc: &str) -> bool {
        scan(data).iter().any(|h| h.ioc == ioc)
    }

    #[test]
    fn auto_tasks_off_is_not_a_hit() {
        // "off" is the hardened setting; flagging it would punish the fix.
        assert!(!reports(br#""task.allowAutomaticTasks": "off","#, "vscode-allow-autorun"));
        assert!(!reports(br#""task.allowAutomaticTasks": false"#, "vscode-allow-autorun"));
    }

    #[test]
    fn auto_tasks_on_is_a_hit() {
        assert!(reports(br#""task.allowAutomaticTasks": true"#, "vscode-allow-autorun"));
        assert!(reports(br#""task.allowAutomaticTasks": "on""#, "vscode-allow-autorun"));
    }

    #[test]
    fn indexed_pass_finds_the_same_things_a_naive_scan_would() {
        // One representative of each indicator shape in a single buffer.
        let sample = concat!(
            "global.i = 'A8-2941';",
            "0xA322e5f3",
            "X-Payload-B64",
            "/0x/cls",
            "global['!']",
            "parseInt(_0x",
            "AUTH_API_KEY",
            "windowsHide",
        );
        let hits = scan(sample.as_bytes());
        let ids: Vec<&str> = hits.iter().map(|h| h.ioc).collect();
        for want in [
            "global-i-assign",
            "campaign-id",
            "eth-dead-drop-sender",
            "payload-header",
            "stage2-path-cls",
            "global-bang",
            "hex-string-array",
            "auth-api-key",
        ] {
            assert!(ids.contains(&want), "missed {want} in {ids:?}");
        }
    }

    #[test]
    fn hits_come_back_in_file_order() {
        let sample = b"AUTH_API_KEY .... global.i = 'A9-1234';";
        let hits = scan(sample);
        let offsets: Vec<usize> = hits.iter().map(|h| h.start).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn early_exit_still_reports_critical() {
        assert!(has_critical(b"x /0x/cls y"));
        assert!(!has_critical(b"nothing of interest here at all"));
    }

    #[test]
    fn match_at_is_anchored_not_a_search() {
        // "global.i =" is at offset 4, so testing offset 0 must not find it.
        let d = b"xxxxglobal.i = 1";
        assert!(match_at(d, 0, Kind::GlobalIAssign).is_none());
        assert!(match_at(d, 4, Kind::GlobalIAssign).is_some());
    }

    #[test]
    fn the_second_obfuscator_variant_is_recognised() {
        assert!(reports(b"x Cot%3t=shtP y", "obf-marker-v2"));
        assert!(reports(b"var s=1111436;", "shuffle-seed-v2a"));
        assert!(reports(b"global['_V']='8-st4';", "global-v-marker"));
    }

    #[test]
    fn other_chains_are_recognised() {
        assert!(reports(b"TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP", "tron-dead-drop-1"));
        assert!(reports(b"https://api.trongrid.io/v1/accounts", "rpc-tron"));
        assert!(reports(b"bsc-dataseed.binance.org", "rpc-bsc"));
    }

    #[test]
    fn trojanized_packages_are_recognised_in_a_manifest() {
        let manifest = br#"{"dependencies":{"tailwindcss-style-animate":"^1.1.6"}}"#;
        assert!(reports(manifest, "pkg-tailwindcss-style-animate"));
    }

    #[test]
    fn the_tasks_json_http_c2_hosts_are_recognised() {
        assert!(reports(b"https://default-configuration.vercel.app/settings/win?flag=3",
                        "c2-vercel-default-config"));
    }

    #[test]
    fn clean_config_has_no_hits() {
        let ok = b"module.exports = { plugins: { tailwindcss: {} } };\n";
        assert!(!has_critical(ok));
    }

    #[test]
    fn campaign_ids() {
        assert!(reports(b"global.i = 'A9-4221';", "campaign-id"));
        assert!(reports(b"A8-2941", "campaign-id"));
        assert!(!reports(b"A7-1234", "campaign-id"));
        assert!(!reports(b"A9-12", "campaign-id"));
    }

    #[test]
    fn campaign_ids_do_not_match_inside_guids() {
        // Real constants from Windows headers that used to trip this.
        assert!(!reports(b"{9E3A8-1234-4f6a-9c2d-000000000000}", "campaign-id"));
        assert!(!reports(b"0xA8-1234abcd", "campaign-id"));
        assert!(!reports(b"FFA8-2941FF", "campaign-id"));
        // ...but a quoted tag still matches.
        assert!(reports(b"\"A8-2941\"", "campaign-id"));
    }

    #[test]
    fn case_insensitive_address() {
        assert!(has_critical(b"SENDER=\"0xA322E5F3D311D3080e\""));
    }

    #[test]
    fn line_numbers_are_one_based() {
        assert_eq!(line_of(b"a\nb\nc", 0), 1);
        assert_eq!(line_of(b"a\nb\nc", 2), 2);
        assert_eq!(line_of(b"a\nb\nc", 4), 3);
    }
}
