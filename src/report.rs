//! Output. Human-readable by default, `--json` for anything downstream.

use crate::gitscan::RefHit;
use crate::scanner::Finding;
use crate::signatures::Severity;
use crate::util::{self, BLUE, BOLD, DIM, GREEN, RED, YELLOW};

pub fn print_findings(findings: &[Finding], json: bool) {
    if json {
        println!("{{\"findings\":[");
        for (i, f) in findings.iter().enumerate() {
            let iocs = f
                .hits
                .iter()
                .map(|h| {
                    format!(
                        "{{\"ioc\":\"{}\",\"severity\":\"{}\",\"line\":{},\"offset\":{},\"why\":\"{}\"}}",
                        util::json_escape(h.ioc),
                        if h.sev == Severity::Critical { "critical" } else { "suspicious" },
                        h.line,
                        h.start,
                        util::json_escape(h.why)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let note = match &f.note {
                Some(n) => format!(",\"note\":\"{}\"", util::json_escape(n)),
                None => String::new(),
            };
            println!(
                "  {{\"path\":\"{}\",\"critical\":{},\"indicators\":[{}]{}}}{}",
                util::json_escape(&f.path.to_string_lossy()),
                f.is_critical(),
                iocs,
                note,
                if i + 1 == findings.len() { "" } else { "," }
            );
        }
        println!("]}}");
        return;
    }

    if findings.is_empty() {
        println!("{}", util::c(GREEN, "No PolinRider indicators found."));
        return;
    }

    for f in findings {
        let tag = if f.is_critical() {
            util::c(RED, "INFECTED")
        } else {
            util::c(YELLOW, "SUSPECT ")
        };
        println!("{} {}", tag, util::c(BOLD, &f.path.to_string_lossy()));
        for h in &f.hits {
            let sev = if h.sev == Severity::Critical {
                util::c(RED, "critical")
            } else {
                util::c(YELLOW, "suspicious")
            };
            println!(
                "    {} {:<24} line {:<5} {}",
                sev,
                h.ioc,
                h.line,
                util::c(DIM, h.why)
            );
        }
        if let Some(note) = &f.note {
            println!("    {}", util::c(DIM, &format!("-> {note}")));
        }
    }
}

pub fn print_ref_hits(hits: &[RefHit], json: bool) {
    if json {
        println!("{{\"refs\":[");
        for (i, h) in hits.iter().enumerate() {
            println!(
                "  {{\"repo\":\"{}\",\"ref\":\"{}\",\"file\":\"{}\",\"indicators\":[{}]}}{}",
                util::json_escape(&h.repo.to_string_lossy()),
                util::json_escape(&h.git_ref),
                util::json_escape(&h.file),
                h.iocs
                    .iter()
                    .map(|s| format!("\"{}\"", util::json_escape(s)))
                    .collect::<Vec<_>>()
                    .join(","),
                if i + 1 == hits.len() { "" } else { "," }
            );
        }
        println!("]}}");
        return;
    }
    if hits.is_empty() {
        println!("{}", util::c(GREEN, "No indicators on any ref."));
        return;
    }
    for h in hits {
        println!(
            "{} {} {} :: {}",
            util::c(RED, "INFECTED"),
            util::c(DIM, &h.repo.to_string_lossy()),
            util::c(BOLD, &h.git_ref.replace("refs/", "")),
            h.file
        );
        println!("    {}", util::c(DIM, &h.iocs.join(", ")));
    }
}

pub fn summary_line(found: usize, healed: usize) {
    if found == 0 {
        println!("{}", util::c(GREEN, "clean — nothing found"));
    } else {
        println!(
            "{} {} finding(s), {} healed",
            util::c(BLUE, "summary:"),
            found,
            healed
        );
    }
}
