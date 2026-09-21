//! Output. Human-readable by default, `--json` for anything downstream.

use crate::gitconfig::ConfigHit;
use crate::gitscan::{HistoryHit, RefHit, RemotePlan};
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
        println!("{}", util::c(GREEN, "clean - nothing found"));
    } else {
        println!(
            "{} {} finding(s), {} healed",
            util::c(BLUE, "summary:"),
            found,
            healed
        );
    }
}

pub fn print_config_hits(hits: &[ConfigHit], json: bool) {
    if json {
        println!("{{\"gitconfig\":[");
        for (i, h) in hits.iter().enumerate() {
            println!(
                "  {{\"repo\":\"{}\",\"location\":\"{}\",\"key\":\"{}\",\"value\":\"{}\",\"severity\":\"{}\",\"fixable\":{},\"why\":\"{}\"}}{}",
                util::json_escape(&h.repo.to_string_lossy()),
                util::json_escape(&h.location.to_string_lossy()),
                util::json_escape(&h.key),
                util::json_escape(&h.value),
                if h.sev == Severity::Critical { "critical" } else { "suspicious" },
                h.fixable,
                util::json_escape(h.why),
                if i + 1 == hits.len() { "" } else { "," }
            );
        }
        println!("]}}");
        return;
    }
    for h in hits {
        let tag = if h.sev == Severity::Critical { util::c(RED, "GITCONFIG") } else { util::c(YELLOW, "GITCONFIG") };
        println!("{} {} {} = {}", tag, util::c(DIM, &h.repo.to_string_lossy()), util::c(BOLD, &h.key), h.value);
        println!("    {} {}", util::c(DIM, &h.location.to_string_lossy()), util::c(DIM, h.why));
    }
}

pub fn print_remote_plans(plans: &[RemotePlan], json: bool) {
    if json {
        println!("{{\"remote_fixes\":[");
        for (i, p) in plans.iter().enumerate() {
            println!(
                "  {{\"repo\":\"{}\",\"remote\":\"{}\",\"branch\":\"{}\",\"local_ref\":\"{}\",\"remote_sha\":\"{}\",\"local_sha\":\"{}\",\"infected_files\":[{}],\"blocked\":{}}}{}",
                util::json_escape(&p.repo.to_string_lossy()),
                util::json_escape(&p.remote),
                util::json_escape(&p.branch),
                util::json_escape(&p.local_ref),
                p.remote_sha,
                p.local_sha,
                p.infected_files.iter().map(|f| format!("\"{}\"", util::json_escape(f))).collect::<Vec<_>>().join(","),
                match &p.blocked { Some(b) => format!("\"{}\"", util::json_escape(b)), None => "null".into() },
                if i + 1 == plans.len() { "" } else { "," }
            );
        }
        println!("]}}");
        return;
    }
    for p in plans {
        match &p.blocked {
            None => {
                println!("{} {} {}/{}", util::c(GREEN, "FIXABLE "), util::c(DIM, &p.repo.to_string_lossy()), p.remote, p.branch);
                println!("    remote {} carries {} infected file(s); local {} is clean", &p.remote_sha[..p.remote_sha.len().min(10)], p.infected_files.len(), p.local_ref.trim_start_matches("refs/heads/"));
                println!("    {}", util::c(DIM, &p.command()));
            }
            Some(b) => {
                println!("{} {} {}/{}", util::c(YELLOW, "BLOCKED "), util::c(DIM, &p.repo.to_string_lossy()), p.remote, p.branch);
                println!("    {}", b);
            }
        }
    }
}

/// Payload blobs still reachable in history, and how to purge them.
///
/// Grouped by repository, because the purge is a per-repository operation and
/// the command that does it takes the whole list of object ids at once.
pub fn print_history_hits(hits: &[HistoryHit], json: bool) {
    if json {
        println!("{{\"history\":[");
        for (i, h) in hits.iter().enumerate() {
            println!(
                "  {{\"repo\":\"{}\",\"blob\":\"{}\",\"path\":\"{}\",\"size\":{},\"indicators\":[{}]}}{}",
                util::json_escape(&h.repo.to_string_lossy()),
                util::json_escape(&h.blob),
                util::json_escape(&h.path),
                h.size,
                h.iocs.iter().map(|s| format!("\"{}\"", util::json_escape(s))).collect::<Vec<_>>().join(","),
                if i + 1 == hits.len() { "" } else { "," }
            );
        }
        println!("]}}");
        return;
    }
    if hits.is_empty() {
        println!("{}", util::c(GREEN, "No payload left anywhere in history."));
        return;
    }
    let mut repos: Vec<&std::path::Path> = hits.iter().map(|h| h.repo.as_path()).collect();
    repos.sort();
    repos.dedup();
    for repo in repos {
        let mine: Vec<&HistoryHit> = hits.iter().filter(|h| h.repo == repo).collect();
        println!("{} {}", util::c(RED, "IN HISTORY"), util::c(DIM, &repo.to_string_lossy()));
        for h in &mine {
            println!("    {} {:>9} B  {}", util::c(BOLD, &h.blob[..12.min(h.blob.len())]), h.size, h.path);
            println!("        {}", util::c(DIM, &h.iocs.join(", ")));
            let commits = crate::gitscan::commits_holding_blob(repo, &h.blob, 4);
            for c in commits {
                println!("        {} {}", util::c(DIM, "in"), util::c(DIM, &c));
            }
        }
        println!();
        println!("    {}", util::c(YELLOW, "These are not on any branch tip - they are older commits. Nothing runs them"));
        println!("    {}", util::c(YELLOW, "unless someone checks out that commit, but anyone with the repository can"));
        println!("    {}", util::c(YELLOW, "read them by object id. To purge (rewrites every commit id; everyone must"));
        println!("    {}", util::c(YELLOW, "re-clone afterwards, and GitHub keeps unreachable objects until its own GC):"));
        println!();
        // Write the id list ourselves rather than printing a shell one-liner to
        // retype. `filter-repo` wants a file, the list is long, and a command
        // the reader has to assemble by hand at 2am is a command that gets
        // assembled wrong.
        let ids: Vec<&str> = mine.iter().map(|h| h.blob.as_str()).collect();
        let list = blob_id_file(repo, &ids);
        println!("      cd {}", repo.display());
        match &list {
            Ok(p) => println!("      git filter-repo --strip-blobs-with-ids {} --force", p.display()),
            Err(_) => {
                println!("      # could not write the id list; put these ids in a file, one per line:");
                for id in &ids {
                    println!("      #   {id}");
                }
                println!("      git filter-repo --strip-blobs-with-ids <that-file> --force");
            }
        }
        println!("      git push --force --all && git push --force --tags");
        if let Ok(p) = &list {
            println!();
            println!("    {} {}", util::c(DIM, "id list written to"), util::c(DIM, &p.display().to_string()));
        }
        println!();
    }
}

/// Write the blob ids to purge into the state directory, one per line.
///
/// Named after the repository so auditing several in one run does not have each
/// overwrite the last.
fn blob_id_file(repo: &std::path::Path, ids: &[&str]) -> std::io::Result<std::path::PathBuf> {
    let stem = repo.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "repo".to_string());
    let safe: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let dir = crate::config::home().join("purge");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{safe}-blobs.txt"));
    let mut out = String::new();
    for id in ids {
        out.push_str(id);
        out.push('\n');
    }
    std::fs::write(&path, out)?;
    Ok(path)
}
