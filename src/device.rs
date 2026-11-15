//! Short, readable names for user agents: "iPhone · Safari", "curl".

/// Words that give away scripts, crawlers and scanners.
const BOT_WORDS: &[&str] = &[
    "bot",
    "crawl",
    "spider",
    "slurp",
    "scan",
    "curl",
    "wget",
    "python",
    "go-http",
    "java/",
    "zgrab",
    "masscan",
    "nmap",
    "httpclient",
    "okhttp",
    "libwww",
    "headless",
    "axios",
    "node-fetch",
    "censys",
    "facebookexternalhit",
    "preview",
    "monitor",
    "uptime",
];

/// True for anything that is not an ordinary browser.
pub fn is_bot(user_agent: &str) -> bool {
    let ua = user_agent.to_ascii_lowercase();
    !ua.starts_with("mozilla/") || BOT_WORDS.iter().any(|w| ua.contains(w))
}

pub fn describe(user_agent: &str) -> String {
    let ua = user_agent.to_ascii_lowercase();
    if ua.is_empty() || ua == "-" {
        return "Unknown".into();
    }
    let tool = [
        ("curl", "curl"),
        ("wget", "wget"),
        ("python", "Python script"),
        ("go-http", "Go program"),
        ("bot", "Bot"),
        ("crawl", "Bot"),
        ("spider", "Bot"),
    ]
    .into_iter()
    .find(|(word, _)| ua.contains(word));
    if let Some((_, name)) = tool {
        return name.into();
    }

    let system = [
        ("iphone", "iPhone"),
        ("ipad", "iPad"),
        ("android", "Android"),
        ("windows", "Windows"),
        ("cros", "Chromebook"),
        ("macintosh", "Mac"),
        ("linux", "Linux"),
    ]
    .into_iter()
    .find(|(word, _)| ua.contains(word))
    .map(|(_, name)| name);
    // Order matters: Edge and Opera also say Chrome, Chrome also says Safari.
    let browser = [
        ("edg/", "Edge"),
        ("opr/", "Opera"),
        ("firefox/", "Firefox"),
        ("fxios", "Firefox"),
        ("crios", "Chrome"),
        ("chrome/", "Chrome"),
        ("safari/", "Safari"),
    ]
    .into_iter()
    .find(|(word, _)| ua.contains(word))
    .map(|(_, name)| name);

    match (system, browser) {
        (Some(s), Some(b)) => format!("{s} · {b}"),
        (Some(s), None) => s.into(),
        (None, Some(b)) => b.into(),
        (None, None) => "Other".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_common_devices() {
        let cases = [
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
                "iPhone · Safari",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0",
                "Windows · Edge",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
                "Linux · Firefox",
            ),
            (
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
                "Android · Chrome",
            ),
            ("curl/8.5.0", "curl"),
            ("-", "Unknown"),
        ];
        for (ua, expected) in cases {
            assert_eq!(describe(ua), expected, "{ua}");
        }
    }

    #[test]
    fn tells_browsers_from_bots() {
        assert!(!is_bot(
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
        ));
        assert!(is_bot("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(is_bot("Mozilla/5.0 zgrab/0.x"));
        assert!(is_bot("python-requests/2.32.3"));
        assert!(is_bot("-"));
    }
}
