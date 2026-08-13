//! Deterministic natural-language templates for generated OKF prose.

use repo2okf_core::OutputLocale;

pub(crate) const fn relationships_heading(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Relationships",
        OutputLocale::Ja => "関係",
    }
}

pub(crate) const fn claims_heading(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Evidence-bound claims",
        OutputLocale::Ja => "証拠に紐づく主張",
    }
}

pub(crate) const fn coverage_heading(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Coverage",
        OutputLocale::Ja => "カバレッジ",
    }
}

pub(crate) const fn repository_knowledge_title(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Repository knowledge",
        OutputLocale::Ja => "リポジトリの情報",
    }
}

pub(crate) const fn root_package_title(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Repository root package",
        OutputLocale::Ja => "リポジトリのルートパッケージ",
    }
}

pub(crate) fn coverage_description(locale: OutputLocale, subject: &str) -> String {
    match locale {
        OutputLocale::En => format!("Repository knowledge extracted from {subject}."),
        OutputLocale::Ja => format!("{subject} から抽出したリポジトリの情報です。"),
    }
}

pub(crate) fn python_description(locale: OutputLocale, path: &str, package: bool) -> String {
    match (locale, package) {
        (OutputLocale::En, true) => format!("Python Package defined by {path}."),
        (OutputLocale::En, false) => format!("Python Module defined by {path}."),
        (OutputLocale::Ja, true) => format!("{path} で定義されている Python パッケージです。"),
        (OutputLocale::Ja, false) => format!("{path} で定義されている Python モジュールです。"),
    }
}

pub(crate) fn fallback_claim_title(locale: OutputLocale, claim_id: &str) -> String {
    match locale {
        OutputLocale::En => format!("Claim {claim_id}"),
        OutputLocale::Ja => format!("主張 {claim_id}"),
    }
}

pub(crate) const fn fallback_claim_description(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Evidence-bound repository knowledge claim.",
        OutputLocale::Ja => "証拠に紐づいたリポジトリに関する記述です。",
    }
}

pub(crate) fn external_module_description(locale: OutputLocale, specifier: &str) -> String {
    match locale {
        OutputLocale::En => format!("External module imported as {specifier}."),
        OutputLocale::Ja => format!("インポートされている外部モジュール {specifier} です。"),
    }
}

pub(crate) fn source_title(locale: OutputLocale, symbol: Option<&str>, path: &str) -> String {
    match (locale, symbol) {
        (OutputLocale::En, Some(symbol)) => format!("{symbol} in {path}"),
        (OutputLocale::Ja, Some(symbol)) => format!("{path} 内の {symbol}"),
        (_, None) => path.to_owned(),
    }
}

pub(crate) fn evidence_title(locale: OutputLocale, evidence_id: &str) -> String {
    match locale {
        OutputLocale::En => format!("Source evidence {evidence_id}"),
        OutputLocale::Ja => format!("ソース上の証拠 {evidence_id}"),
    }
}

pub(crate) const fn included_label(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Included",
        OutputLocale::Ja => "収録済み",
    }
}

pub(crate) const fn excluded_label(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Excluded",
        OutputLocale::Ja => "除外",
    }
}

pub(crate) const fn unresolved_label(locale: OutputLocale) -> &'static str {
    match locale {
        OutputLocale::En => "Unresolved",
        OutputLocale::Ja => "未解決",
    }
}
