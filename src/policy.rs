//! Pure lookup classification. Network calls happen after this returns
//! a `Step::Decide`.

use chrono::{DateTime, Datelike, Local, Timelike};

use crate::model::{CompiledList, CompiledRule, FailMode, Snapshot};
use crate::names::{self, Pattern};

#[derive(Debug, Clone)]
pub struct QueryContext {
    pub domain: String,
    pub qtype: String,
    pub device_ip: String,
    pub profile: String,
    pub now: DateTime<Local>,
}

impl QueryContext {
    pub fn new(domain: &str, qtype: &str, device_ip: &str, profile: &str) -> Self {
        Self {
            domain: names::normalize_name(domain),
            qtype: qtype.to_ascii_uppercase(),
            device_ip: device_ip.to_string(),
            profile: if profile.is_empty() {
                "standard".into()
            } else {
                profile.to_string()
            },
            now: Local::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    Allow {
        reason: String,
    },
    Block {
        reason: String,
        rule_id: Option<i64>,
    },
    Decide {
        rule: CompiledRule,
    },
}

pub fn classify(snap: &Snapshot, ctx: &QueryContext) -> Step {
    if let Some(hit) = find_list(&snap.allowlist, &ctx.domain) {
        return Step::Allow {
            reason: format!("allowlist {}", hit.pattern),
        };
    }
    if let Some(hit) = find_list(&snap.blocklist, &ctx.domain) {
        return Step::Block {
            reason: format!("blocklist {}", hit.pattern),
            rule_id: None,
        };
    }
    if names::is_infrastructure(&ctx.domain) {
        return Step::Allow {
            reason: "infrastructure name".into(),
        };
    }

    let mut ordered: Vec<&CompiledRule> = snap.rules.iter().collect();
    ordered.sort_by_key(|rule| (rule.rule.priority, rule.rule.id));
    for compiled in ordered {
        let rule = &compiled.rule;
        if !rule.enabled || !rule_matches(rule, &compiled.pattern, ctx) {
            continue;
        }
        match rule.action.as_str() {
            "allow" => {
                return Step::Allow {
                    reason: format!("rule {}", rule.name),
                };
            }
            "block" => {
                return Step::Block {
                    reason: format!("rule {}", rule.name),
                    rule_id: Some(rule.id),
                };
            }
            "decide" => {
                let ready = rule.service_id.and_then(|id| snap.service(id)).is_some_and(|s| s.enabled);
                if ready {
                    return Step::Decide {
                        rule: (*compiled).clone(),
                    };
                }
                // Service missing or disabled: skip so a later rule can still match.
                continue;
            }
            _ => continue,
        }
    }

    Step::Allow {
        reason: "default".into(),
    }
}

fn find_list<'a>(list: &'a [CompiledList], domain: &str) -> Option<&'a CompiledList> {
    list.iter().find(|e| names::matches(&e.compiled, domain))
}

fn rule_matches(rule: &crate::model::Rule, pattern: &Pattern, ctx: &QueryContext) -> bool {
    if !rule.device_ip.is_empty() && rule.device_ip != ctx.device_ip {
        return false;
    }
    if rule.profile != "any" && rule.profile != ctx.profile {
        return false;
    }
    if !names::matches(pattern, &ctx.domain) {
        return false;
    }
    schedule_active(rule, ctx.now)
}

fn schedule_active(rule: &crate::model::Rule, now: DateTime<Local>) -> bool {
    if rule.days_mask != 0 && rule.days_mask != 0b111_1111 {
        let bit = 1u8 << now.weekday().num_days_from_sunday();
        if rule.days_mask & bit == 0 {
            return false;
        }
    }
    match (rule.hour_start, rule.hour_end) {
        (Some(start), Some(end)) if start != end => {
            let hour = now.hour() as u8;
            if start < end {
                hour >= start && hour < end
            } else {
                hour >= start || hour < end
            }
        }
        _ => true,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub block: bool,
    pub reason: String,
}

pub fn interpret(rule: &crate::model::Rule, answers: &serde_json::Map<String, serde_json::Value>) -> Verdict {
    if let Some(obj) = rule.block_choices.as_object() {
        for (qid, blocked_vals) in obj {
            let Some(answer) = answers.get(qid) else {
                continue;
            };
            let choice = answer.get("choice").and_then(|v| v.as_str()).unwrap_or("");
            if choice.is_empty() {
                continue;
            }
            let blocked = string_list(blocked_vals);
            if !blocked.iter().any(|b| b == choice) {
                continue;
            }
            let confidence = answer.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0);
            let detail = format!("{qid}={choice} confidence={confidence:.2}");
            if confidence < rule.min_confidence {
                return uncertain(rule, &detail);
            }
            return Verdict {
                block: true,
                reason: detail,
            };
        }
    }

    if !rule.score_question.is_empty() {
        if let Some(answer) = answers.get(&rule.score_question) {
            let score = answer.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if score >= rule.score_threshold {
                let confidence = answer.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0);
                let detail = format!(
                    "{} score={score:.2} >= {:.2} confidence={confidence:.2}",
                    rule.score_question, rule.score_threshold
                );
                if confidence < rule.min_confidence {
                    return uncertain(rule, &detail);
                }
                return Verdict {
                    block: true,
                    reason: detail,
                };
            }
        }
    }

    if !rule.noul_question.is_empty() {
        if let Some(answer) = answers.get(&rule.noul_question) {
            let noul = answer
                .get("noul")
                .and_then(|v| v.as_f64())
                .or_else(|| answer.as_f64())
                .unwrap_or(0.0);
            if noul >= rule.noul_threshold {
                return Verdict {
                    block: true,
                    reason: format!(
                        "{}={noul:.2} >= {:.2}",
                        rule.noul_question, rule.noul_threshold
                    ),
                };
            }
        }
    }

    Verdict {
        block: false,
        reason: "decision allowed".into(),
    }
}

fn uncertain(rule: &crate::model::Rule, detail: &str) -> Verdict {
    Verdict {
        block: rule.on_uncertain == FailMode::Block,
        reason: format!("uncertain: {detail}"),
    }
}

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BlockMode, Device, FailMode, Rule, Service, Settings};
    use crate::names::parse_pattern;
    use serde_json::json;

    fn rule(action: &str, profile: &str, pattern: &str, priority: i64) -> CompiledRule {
        CompiledRule {
            pattern: parse_pattern(pattern).unwrap(),
            rule: Rule {
                id: priority,
                name: format!("{action}-{priority}"),
                enabled: true,
                priority,
                profile: profile.into(),
                device_ip: String::new(),
                domain_pattern: pattern.into(),
                action: action.into(),
                service_id: Some(1),
                questions: json!({}),
                noul_question: "unsafe_for_children".into(),
                noul_threshold: 0.8,
                score_question: String::new(),
                score_threshold: 2.0,
                block_choices: json!({"category": ["adult", "malware"]}),
                min_confidence: 0.55,
                on_uncertain: FailMode::Allow,
                on_error: FailMode::Allow,
                hour_start: None,
                hour_end: None,
                days_mask: 0,
                comment: String::new(),
            },
        }
    }

    fn snap(rules: Vec<CompiledRule>, block: &[&str], allow: &[&str]) -> Snapshot {
        let list = |kind: &str, items: &[&str]| -> Vec<CompiledList> {
            items
                .iter()
                .enumerate()
                .map(|(i, p)| CompiledList {
                    id: i as i64,
                    kind: kind.into(),
                    pattern: (*p).into(),
                    compiled: parse_pattern(p).unwrap(),
                    comment: String::new(),
                })
                .collect()
        };
        Snapshot {
            settings: Settings {
                block_mode: BlockMode::Sinkhole,
                ..Settings::default()
            },
            devices: vec![Device {
                id: 1,
                ip: "192.168.1.20".into(),
                name: "kid".into(),
                profile: "child".into(),
                notes: String::new(),
                first_seen: 0,
                last_seen: 0,
            }],
            services: vec![Service {
                id: 1,
                name: "jev".into(),
                kind: "jev".into(),
                base_url: "https://api.typesafe.ai".into(),
                model: "jev-latest".into(),
                timeout_ms: 1000,
                enabled: true,
                has_api_key: true,
                key_hint: String::new(),
                api_key: "secret".into(),
            }],
            rules,
            allowlist: list("allow", allow),
            blocklist: list("block", block),
            warnings: vec![],
        }
    }

    fn ctx(profile: &str, domain: &str) -> QueryContext {
        QueryContext::new(domain, "A", "192.168.1.20", profile)
    }

    #[test]
    fn allowlist_beats_blocklist_and_rules() {
        let snap = snap(
            vec![rule("block", "any", "*", 1)],
            &["example.com"],
            &["safe.example.com"],
        );
        match classify(&snap, &ctx("child", "safe.example.com")) {
            Step::Allow { reason } => assert!(reason.contains("allowlist")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn blocklist_and_child_rule_and_default() {
        let snap = snap(vec![rule("decide", "child", "*", 10)], &["ads.example"], &[]);
        match classify(&snap, &ctx("standard", "ads.example")) {
            Step::Block { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        match classify(&snap, &ctx("child", "news.example")) {
            Step::Decide { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        match classify(&snap, &ctx("standard", "news.example")) {
            Step::Allow { reason } => assert_eq!(reason, "default"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn infrastructure_skips_decide_rules() {
        let snap = snap(vec![rule("decide", "any", "*", 10)], &[], &[]);
        match classify(&snap, &ctx("child", "1.0.0.127.in-addr.arpa")) {
            Step::Allow { reason } => assert!(reason.contains("infrastructure")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn interpret_noul_choice_and_low_confidence() {
        let compiled = rule("decide", "child", "*", 1);
        let rule = &compiled.rule;
        let blocked = interpret(
            rule,
            json!({"unsafe_for_children": {"type": "noul", "noul": 0.91}})
                .as_object()
                .unwrap(),
        );
        assert!(blocked.block);

        let choice = interpret(
            rule,
            json!({"category": {"type": "choice", "choice": "adult", "confidence": 0.9}})
                .as_object()
                .unwrap(),
        );
        assert!(choice.block);

        let unsure = interpret(
            rule,
            json!({"category": {"type": "choice", "choice": "adult", "confidence": 0.2}})
                .as_object()
                .unwrap(),
        );
        assert!(!unsure.block);
        assert!(unsure.reason.contains("uncertain"));

        let allowed = interpret(
            rule,
            json!({
                "unsafe_for_children": {"type": "noul", "noul": 0.1},
                "category": {"type": "choice", "choice": "safe", "confidence": 0.8}
            })
            .as_object()
            .unwrap(),
        );
        assert!(!allowed.block);
    }

    #[test]
    fn lower_priority_number_wins() {
        let mut first = rule("allow", "any", "*", 5);
        first.rule.name = "allow-all".into();
        let mut second = rule("block", "any", "*", 50);
        second.rule.name = "block-all".into();
        let snap = snap(vec![second, first], &[], &[]);
        match classify(&snap, &ctx("child", "example.com")) {
            Step::Allow { reason } => assert!(reason.contains("allow-all")),
            other => panic!("unexpected {other:?}"),
        }
    }

}
