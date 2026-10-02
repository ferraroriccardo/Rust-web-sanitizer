use crate::sanitizer::rules::{ActionMode, Fields, Rules};
use crate::sanitizer::security::suspicious_host;
use crate::sanitizer::status::{ContentStatus, RemovedElement};
use lol_html::Settings;
use lol_html::element;
use lol_html::html_content::ContentType;
use std::cell::RefCell;
use std::rc::Rc;

pub fn apply_action(
    element: &mut lol_html::html_content::Element,
    attr: &str,
    action: ActionMode,
) -> Result<(), String> {
    match action {
        ActionMode::Replace => {
            element.set_attribute(attr, "#").unwrap();
            Ok(())
        }
        ActionMode::Remove => {
            element.remove_attribute(attr);
            Ok(())
        }
        ActionMode::Reject => Err(element.tag_name()),
    }
}

pub fn apply_rule<'a, F, G, H>(
    setting: Settings<'a, 'a>,
    rule_fields: Option<&'a Fields>,
    filter_attr_value_function: F,
    allowlist_blocklist_function: G,
    write_summary: H,
    tag_name: &str,
    summary: Rc<RefCell<ContentStatus>>,
    action: ActionMode,
    reason: String,
) -> Settings<'a, 'a>
where
    F: Fn(&str, &str) -> bool + 'static,
    G: Fn(&String, &Option<Vec<String>>) -> bool + 'static,
    H: Fn(&str, &str, &str, bool) -> String + 'static,
{
    let Some(fields) = rule_fields else {
        return setting;
    };
    setting.append_element_content_handler(element!(tag_name, move |elmt| {
        let mut elements: Vec<String> = Vec::new();
        let mut borrowed_summary = summary.borrow_mut();
        match *borrowed_summary {
            ContentStatus::Accepted(ref mut vec) => {
                let to_remove: Vec<(String, String)> = elmt
                    .attributes()
                    .iter()
                    .filter(|attr| filter_attr_value_function(&attr.name(), &attr.value()))
                    .filter(|attr| allowlist_blocklist_function(&attr.value(), &fields.filters))
                    .map(|attr| (attr.name().to_string(), attr.value().to_string()))
                    .collect();

                let chosen_action = if fields.need_replace {
                    action
                } else {
                    ActionMode::Remove
                };

                let mut reject_occurred = false;
                let mut rejected_string = String::new();
                to_remove.iter().for_each(|(attr, value)| {
                    if !reject_occurred {
                        elements.push(write_summary(
                            elmt.tag_name().as_str(),
                            attr,
                            value,
                            fields.need_replace,
                        ));
                        match apply_action(elmt, attr, chosen_action) {
                            Ok(()) => {}
                            Err(string) => {
                                reject_occurred = true;
                                rejected_string = string;
                            }
                        }
                    }
                });

                if reject_occurred {
                    *borrowed_summary = ContentStatus::Rejected(rejected_string);
                } else if !elements.is_empty() {
                    vec.push(RemovedElement::new(elements.clone(), reason.clone()));
                }
            }
            _ => {}
        }
        Ok(())
    }))
}

pub fn configure_element_rules<'a>(
    mut settings: Settings<'a, 'a>,
    rules: &'a Rules,
    summary: Rc<RefCell<ContentStatus>>,
) -> Settings<'a, 'a> {
    // Iframe
    settings = apply_rule(
        settings,
        rules.iframe.as_ref(),
        |attr, _| attr == "src" || attr == "srcdoc",
        |value, filters| {
            if let Some(allow_list) = filters {
                !allow_list.contains(&value)
            } else {
                true
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => String::from(""),
            false => format!(
                "Removed from tag {} attribute {} with vaule {}",
                tag_name, attr_name, value_name
            ),
        },
        "iframe",
        Rc::clone(&summary),
        ActionMode::Reject,
        String::from("Value not in iframe rule allow-list"),
    );

    // Links (<a>)
    settings = apply_rule(
        settings,
        rules.links.as_ref(),
        |attr, _| attr == "href",
        |value, filters| {
            if suspicious_host(value) {
                return true;
            }
            if let Some(block_list) = filters {
                block_list.iter().any(|blocked| value.contains(blocked))
            } else {
                false
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substitued tag {} attribute {} with vaule #",
                tag_name, attr_name
            ),
            false => format!(
                "Removed from tag {} attribute {} with vaule {}",
                tag_name, attr_name, value_name
            ),
        },
        "a",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("URL blocked as in block-list"),
    );

    // Forms
    settings = apply_rule(
        settings,
        rules.forms.as_ref(),
        |attr, _| attr == "action",
        |value, filters| {
            if suspicious_host(value) {
                return true;
            }
            if let Some(block_list) = filters {
                block_list.iter().any(|blocked| value.contains(blocked))
            } else {
                false
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substitued tag {} attribute {} with vaule #",
                tag_name, attr_name
            ),
            false => format!(
                "Removed from tag {} attribute {} with vaule {}",
                tag_name, attr_name, value_name
            ),
        },
        "form",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Form blocked as in block-list"),
    );

    // Images (<img>)
    settings = apply_rule(
        settings,
        rules.images.as_ref(),
        |attr, _| attr == "src",
        |value, filters| {
            if suspicious_host(value) {
                return true;
            }
            if let Some(block_list) = filters {
                block_list.iter().any(|blocked| value.contains(blocked))
            } else {
                false
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substitued tag {} attribute {} with vaule #",
                tag_name, attr_name
            ),
            false => format!(
                "Removed from tag {} attribute {} with vaule {}",
                tag_name, attr_name, value_name
            ),
        },
        "img",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Image blocked as in block-list"),
    );

    // Styles (<link>)
    settings = apply_rule(
        settings,
        rules.styles.as_ref(),
        |attr, _| attr == "href",
        |value, filters| {
            if suspicious_host(value) {
                return true;
            }
            if let Some(block_list) = filters {
                block_list.iter().any(|blocked| value.contains(blocked))
            } else {
                false
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substitued tag {} attribute {} with vaule #",
                tag_name, attr_name
            ),
            false => format!(
                "Removed from tag {} attribute {} with vaule {}",
                tag_name, attr_name, value_name
            ),
        },
        "link",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Stylesheet blocked as in block-list"),
    );

    // Object
    settings = apply_rule(
        settings,
        rules.object.as_ref(),
        |attr, _| attr == "data",
        |value, filters| {
            if let Some(allow_list) = filters {
                !allow_list.contains(&value)
            } else {
                true
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substituted with # value {} of attribute {} from tag {}",
                value_name, attr_name, tag_name
            ),
            false => format!(
                "Removed from tag {} attribute {} with value {}",
                tag_name, attr_name, value_name
            ),
        },
        "object",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Value not in object rule allow-list"),
    );

    // Embed
    settings = apply_rule(
        settings,
        rules.embed.as_ref(),
        |attr, _| attr == "src",
        |value, filters| {
            if let Some(allow_list) = filters {
                !allow_list.contains(&value)
            } else {
                true
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substituted with # value {} of attribute {} from tag {}",
                value_name, attr_name, tag_name
            ),
            false => format!(
                "Removed from tag {} attribute: {} with value {}",
                tag_name, attr_name, value_name
            ),
        },
        "embed",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Value not in embed rule allow-list"),
    );

    settings
}

pub fn configure_uri_and_event_rules<'a>(
    mut settings: Settings<'a, 'a>,
    rules: &'a Rules,
    summary: Rc<RefCell<ContentStatus>>,
) -> Settings<'a, 'a> {
    // JavaScript URIs
    settings = apply_rule(
        settings,
        rules.javascript_uri.as_ref(),
        |_, value| {
            value
                .split_whitespace()
                .collect::<String>()
                .to_ascii_lowercase()
                .contains("javascript:")
        },
        |_, _| true,
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substituted with # value {} of attribute {} from tag {}",
                value_name, attr_name, tag_name
            ),
            false => format!(
                "Removed tag {} with attribute: {} and value {}",
                tag_name, attr_name, value_name
            ),
        },
        "*",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Neutralized dangerous URLs in attribute"),
    );

    // Data URIs
    settings = apply_rule(
        settings,
        rules.data_uri.as_ref(),
        |_, value| {
            value
                .split_whitespace()
                .collect::<String>()
                .to_ascii_lowercase()
                .contains("data:")
        },
        |value, filters| {
            if let Some(allow_list) = filters {
                !allow_list.contains(&value)
            } else {
                true
            }
        },
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substituted with # value {} of attribute {} from tag {}",
                value_name, attr_name, tag_name
            ),
            false => format!(
                "Removed tag {} with attribute: {} and value {}",
                tag_name, attr_name, value_name
            ),
        },
        "*",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Value not in data rule allow-list"),
    );

    // On-prefix events (onclick, onload, etc.)
    settings = apply_rule(
        settings,
        rules.on_prefix.as_ref(),
        |attr, _| attr.starts_with("on"),
        |_, _| true,
        |tag_name, attr_name, value_name, need_replace| match need_replace {
            true => format!(
                "Substituted with # value {} of attribute {} from tag {}",
                value_name, attr_name, tag_name
            ),
            false => format!(
                "Removed attribute {} from tag {}, which has value {}",
                attr_name, tag_name, value_name
            ),
        },
        "*",
        Rc::clone(&summary),
        ActionMode::Replace,
        String::from("Stripped inline event handler to prevent event-drive script execution"),
    );

    settings
}

pub fn configure_meta_rule<'a>(
    settings: Settings<'a, 'a>,
    meta_fields: Option<&'a Fields>,
    summary: Rc<RefCell<ContentStatus>>,
) -> Settings<'a, 'a> {
    let Some(meta) = meta_fields else {
        return settings;
    };

    settings.append_element_content_handler(element!("meta", move |elmt| {
        let mut borrowed_summary = summary.borrow_mut();
        if let ContentStatus::Accepted(ref mut vec) = *borrowed_summary {
            let is_refresh = elmt
                .get_attribute("http-equiv")
                .map_or(false, |v| v.trim().eq_ignore_ascii_case("refresh"));

            if is_refresh {
                let phrase = if meta.need_replace {
                    elmt.set_tag_name("span").unwrap();
                    String::from("Substituted meta refresh tag with span tag")
                } else {
                    elmt.remove();
                    String::from("Removed meta refresh tag")
                };

                vec.push(RemovedElement::new(
                    vec![phrase],
                    String::from("Disabled automatic client-side redirect directive"),
                ));
            }
        }
        Ok(())
    }))
}

pub fn configure_script_rule<'a>(
    settings: Settings<'a, 'a>,
    script_fields: Option<&'a Fields>,
    summary: Rc<RefCell<ContentStatus>>,
) -> Settings<'a, 'a> {
    let Some(script) = script_fields else {
        return settings;
    };

    settings.append_element_content_handler(element!("script", move |emt| {
        let mut borrowed_summary = summary.borrow_mut();
        if let ContentStatus::Accepted(ref mut vec) = *borrowed_summary {
            let to_remove: Option<(String, String)> = emt
                .attributes()
                .iter()
                .filter(|attr| attr.name() == "src")
                .map(|attr| (attr.name().to_string(), attr.value().to_string()))
                .nth(0);

            let mut phrase = String::new();
            match to_remove {
                Some((attr, value)) => {
                    if let Some(allow_list) = &script.filters {
                        if !allow_list.contains(&value) {
                            if script.need_replace {
                                emt.set_attribute(&attr, "#").unwrap();
                                phrase = format!(
                                    "Substitued value {} from attribute {} of script tag",
                                    value, attr
                                );
                            } else {
                                emt.remove_attribute(&attr);
                                phrase = format!(
                                    "Removed attribute {} with value {} from script tag",
                                    attr, value
                                );
                            }
                        }
                    }
                }
                None => {
                    if script.need_replace {
                        emt.set_inner_content("", ContentType::Html);
                        phrase = String::from("Removed script tag's inner content");
                    } else {
                        emt.remove();
                        phrase = String::from("Removed script tag");
                    }
                }
            }

            if !phrase.is_empty() {
                vec.push(RemovedElement::new(
                    vec![phrase],
                    String::from("Inline script or external source not present in allow-list"),
                ));
            }
        }
        Ok(())
    }))
}
