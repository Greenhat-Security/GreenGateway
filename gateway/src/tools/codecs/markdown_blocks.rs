use std::ops::Range;

use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde_json::{json, Map, Value};

use super::{CodecError, MarkdownDialect};

pub fn encode(
    value: Value,
    dialect: MarkdownDialect,
    max_input_bytes: usize,
) -> Result<Value, CodecError> {
    if !(1..=262_144).contains(&max_input_bytes) {
        return Err(CodecError::new(
            "Markdown input limit must be between 1 and 262144 bytes",
        ));
    }
    let Value::String(markdown) = value else {
        return Err(CodecError::new("agent value must be a Markdown string"));
    };
    if markdown.len() > max_input_bytes {
        return Err(CodecError::new(format!(
            "Markdown input exceeds the configured {max_input_bytes}-byte limit"
        )));
    }
    match dialect {
        MarkdownDialect::Blocknote => blocknote(&markdown),
    }
}

#[derive(Default)]
struct InlineStyles {
    bold: bool,
    italic: bool,
    code: bool,
}

enum Frame {
    Document(Vec<Value>),
    Paragraph(Vec<Value>),
    Heading {
        level: u8,
        content: Vec<Value>,
    },
    List {
        ordered: bool,
        items: Vec<Value>,
    },
    Item {
        content: Option<Vec<Value>>,
        children: Vec<Value>,
    },
}

struct ActiveLink {
    href: String,
    content: Vec<Value>,
}

fn blocknote(markdown: &str) -> Result<Value, CodecError> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS;
    let parser = Parser::new_ext(markdown, options).into_offset_iter();
    let mut frames = vec![Frame::Document(Vec::new())];
    let mut styles = InlineStyles::default();
    let mut link: Option<ActiveLink> = None;

    for (event, range) in parser {
        let line = source_line(markdown, &range);
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => frames.push(Frame::Paragraph(Vec::new())),
                Tag::Heading { level, .. } => {
                    let level = heading_level(level).ok_or_else(|| unsupported("heading", line))?;
                    frames.push(Frame::Heading {
                        level,
                        content: Vec::new(),
                    });
                }
                Tag::List(start) => frames.push(Frame::List {
                    ordered: start.is_some(),
                    items: Vec::new(),
                }),
                Tag::Item => frames.push(Frame::Item {
                    content: None,
                    children: Vec::new(),
                }),
                Tag::Emphasis => styles.italic = true,
                Tag::Strong => styles.bold = true,
                Tag::Link { dest_url, .. } => {
                    if link.is_some() {
                        return Err(unsupported("nested link", line));
                    }
                    link = Some(ActiveLink {
                        href: dest_url.into_string(),
                        content: Vec::new(),
                    });
                }
                Tag::Image { .. } => return Err(unsupported("image", line)),
                Tag::CodeBlock(_) => return Err(unsupported("code block", line)),
                Tag::BlockQuote(_) => return Err(unsupported("block quote", line)),
                Tag::HtmlBlock => return Err(unsupported("HTML block", line)),
                Tag::FootnoteDefinition(_) => return Err(unsupported("footnote", line)),
                Tag::Table(_) | Tag::TableHead | Tag::TableRow | Tag::TableCell => {
                    return Err(unsupported("table", line));
                }
                Tag::Strikethrough => return Err(unsupported("strikethrough", line)),
                _ => return Err(unsupported("Markdown construct", line)),
            },
            Event::End(tag) => match tag {
                TagEnd::Paragraph => close_paragraph(&mut frames, line)?,
                TagEnd::Heading(_) => close_heading(&mut frames, line)?,
                TagEnd::List(_) => close_list(&mut frames, line)?,
                TagEnd::Item => close_item(&mut frames, line)?,
                TagEnd::Emphasis => styles.italic = false,
                TagEnd::Strong => styles.bold = false,
                TagEnd::Link => {
                    let Some(active) = link.take() else {
                        return Err(invalid_markdown("link close without a link", line));
                    };
                    push_inline(
                        &mut frames,
                        json!({
                            "type": "link",
                            "href": active.href,
                            "content": active.content,
                        }),
                        line,
                    )?;
                }
                _ => return Err(unsupported("Markdown construct", line)),
            },
            Event::Text(text) => push_text(&mut frames, &mut link, &styles, text.as_ref(), line)?,
            Event::Code(text) => {
                let previous = styles.code;
                styles.code = true;
                push_text(&mut frames, &mut link, &styles, text.as_ref(), line)?;
                styles.code = previous;
            }
            Event::SoftBreak | Event::HardBreak => {
                push_text(&mut frames, &mut link, &styles, "\n", line)?;
            }
            Event::Rule => return Err(unsupported("thematic break", line)),
            Event::Html(_) | Event::InlineHtml(_) => return Err(unsupported("HTML", line)),
            Event::FootnoteReference(_) => return Err(unsupported("footnote", line)),
            Event::TaskListMarker(_) => return Err(unsupported("task list", line)),
            _ => return Err(unsupported("Markdown construct", line)),
        }
    }

    if link.is_some() || frames.len() != 1 {
        return Err(CodecError::new(
            "Markdown document ended inside a construct",
        ));
    }
    let Frame::Document(mut blocks) = frames.pop().expect("document frame exists") else {
        unreachable!("the only remaining frame is the document")
    };
    if blocks.is_empty() {
        blocks.push(block(
            "paragraph",
            paragraph_props(),
            Vec::new(),
            Vec::new(),
        ));
    }
    Ok(Value::Array(blocks))
}

fn push_text(
    frames: &mut [Frame],
    link: &mut Option<ActiveLink>,
    styles: &InlineStyles,
    text: &str,
    line: usize,
) -> Result<(), CodecError> {
    if text.is_empty() {
        return Ok(());
    }
    let mut style_value = Map::new();
    if styles.bold {
        style_value.insert("bold".to_owned(), Value::Bool(true));
    }
    if styles.italic {
        style_value.insert("italic".to_owned(), Value::Bool(true));
    }
    if styles.code {
        style_value.insert("code".to_owned(), Value::Bool(true));
    }
    let value = json!({
        "type": "text",
        "text": text,
        "styles": style_value,
    });
    if let Some(link) = link {
        push_or_merge_text(&mut link.content, value);
        Ok(())
    } else {
        let content = inline_content_mut(frames, line)?;
        push_or_merge_text(content, value);
        Ok(())
    }
}

fn push_or_merge_text(content: &mut Vec<Value>, value: Value) {
    let styles = value.get("styles");
    if let Some(last) = content.last_mut() {
        if last.get("type").and_then(Value::as_str) == Some("text") && last.get("styles") == styles
        {
            if let (Some(existing), Some(addition)) = (
                last.get("text").and_then(Value::as_str).map(str::to_owned),
                value.get("text").and_then(Value::as_str),
            ) {
                last["text"] = Value::String(existing + addition);
                return;
            }
        }
    }
    content.push(value);
}

fn push_inline(frames: &mut [Frame], value: Value, line: usize) -> Result<(), CodecError> {
    inline_content_mut(frames, line)?.push(value);
    Ok(())
}

fn inline_content_mut(frames: &mut [Frame], line: usize) -> Result<&mut Vec<Value>, CodecError> {
    match frames.last_mut() {
        Some(Frame::Paragraph(content) | Frame::Heading { content, .. }) => Ok(content),
        Some(Frame::Item { content, .. }) => Ok(content.get_or_insert_with(Vec::new)),
        _ => Err(invalid_markdown("inline content outside a paragraph", line)),
    }
}

fn close_paragraph(frames: &mut Vec<Frame>, line: usize) -> Result<(), CodecError> {
    let Some(Frame::Paragraph(content)) = frames.pop() else {
        return Err(invalid_markdown(
            "paragraph close without a paragraph",
            line,
        ));
    };
    match frames.last_mut() {
        Some(Frame::Document(blocks)) => {
            blocks.push(block("paragraph", paragraph_props(), content, Vec::new()));
            Ok(())
        }
        Some(Frame::Item {
            content: item_content,
            ..
        }) if item_content.is_none() => {
            *item_content = Some(content);
            Ok(())
        }
        Some(Frame::Item { .. }) => Err(unsupported("multi-paragraph list item", line)),
        _ => Err(invalid_markdown("paragraph has an invalid parent", line)),
    }
}

fn close_heading(frames: &mut Vec<Frame>, line: usize) -> Result<(), CodecError> {
    let Some(Frame::Heading { level, content }) = frames.pop() else {
        return Err(invalid_markdown("heading close without a heading", line));
    };
    let Some(Frame::Document(blocks)) = frames.last_mut() else {
        return Err(unsupported("heading inside a list", line));
    };
    let mut props = paragraph_props();
    props.insert("level".to_owned(), Value::from(level));
    blocks.push(block("heading", props, content, Vec::new()));
    Ok(())
}

fn close_list(frames: &mut Vec<Frame>, line: usize) -> Result<(), CodecError> {
    let Some(Frame::List { items, .. }) = frames.pop() else {
        return Err(invalid_markdown("list close without a list", line));
    };
    match frames.last_mut() {
        Some(Frame::Document(blocks)) => {
            blocks.extend(items);
            Ok(())
        }
        Some(Frame::Item { children, .. }) => {
            children.extend(items);
            Ok(())
        }
        _ => Err(invalid_markdown("list has an invalid parent", line)),
    }
}

fn close_item(frames: &mut Vec<Frame>, line: usize) -> Result<(), CodecError> {
    let Some(Frame::Item { content, children }) = frames.pop() else {
        return Err(invalid_markdown("list item close without an item", line));
    };
    let Some(Frame::List { ordered, items }) = frames.last_mut() else {
        return Err(invalid_markdown("list item has no list parent", line));
    };
    items.push(block(
        if *ordered {
            "numberedListItem"
        } else {
            "bulletListItem"
        },
        paragraph_props(),
        content.unwrap_or_default(),
        children,
    ));
    Ok(())
}

fn block(
    kind: &str,
    props: Map<String, Value>,
    content: Vec<Value>,
    children: Vec<Value>,
) -> Value {
    json!({
        "type": kind,
        "props": props,
        "content": content,
        "children": children,
    })
}

fn paragraph_props() -> Map<String, Value> {
    Map::from_iter([
        ("textColor".to_owned(), Value::String("default".to_owned())),
        (
            "backgroundColor".to_owned(),
            Value::String("default".to_owned()),
        ),
        ("textAlignment".to_owned(), Value::String("left".to_owned())),
    ])
}

fn heading_level(level: HeadingLevel) -> Option<u8> {
    match level {
        HeadingLevel::H1 => Some(1),
        HeadingLevel::H2 => Some(2),
        HeadingLevel::H3 => Some(3),
        HeadingLevel::H4 | HeadingLevel::H5 | HeadingLevel::H6 => None,
    }
}

fn source_line(source: &str, range: &Range<usize>) -> usize {
    source
        .as_bytes()
        .iter()
        .take(range.start)
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn unsupported(construct: &str, line: usize) -> CodecError {
    CodecError::new(format!(
        "unsupported Markdown construct '{construct}' at line {line}"
    ))
}

fn invalid_markdown(reason: &str, line: usize) -> CodecError {
    CodecError::new(format!(
        "invalid Markdown structure at line {line}: {reason}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_blocknote_fixture_covers_the_supported_subset() {
        let markdown = "# Account\n\nA **bold** and *italic* [link](https://example.test) with `code`.\n\n- first\n- second\n\n1. one\n2. two";
        let first = encode(
            Value::String(markdown.to_owned()),
            MarkdownDialect::Blocknote,
            65_536,
        )
        .expect("supported Markdown should encode");
        let second = encode(
            Value::String(markdown.to_owned()),
            MarkdownDialect::Blocknote,
            65_536,
        )
        .expect("encoding should be repeatable");
        assert_eq!(first, second);
        let blocks = first.as_array().expect("BlockNote is an array");
        assert_eq!(blocks[0]["type"], "heading");
        assert_eq!(blocks[0]["props"]["level"], 1);
        assert_eq!(blocks[2]["type"], "bulletListItem");
        assert_eq!(blocks[4]["type"], "numberedListItem");
        assert!(blocks.iter().all(|block| block.get("id").is_none()));
    }

    #[test]
    fn unsupported_markdown_names_the_construct_and_one_based_line() {
        let error = encode(
            Value::String("paragraph\n\n![alt](image.png)".to_owned()),
            MarkdownDialect::Blocknote,
            65_536,
        )
        .expect_err("images are outside the supported subset");
        assert_eq!(
            error.reason,
            "unsupported Markdown construct 'image' at line 3"
        );
    }

    #[test]
    fn nested_lists_become_children() {
        let value = encode(
            Value::String("- parent\n  - child".to_owned()),
            MarkdownDialect::Blocknote,
            65_536,
        )
        .expect("nested lists are supported");
        assert_eq!(value[0]["type"], "bulletListItem");
        assert_eq!(value[0]["children"][0]["type"], "bulletListItem");
    }

    #[test]
    fn input_and_configuration_limits_are_enforced_before_parsing() {
        assert!(encode(
            Value::String("ok".to_owned()),
            MarkdownDialect::Blocknote,
            0,
        )
        .is_err());
        assert!(encode(
            Value::String("too long".to_owned()),
            MarkdownDialect::Blocknote,
            3,
        )
        .is_err());
    }
}
