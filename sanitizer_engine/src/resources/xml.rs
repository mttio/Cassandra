use crate::{errors::RuleError, log::Log, policy::Policy};

#[derive(Debug)]
pub struct XmlReader {
    length: usize,
    buffer: Vec<u8>,
    is_backslash: bool,
    previous_is_entity: bool,
}

enum FeedOutput {
    Continue,
    StartTag,
    EndTag,
    Cancel,
}

impl XmlReader {
    pub fn new(length: usize) -> Self {
        Self {
            length,
            buffer: Vec::new(),
            is_backslash: false,
            previous_is_entity: false,
        }
    }

    /// Process a byte, returns true if b"<!ENTITY" (case-insensitive) is matched
    fn feed(&mut self, b: u8) -> FeedOutput {
        let target = b"<!ENTITY";
        if self.previous_is_entity
            && let Some(target_char) = target.get(self.buffer.len())
            && b.eq_ignore_ascii_case(target_char)
        {
            FeedOutput::Continue
        } else {
            if b == b'<' && (!self.previous_is_entity || self.buffer.len() < target.len()) {
                FeedOutput::StartTag
            } else if b == b'>' && !self.is_backslash && self.buffer.len() >= target.len() {
                FeedOutput::EndTag
            } else {
                if b == b'\\' {
                    self.is_backslash = !self.is_backslash;
                } else {
                    self.is_backslash = false;
                }

                if self.previous_is_entity && self.buffer.len() >= target.len() {
                    FeedOutput::Continue
                } else {
                    FeedOutput::Cancel
                }
            }
        }
    }

    pub fn next_chunk(
        &mut self,
        chunk: &[u8],
        policy: &Policy,
        logger: &impl Log,
    ) -> Result<Vec<u8>, RuleError> {
        let mut data = Vec::new();

        for &b in chunk {
            match self.feed(b) {
                FeedOutput::Continue => self.buffer.push(b),
                FeedOutput::StartTag => {
                    self.length += self.buffer.len();
                    data.append(&mut self.buffer);
                    self.buffer.push(b);
                    self.previous_is_entity = true;
                }
                FeedOutput::EndTag => {
                    self.buffer.push(b);
                    let start = self.length;
                    let end = self.length + self.buffer.len();
                    self.length = end;

                    if let Some(replace) = policy.html.xml_entities.check(
                        &String::from_utf8_lossy(&self.buffer),
                        start..end,
                        logger,
                    )? {
                        data.append(&mut replace.into_bytes());
                        self.buffer.clear();
                    } else {
                        data.append(&mut self.buffer);
                    }
                }
                FeedOutput::Cancel => {
                    self.buffer.push(b);
                    self.length += self.buffer.len();
                    data.append(&mut self.buffer);
                    self.previous_is_entity = false;
                }
            }
        }

        policy.resources.max_bytes.check(self.length, logger)?;

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::log::NullLogger;
    use std::{assert_matches, ops::Range};

    use super::*;

    #[test]
    fn xml_reader() {
        let policy = Policy::default();
        let logger = NullLogger;

        let mut scanner = XmlReader::new(0);
        assert_eq!(
            scanner.next_chunk(b"<html><body>", &policy, &logger),
            Ok(b"<html><body>".to_vec())
        );
        assert_eq!(
            scanner.next_chunk(b"<!DOCTYPE html>", &policy, &logger),
            Ok(b"<!DOCTYPE html>".to_vec())
        );
        assert_matches!(
            scanner.next_chunk(b"<!ENTITY x 'y'>", &policy, &logger),
            Err(RuleError::Replace {
                offset: Range { start: 27, end: 42 },
                ..
            })
        );

        // Case insensitivity
        let mut reader = XmlReader::new(0);
        assert_matches!(
            reader.next_chunk(b"<!entity lol 'lol'>", &policy, &logger),
            Err(RuleError::Replace {
                offset: Range { start: 0, end: 19 },
                ..
            })
        );

        // // Boundary split
        let mut reader = XmlReader::new(0);
        assert_matches!(reader.next_chunk(b"abc<!ENT", &policy, &logger), Ok(_));
        assert_matches!(reader.next_chunk(b"ITY def", &policy, &logger), Ok(_));
        assert_matches!(
            reader.next_chunk(b">", &policy, &logger),
            Err(RuleError::Replace {
                offset: Range { start: 3, end: 16 },
                ..
            })
        );

        // Overlapping match
        let mut reader = XmlReader::new(0);
        assert_matches!(reader.next_chunk(b"<!<!ENT", &policy, &logger), Ok(_));
        assert_matches!(reader.next_chunk(b"ITY", &policy, &logger), Ok(_));
        assert_matches!(
            reader.next_chunk(b">", &policy, &logger),
            Err(RuleError::Replace {
                offset: Range { start: 2, end: 11 },
                ..
            })
        );

        // Another overlap match
        let mut reader = XmlReader::new(0);
        assert_matches!(reader.next_chunk(b"<!EN<!ENT", &policy, &logger), Ok(_));
        assert_matches!(reader.next_chunk(b"ITY", &policy, &logger), Ok(_));
        assert_matches!(
            reader.next_chunk(b">", &policy, &logger),
            Err(RuleError::Replace {
                offset: Range { start: 4, end: 13 },
                ..
            })
        );
    }
}
