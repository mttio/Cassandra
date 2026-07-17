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

    // fn feed_chunk(&mut self, chunk: &[u8]) -> Option<(usize, Option<usize>)> {
    //     for (i, &b) in chunk.iter().enumerate() {
    //         if let Some(index) = self.feed(b) {
    //             return Some((i.saturating_sub(index), Some(i + 1)));
    //         }
    //     }

    //     if self.match_idx > 0 {
    //         return Some((chunk.len().saturating_sub(self.match_idx), None));
    //     }

    //     None
    // }

    pub fn next_chunk(
        &mut self,
        chunk: &[u8],
        policy: &Policy,
        logger: &impl Log,
    ) -> Result<Vec<u8>, RuleError> {
        let mut data = Vec::new();

        for &b in chunk {
            let boi = self.feed(b);
            // println!(
            //     "{boi:?} - {{\n  length = {}\n  is_entity = {}\n  buffer = {:?}\n}}",
            //     self.length,
            //     self.previous_is_entity,
            //     String::from_utf8_lossy(&self.buffer)
            // );

            match boi {
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

    // pub fn next_chunk_2(
    //     &mut self,
    //     mut chunk: &[u8],
    //     policy: &Policy,
    //     logger: &impl Log,
    // ) -> Result<Vec<u8>, RuleError> {
    //     let mut data = Vec::new();

    //     loop {
    //         let Some((start, end)) = self.feed_chunk(chunk) else {
    //             data.append(&mut self.buffer);
    //             data.extend_from_slice(chunk);
    //             break;
    //         };

    //         let Some(end) = end else {
    //             self.buffer.extend_from_slice(&chunk[start..]);
    //             data.extend_from_slice(&chunk[..start]);
    //             break;
    //         };

    //         self.buffer.extend_from_slice(&chunk[start..end]);
    //         data.extend_from_slice(&chunk[..start]);

    //         chunk = &chunk[end..];

    //         let start = start + self.length;
    //         let end = end + self.length;
    //         self.length = end;

    //         if let Some(replace) = policy.html.xml_entities.check(
    //             &String::from_utf8_lossy(&self.buffer),
    //             start..end,
    //             logger,
    //         )? {
    //             data.append(&mut replace.into_bytes());
    //             self.buffer.clear();
    //         } else {
    //             data.append(&mut self.buffer);
    //         }
    //     }

    //     self.length += chunk.len();
    //     policy.resources.max_bytes.check(self.length, logger)?;

    //     Ok(data)
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_reader() {
        let mut scanner = XmlReader::new(0);
        assert_eq!(scanner.feed_chunk(b"<html><body>"), None);
        assert_eq!(scanner.feed_chunk(b"<!DOCTYPE html>"), None);
        assert_eq!(scanner.feed_chunk(b"<!ENTITY x 'y'>"), Some((0, Some(15))));

        // Case insensitivity
        let mut reader = XmlReader::new(0);
        assert_eq!(
            reader.feed_chunk(b"<!entity lol 'lol'>"),
            Some((0, Some(19)))
        );

        // Boundary split
        let mut reader = XmlReader::new(0);
        assert_eq!(reader.feed_chunk(b"abc<!ENT"), Some((3, None)));
        assert_eq!(reader.feed_chunk(b"ITY def"), Some((0, None)));
        assert_eq!(reader.feed_chunk(b">"), Some((0, Some(1))));

        // Overlapping match
        let mut reader = XmlReader::new(0);
        assert_eq!(reader.feed_chunk(b"<!<!ENT"), Some((2, None)));
        assert_eq!(reader.feed_chunk(b"ITY"), Some((0, None)));
        assert_eq!(reader.feed_chunk(b">"), Some((0, Some(1))));

        // Another overlap match
        let mut reader = XmlReader::new(0);
        assert_eq!(reader.feed_chunk(b"<!EN<!ENT"), Some((4, None)));
        assert_eq!(reader.feed_chunk(b"ITY"), Some((0, None)));
        assert_eq!(reader.feed_chunk(b">"), Some((0, Some(1))));
    }
}
