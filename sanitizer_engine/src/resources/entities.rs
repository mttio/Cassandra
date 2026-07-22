/// Scanner to detect ENTITY declarations in custom XML/HTML content blocks.
#[derive(Debug)]
pub struct EntityScanner {
    match_idx: usize,
}

impl EntityScanner {
    pub fn new() -> Self {
        Self { match_idx: 0 }
    }

    /// Process a byte, returns true if b"<!ENTITY" (case-insensitive) is matched
    pub fn feed(&mut self, b: u8) -> bool {
        let target = b"<!ENTITY";
        let target_char = target[self.match_idx];
        if b.eq_ignore_ascii_case(&target_char) {
            self.match_idx += 1;
            if self.match_idx == target.len() {
                return true;
            }
        } else {
            if b == b'<' {
                self.match_idx = 1;
            } else {
                self.match_idx = 0;
            }
        }
        false
    }

    /// Feeds a chunk of bytes, returns true if b"<!ENTITY" is found
    pub fn feed_chunk(&mut self, chunk: &[u8]) -> bool {
        for &b in chunk {
            if self.feed(b) {
                return true;
            }
        }
        false
    }
}






























#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_scanner() {
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<html><body>"));
        assert!(!scanner.feed_chunk(b"<!DOCTYPE html>"));
        assert!(scanner.feed_chunk(b"<!ENTITY x 'y'>"));

        // Case insensitivity
        let mut scanner = EntityScanner::new();
        assert!(scanner.feed_chunk(b"<!entity lol 'lol'>"));

        // Boundary split
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"abc<!ENT"));
        assert!(scanner.feed_chunk(b"ITY def"));

        // Overlapping match
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<!<!ENT"));
        assert!(scanner.feed_chunk(b"ITY"));

        // Another overlap match
        let mut scanner = EntityScanner::new();
        assert!(!scanner.feed_chunk(b"<!EN<!ENT"));
        assert!(scanner.feed_chunk(b"ITY"));
    }
}
