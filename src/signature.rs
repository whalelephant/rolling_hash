use crate::rollsum::Rollsum;
use std::collections::HashMap;
use std::io::Read;

use crate::{Blake2b, Digest};

/// Basic structure containing a file signature
#[derive(Debug)]
pub struct Signature {
    /// key: checksum | value: all checksum collided strong hash
    chunk_hashes: HashMap<u32, Vec<BlockHash>>,
    block_size: usize,
    blocks: u16,
    file_size: u16,
}

/// Strong hash of a block for signature
#[derive(Debug)]
pub struct BlockHash {
    pub block_index: u16,
    pub hash: Vec<u8>,
}

impl Signature {
    pub fn new(_block_size: usize) -> Self {
        Self {
            chunk_hashes: HashMap::new(),
            block_size: _block_size,
            blocks: 0,
            file_size: 0,
        }
    }

    /// Main function that generates a signature
    pub fn generate(&mut self, input: &mut dyn Read) {
        // TODO define input type
        let mut buf = vec![0; self.block_size];
        let mut read_size = input.read(&mut buf).unwrap(); // handle
        let mut rs = Rollsum::new(&buf);
        if read_size == 0 {
            self.blocks = 0;
            self.file_size = 0;
        }
        while read_size > 0 {
            let mut blake_hasher = Blake2b::new();
            blake_hasher.update(&buf);
            let hash = blake_hasher.finalize();
            let hashes = self.chunk_hashes.entry(rs.digest()).or_insert(Vec::new());
            hashes.push(BlockHash {
                block_index: self.blocks,
                hash: hash.as_slice().to_owned(),
            });
            self.blocks += 1;
            self.file_size += read_size as u16;
            read_size = input.read(&mut buf).unwrap();
            rs.batch_roll(&buf).unwrap();
        }
    }

    pub fn get_chunk_map(&self, key: u32) -> Option<&Vec<BlockHash>> {
        self.chunk_hashes.get(&key)
    }

    pub fn get_file_size(&self) -> u16 {
        self.file_size
    }

    pub fn get_blocks(&self) -> u16 {
        self.blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn initiate_signature_produce_correct_sizes() {
        let mut input = Cursor::new(
            "Words are, in my not-so-humble opinion, our most inexhaustible source of magic.",
        ); // 79 characters
        let mut sig = Signature::new(8);
        sig.generate(&mut input);
        assert_eq!(sig.get_blocks(), 10);
        assert_eq!(sig.get_file_size(), 79)
    }
}
