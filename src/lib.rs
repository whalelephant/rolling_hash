#![allow(unused_variables)]
pub use blake2::{Blake2b, Digest};
use std::io::{Cursor, Read};

mod rollsum;
mod signature;

use rollsum::Rollsum;
use signature::{BlockHash, Signature};

#[derive(Debug)]
pub enum Delta {
    Add(Add),
    Delete(Delete),
}

#[derive(Debug, PartialEq)]
pub struct Add {
    /// The first byte index to insert / delete the content
    byte_index: u16,
    /// Total bytes to be inserted / deleted
    bytes: u16,
    /// Content to be inserted
    content: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Delete {
    /// The first byte index to insert / delete the content
    byte_index: u16,
    /// Total bytes to be inserted / deleted
    bytes: u16,
}

impl Add {
    pub fn new(byte_index: u16) -> Self {
        Self {
            byte_index,
            bytes: 0,
            content: Vec::new(),
        }
    }
}

pub fn check_diffs(
    block_size: usize,
    mut old_buf: Cursor<&[u8]>,
    mut new_buf: Cursor<&[u8]>,
) -> Vec<Delta> {
    // TODO check if old_buf and new_buf is large enough for one block

    // slideing window through new file
    let mut window = vec![0u8; block_size];
    let mut start_win = 0u16;
    let mut end_win = (block_size - 1) as u16;

    // returned delta data
    let mut deltas = Vec::new();
    let mut new_bytes = Add::new(start_win);

    // the last block consumed of the Signature file, start before block zero
    let mut consumed_block_index = -1i32;

    let mut sig = Signature::new(block_size);
    sig.generate(&mut old_buf);

    // initial window and its weak hash
    new_buf.read(&mut window).unwrap();
    let mut rs = Rollsum::new(&window);
    let buf_len = new_buf.get_ref().len();

    // Start to loop through the file
    loop {
        if let Some(strong_hashes) = sig.get_chunk_map(rs.digest()) {
            if let Some(new_matched_index) =
                check_strong_hash(consumed_block_index, &window, &strong_hashes)
            {
                // There are blocks in the signature file that are not in new file, needs to be deleted
                let advanced_blocks = new_matched_index - (consumed_block_index + 1) as u16;
                if advanced_blocks > 0 {
                    deltas.push(Delta::Delete(Delete {
                        byte_index: start_win,
                        bytes: (advanced_blocks) * block_size as u16,
                    }));
                }
                // This makes sure that we do not take the same block from the past and use it as a match again
                consumed_block_index = new_matched_index as i32;

                // Ther are currently new bytes added in the previous loop
                if new_bytes.bytes > 0 {
                    deltas.push(Delta::Add(new_bytes));
                }
                new_bytes = Add::new(end_win + 1);

                // Since no partial block match, we can move and start fresh with new window 1 block from now
                if end_win as usize + block_size > buf_len {
                    new_bytes.bytes = buf_len as u16 - end_win - 1;
                    new_bytes.byte_index = end_win + 1;
                    new_bytes.content = new_buf.get_ref()[end_win as usize..].to_owned();
                    break;
                } else {
                    start_win += block_size as u16;
                    end_win += block_size as u16;
                    new_buf.set_position(start_win as u64);
                    new_buf.read(&mut window).unwrap();
                    rs.batch_roll(&window).unwrap();
                }
            }
        // TODO HANDLE IF NO STRONG MATCH
        } else {
            // No match, increment the sliding window if at least 1 byte left
            // Or add the rest of the file since final window did not match
            new_bytes.content.push(window[0]);
            new_bytes.bytes += 1;
            if end_win as usize >= buf_len - 1 {
                new_bytes.bytes += buf_len as u16 - start_win;
                new_bytes.content = new_buf.get_ref()[start_win as usize..].to_owned();
                break;
            } else {
                start_win += 1;
                end_win += 1;
                window.push(new_buf.get_ref()[(end_win) as usize]);
                window.remove(0);
                rs.roll_hash(
                    Some(new_buf.get_ref()[(end_win) as usize]),
                    new_buf.get_ref()[start_win as usize - 1],
                );
            }
        }
    }
    // final new bytes
    if new_bytes.bytes > 0 {
        deltas.push(Delta::Add(new_bytes));
    }

    // handlefinal unmatched bytes
    if sig.get_blocks() - 1 > consumed_block_index as u16 {
        deltas.push(Delta::Delete(Delete {
            byte_index: ((consumed_block_index + 1) as usize * block_size - 1) as u16,
            bytes: sig.get_file_size() - (consumed_block_index + 1) as u16 * block_size as u16,
        }));
    }
    deltas
}

fn check_strong_hash(
    consumed_block_index: i32,
    window: &[u8],
    blocks: &Vec<BlockHash>,
) -> Option<u16> {
    let mut blake_hasher = Blake2b::new();
    blake_hasher.update(window);
    let hash = blake_hasher.finalize();
    for block in blocks {
        if block.hash.eq(&hash.as_slice()) {
            if block.block_index as i32 > consumed_block_index {
                return Some(block.block_index);
            }
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_detects_added_blocks() {
        let diffs = check_diffs(
            4,
            Cursor::new(
                String::from("Anyone can speak Troll. All you have to do is grunt.").as_bytes(),
            ),
            Cursor::new(
                String::from("Anyone can speak Troll. All you have to not do is grunt.").as_bytes(),
            ),
        );
        assert_eq!(diffs.len(), 1); // only 1 block change
        match &diffs[0] {
            Delta::Add(add) => {
                assert_eq!(add.byte_index, 40); // index to start inserting
                assert_eq!(add.bytes, 4); // number of bytes to insert
                assert_eq!(
                    // what to insert
                    String::from_utf8(add.content.clone()).unwrap(),
                    String::from("not ")
                );
            }
            _ => panic!("Should not be delete"),
        }
    }

    #[test]
    fn it_detects_removed_blocks() {
        let diffs = check_diffs(
            5,
            Cursor::new(String::from("Make a rolling hash diffing algorithm in Rust").as_bytes()),
            Cursor::new(String::from("a rolling hash diffing algorithm in Rust").as_bytes()),
        );
        assert_eq!(diffs.len(), 1); // only diff
        match &diffs[0] {
            Delta::Delete(delete) => {
                assert_eq!(delete.byte_index, 0); // position to start remove
                assert_eq!(delete.bytes, 5); // bytes to remove
            }
            _ => panic!("Should not be add"),
        }
    }

    #[test]
    fn it_detechs_edits() {
        let diffs = check_diffs(
            7,
            Cursor::new(
                String::from("Now repeat after me - repeat after me, Riddikulus").as_bytes(),
            ),
            Cursor::new(
                String::from(
                    "Now repeat after me - without wands please - repeat after me, Ridiculous",
                )
                .as_bytes(),
            ),
        );
        // 2 additions and 1 deletion
        assert_eq!(diffs.len(), 3);

        // First insertion content
        match &diffs[0] {
            Delta::Add(add) => {
                assert_eq!(
                    String::from_utf8(add.content.clone()).unwrap(),
                    String::from(" without wands please -")
                );
            }
            _ => panic!("Should not be delete"),
        }

        // Second insertion content
        match &diffs[1] {
            Delta::Add(add) => {
                assert_eq!(
                    String::from_utf8(add.content.clone()).unwrap(),
                    String::from("iculous")
                );
            }
            _ => panic!("Should not be delete"),
        }

        // Deletion bytes
        match &diffs[2] {
            Delta::Delete(delete) => {
                assert_eq!(
                    delete.bytes,
                    String::from("dikulus").as_bytes().len() as u16
                );
            }
            _ => panic!("Should not be add"),
        }
    }
}
