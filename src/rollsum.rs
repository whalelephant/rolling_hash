use std::num::Wrapping;

/// This rolling sum uses Adler-32 checksum which is used in rsync
///

pub struct Rollsum {
    /// sum of bytes - wrapped round max
    pub s: Wrapping<u32>,
    /// sum of sum of bytes - wrapped round max
    pub ss: Wrapping<u32>,
    /// the total size in the block
    pub block_size: usize,
}

#[derive(Debug)]
pub enum Error {
    BatchRollError,
}

impl Rollsum {
    /// Warning: Assumes that the initial block has the exact blocksize required
    pub fn new(_buf: &[u8]) -> Self {
        let mut s = Wrapping(0 as u32);
        let mut ss = Wrapping(0 as u32);
        let mut block_size = 0usize;
        for byte in _buf {
            s += Wrapping(*byte as u32);
            ss += s;
            block_size += 1;
        }
        Self { s, ss, block_size }
    }

    /// Current digest at this block
    pub fn digest(&self) -> u32 {
        self.ss.0 << 16 | self.s.0
    }

    /// Prepares Rollsum for the next byte, get the hash with digest()
    ///
    /// This is useful for checking quickly if the new file might have the same block
    pub fn roll_hash(&mut self, new_byte: Option<u8>, old_byte: u8) {
        self.s -= Wrapping(old_byte as u32);
        self.ss -= Wrapping(self.block_size as u32) * Wrapping(old_byte as u32);
        if let Some(new_byte) = new_byte {
            self.s += Wrapping(new_byte as u32);
            self.ss += self.s;
        } else {
            self.block_size -= 1
        }
    }

    /// Prepare Rollsum for a next set of bytes of len eq block_size
    ///
    /// Useful for creating signature and roll forward a whole block after matched
    pub fn batch_roll(&mut self, buffer: &[u8]) -> Result<(), Error> {
        if buffer.len() != self.block_size {
            return Err(Error::BatchRollError);
        }
        self.s = Wrapping(0);
        self.ss = Wrapping(0);
        for byte in buffer {
            self.s += Wrapping(*byte as u32);
            self.ss += self.s;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rollsum_works() {
        let v = vec![1, 2, 3, 4, 5];
        let rs = Rollsum::new(&v);
        assert_eq!(rs.s.0, 15);
        assert_eq!(rs.ss.0, 35);
        assert_eq!(rs.digest(), 35 << 16 | 15);
    }

    #[test]
    fn roll_forward_full_works() {
        let v = vec![1, 2, 3, 4, 5];
        let mut rs = Rollsum::new(&v);
        rs.roll_hash(Some(6), 1);
        assert_eq!(rs.s.0, 20);
        assert_eq!(rs.ss.0, 50);
        assert_eq!(rs.digest(), 50 << 16 | 20);
    }

    #[test]
    fn roll_forward_empty_works() {
        let v = vec![1, 2, 3, 4, 5];
        let mut rs = Rollsum::new(&v);
        rs.roll_hash(None, 1);
        assert_eq!(rs.s.0, 14);
        assert_eq!(rs.ss.0, 30);
        assert_eq!(rs.digest(), 30 << 16 | 14);
    }
}
