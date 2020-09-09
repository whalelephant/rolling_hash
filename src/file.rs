use std::fs::File;
use std::path::Path;

pub fn read_file(filepath: &'static str) -> Vec<u8> {
    let path = Path::new(filepath);
    let mut buf = Vec::new();
    let mut file = match File::open(&path) {
        Err(_) => panic!("couldn't open {}"),
        Ok(file) => file,
    };
    match file.read_to_end(&mut buf) {
        Ok(bytes) => {
            println!("file size in bytes: {}", bytes);
            buf
        }
        Err(_) => panic!("Cannot read file at {}", filepath),
    }
}
