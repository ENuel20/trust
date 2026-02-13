use std::io;
use std::io::prelude::*;
use std::thread;
mod tcp;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("created interface");
    let mut l1 = i.bind(4000)?;
    eprintln!("bind");
    let t1 = thread::spawn(move || {
        eprintln!("tread");
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection!");
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut [0]).unwrap();
                eprintln!("read {:?}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });

    t1.join().unwrap();
    Ok(())
}
