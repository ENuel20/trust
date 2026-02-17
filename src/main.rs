use std::io;
use std::io::prelude::*;
use std::thread;
mod tcp;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("created interface");
    let mut l1 = i.bind(4000)?;
    let t1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection!");
            stream.write(b"hello");
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
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
