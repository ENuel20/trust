use std::io;
use std::io::prelude::*;
use std::thread;
mod tcp;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("Created Interface");
    let mut listener = i.bind(8000)?;
    while let Ok(mut stream) = listener.accept() {
        eprintln!("got connection!");
        thread::spawn(move || {
            stream.write(b"hello from trust!\n").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of date", n);
                if n == 0 {
                    eprintln!("No nore data");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }
    Ok(())
}
