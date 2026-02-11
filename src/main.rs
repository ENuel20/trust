use std::io;
use std::io::prelude::*;
use std::thread;
mod tcp;

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("created interface");
    let mut l1 = i.bind(7000)?;
    let t1 = thread::spawn(move || {
        while let Ok(_stream) = l1.accept() {
            eprintln!("got connection!");
            let n = stream.read(&mut[0]).unwrap();
            eprintln!("read data");
            assert_eq!(n, 0);
        }
    });

    t1.join().unwrap();
    Ok(())
}
