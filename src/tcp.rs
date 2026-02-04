use std::io;

pub enum State {
    //Closed,
    //Listen,
    SynRevd,
    Extab,
}

pub struct Connection {
    state: State,
    recv: RecvSequenceSpace,
    send: SendSequenceSpace,
    ip: etherparse::Ipv4Header,
}

/*
State of the Send Sequence Space (RFC 793 S3.2)

                  1         2          3          4
             ----------|----------|----------|----------
                    SND.UNA    SND.NXT    SND.UNA
                                         +SND.WND

       1 - old sequence numbers which have been acknowledged
       2 - sequence numbers of unacknowledged data
       3 - sequence numbers allowed for new data transmission
       4 - future sequence numbers which are not yet allowed

                         Send Sequence Space

                              Figure 4.



 The send window is the portion of the sequence space labeled 3 in
 figure 4.
 */

struct SendSequenceSpace {
    /// send acknoledgement
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// send sequence number used for last window update
    wl1: usize,
    /// send acknoledgement number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/*
State of the Receive Sequence Space (RFC 793 S3.2)

                      1          2          3
                  ----------|----------|----------
                         RCV.NXT    RCV.NXT
                                   +RCV.WND

       1 - old sequence numbers which have been acknowledged
       2 - sequence numbers allowed for new reception
       3 - future sequence numbers which are not yet allowed

                        Receive Sequence Space

                              Figure 5.



 The receive window is the portion of the sequence space labeled 2 in
 figure 5.
 */

struct RecvSequenceSpace {
    ///recieve next
    nxt: u32,
    ///recieve window
    wnd: u16,
    ///recieve urgent pointer
    up: bool,
    ///initial recieve sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            //only expected syn packet
            return Ok(None);
        }

        let iss = 0;
        let mut buf = [0u8; 1500];

        let mut c = Connection {
            state: State::SynRevd,

            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,

                wl1: 0,
                wl2: 0,
            },

            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
        };

        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        let ip = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            [
                iph.destination()[0],
                iph.destination()[1],
                iph.destination()[2],
                iph.destination()[3],
            ],
            [
                iph.source()[0],
                iph.source()[1],
                iph.source()[2],
                iph.source()[3],
            ],
        );
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&ip, &[])
            .expect("failed to compute checksum");

        eprintln!("got ip header {:02x?}", iph);
        eprintln!("got tcp header {:02x?}", tcph);
        //write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        eprintln!("responding with {:02x?}", &buf[..buf.len() - unwritten]);
        nic.send(&buf[..unwritten])?;

        Ok(Some(c))
    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
    }

    fn in_between_wrapped() -> bool {
        use std::cmp::Ordering;
        match start.cmp(x) {
            Ordering::Equal => return false,
            // we have:
            //
            //  |--------------S--------X----------------------|
            //  x is between S and E (S < X < E) in these cases:
            //
            //  |--------------S--------X----E-----------------|
            //
            //  |-----------E---S--------X---------------------|
            //
            //  but *not* in the cases
            //
            //  |-----------S-----E------X---------------------|
            //
            //  |----------------|--------X--------------------|
            //                  ^-S+E
            //  |---------------S--------|---------------------|
            //                           ^-S+X
            Ordering::Less => {
                if end >= start && end >= x {
                    return false;
                }
            }
        }
    }
}
