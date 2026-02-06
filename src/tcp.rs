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

impl State {
    fn is_synchronized() {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,
        }
    }
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

            ip: etherparse::Ipv4Header::new(
                0,
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
            ),
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                c.send.iss,
                c.send.wnd,
            ),
        };

        self.tcp.syn = true;
        self.tcp.ack = true;
        c.write(nic, &[])?;

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledge_number = self.recv.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        self.ip.set_payload_len(size);

        // the kernel is nice and does this for us
        // self.tcp.checksum = self.tcp
        //      .calc_checksum_ipv4(&self.ip, &[]);
        //      .expect("failed to compute checksum");
        //

        // write out the headers
        use std::io::write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;
        let unwritten = unwritten.len();
        let payload_bytes = unwritten.write(payload)?;
        self.send.nxt(wrapping_add(payload_bytes as u32));
        if self.tcp.syn {
            self.send.nxt = self.send.nxt(wrapping_add(1));
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt(wrapping_add(1));
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        //fix sequence number here
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgement_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first check that sequence numbers are valid (RFC 793 S3.3)
        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!

        let ackn = tcph.acknoledgement_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                //according to Reset Generation, we should send a RST
                self.send_rst(nic);
            }
            return Ok(());
        }

        // valid segment check, okay if it acks at least one byte, at least
        // one of the following is true
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
        // RCV.NXT =< SEG.SEQ + SEG.LEN-1 < RCV.NXT + RCV.WND

        let seqn = tcp.sequence_number();
        let mut slen = data.len();
        if tcp.fin() {
            slen += 1;
        };

        if tcp.syn() {
            slen += 1;
        };

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            //zero lengt segment have seperate rules for accceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + data.len() - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => {
                //expect to get an ack for our SYN
                if !tcph.ack() {
                    return Ok(());
                }
                // must have ACKed our SYN, since we have only detected one byte and
                // we have only sent one byte (the syn)
                self.state = Estab;

                //now lets terminate the program
            }
            State::Estab => {
                unimplemented!();
            }
        }
    }

    fn in_between_wrapped(start: u32, x: u32, end: u32) -> bool {
        use std::cmp::Ordering;
        match start.cmp(x) {
            Ordering::Equal => return false,

            // we have:
            //
            //   0|--------------S--------X----------------------|(wraparound)
            //   x is between S and E (S < X < E) in these cases:
            //
            //   0|--------------S--------X----E-----------------|(wraparound)
            //
            //   0|-----------E---S--------X---------------------|(wraparound)
            //
            //     but *not* in the cases
            //
            //   0|-----------S-----E------X---------------------|(wraparound)
            //
            //   0|----------------|--------X--------------------|(wraparound)
            //                  ^-S+E
            //   0|---------------S--------|---------------------|(wraparound)
            //                             ^-S+X
            //      in other words iff !(S<=E<=X)
            Ordering::Less => {
                if end >= start && end <= x {
                    return false;
                }
            }

            // we have:
            //
            //   0|--------------X-------S-----------------------|(wraparound)
            //   x is between S and E (S < X < E) in these cases:
            //
            //   0|--------------X--------E-----S----------------|(wraparound)
            //
            //     but *not* in the cases
            //
            //   0|-----------E---X--------S---------------------|(wraparound)
            //
            //   0|-----------X-----S------E---------------------|(wraparound)
            //
            //   0|----------------|--------S--------------------|(wraparound)
            //                  ^-S+E
            //   0|---------------X--------|---------------------|(wraparound)
            //                           ^-S+X
            //      in other words iff !(S<E<X)
            Ordering::Greater => {
                if end < start && end > x {
                } else {
                    return false;
                }
            }
        }
        return true;
    }
}
