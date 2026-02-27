#![feature(Duration_float)]
use bitflags::bitflags;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io;
use std::time;

bitflags! {
pub(crate) struct Available : u8 {
    const Read = 0b00000001;
    const Write = 0b00000010;
}
}

#[derive(Debug)]
pub enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    recv: RecvSequenceSpace,
    send: SendSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        eprintln!("asked if closed wen in {:?}", self.state);
        if let State::TimeWait = self.state {
            //TODO: any state after recv FIN,so also CLOSE-WAIT, LAST-ACK,CLOSED,CLOSING
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        eprintln!("Computing availaility");
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::Read
        }
        // TODO: take into account self.state
        // TODO: set Available::Write
        a
    }
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
        let wnd = 1024;

        let mut c = Connection {
            state: State::SynRcvd,

            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
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
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),

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
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },

            incoming: Default::default(),
            unacked: Default::default(),
            closed: false,
            closed_at: None,
        };

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, c.send.nxt, 0)?;

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let mut offset = seq.wrapping_sub(self.send.una) as usize;

        //we need to special case the two virtual bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                offset = 0;
            }
        }
        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }
        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // the kernel is nice and does this for us
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        // write out the headers

        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        let ip_header_ends_at = buf_len - unwritten.len();
        // self.tcp.write(&mut unwritten);
        // potpone writing the tcp header because we need the payload as one contigious slice to
        // calculte the tcp checksum
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        //write out the payload
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            //first write as much as you can from payload1
            let pl1 = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..pl1])?;
            limit -= written;

            //now write as much as you can from payload2
            let pl2 = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..pl2])?;
            written
        };
        let payload_ends_at = buf_len - unwritten.len();
        // finally lets calculate the checksum and write out the tcp header
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.write(&mut tcp_header_buf);
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());
        nic.send(&buf[..payload_ends_at])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        //TODO:fix sequence number here
        //If the incoming segment has an ACK field, the reset takes its
        //sequence number from the ACK field of the segment, otherwise the
        //reset has sequence number zero and the ACK field is set to the sum
        //of the sequence number and segment length of the incoming segment.
        //The connection remains in the same state.

        //TODO: handle Synchronized reset
        //3.If the connection is in a synchronized state (ESTABLISHED,
        //FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //any unacceptable segment (out of window sequence number or
        //unacceptible acknowledgment number) must elicit only an empty
        //acknowledgment segment containing the current send-sequence number
        //and an acknowledgment indicating the next sequence number expected
        //to be received, and the connection remains in the same state.

        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }
    pub(crate) fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        let nunacked = self.send.nxt.wrapping_sub(self.send.una);
        let unsent = self.unacked.len() as u32 - nunacked;
        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());
        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            // we should retransmit things
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);

            if resend < self.send.wnd as u32 && self.closed {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            let (h, t) = self.unacked.as_slices();
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            //we should now send data if we ave new data or space in te window
            if unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked;
            if allowed == 0 {
                return Ok(());
            }
            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(unsent));
            }

            /*let (mut h, mut t) = self.unacked.as_slices();
            //we want self.unacked[nunacked..]
            if h.len() >= nunacked {
                h = &h[nunacked..];
            } else {
                let skipped = h.len();
                h = &[];
                t = &t[(nunacked - skipped)..];
            }*/
            self.write(nic, self.send.nxt, send as usize)?;
        }
        Ok(())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first check that sequence numbers are valid (RFC 793 S3.3)
        //
        // valid segment check, okay if it acks at least one byte, at least
        // one of the following is true
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
        // RCV.NXT =< SEG.SEQ + SEG.LEN-1 < RCV.NXT + RCV.WND

        let seqn = tcph.sequence_number();
        eprintln!("printn sequence numer!");
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };

        if tcph.syn() {
            slen += 1;
        };

        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            eprintln!("is OKAY");
            //zero lengt segment have seperate rules for accceptance
            if self.recv.wnd == 0 {
                eprintln!("recv wnd = 0");
                if seqn != self.recv.nxt {
                    eprintln!("equal");
                    false
                } else {
                    true
                }
            } else if !in_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !in_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !in_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprintln!("Not Okay");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        //TODO: if not acceptale send an Ack
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            if tcph.syn() {
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            eprintln!("send recieve state");
            if in_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we have only detected one byte and
                // we have only sent one byte (the syn)
                self.state = State::Estab;
                eprintln!("not estab");
            } else {
                //TODO: <SEQ=SEG.ACK><CTL=RST>
                //now lets terminate the program
                //TODO: this should be gotten from the retransmission queue
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if in_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                if !self.unacked.is_empty() {
                    let _nacked = self
                        .unacked
                        .drain(..ackn.wrapping_sub(self.send.una) as usize)
                        .count();
                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let mut srtt = &mut self.timers.srtt;
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            if in_between_wrapped(una, seq, ackn) {
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }
                self.send.una = ackn;
            }
        }

        /*if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                self.state = State::FinWait2;
            }
        }*/

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            let mut unread_data_at = (self.recv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                // we must have a re-transmitted fin that we must have already seen
                // nxt points to beyound the fin, but the fin is not in te data!

                assert_eq!(unread_data_at, data.len() + 1);
                unread_data_at = 0;
                eprintln!("reading from {:?} of {:?}", unread_data_at, data);
            }
            eprintln!("reading from {:?} of {:?}", unread_data_at, data);

            self.incoming.extend(&data[unread_data_at..]);

            //Once the TCP takes responsiblity for the data is advances
            //RCV.NXT over the data accepted, and adjust RCV.WND as appropriate
            //to the current buffer availaility. The total of  RCV.NXT and RCV.WND
            //should not be reduced

            self.recv.nxt = seqn
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcph.fin() { 1 } else { 0 });
            //send an acknowledgement of the form <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            //TODO: maybe just tick to piggyback ack on data
            self.write(nic, self.send.nxt, 0)?;
        }

        if tcph.fin() {
            eprintln!("is FIN in {:?}", self.state);
            match self.state {
                State::FinWait2 => {
                    //we are done with the connection!
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }
        Ok(self.availability())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "alread closing",
                ))
            }
        }
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    //from RFC1323
    // Tcp determines if a data segment is "old" or "new" by testing
    // whether its sequence number is within 2**31 bytes of the left edge
    // of the window, and if it is not discarding the data as "old", To
    // insure that the new data is never mistakenly considered old and vice
    // -versa, the left edge has to be at most 2^31 away from the rigt edge
    // of the reciever's window

    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn in_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
