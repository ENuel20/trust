pub enum State {
    Closed,
    Listen,
    SynRevd,
    Extab,
}

impl Default for State {
    fn default() -> Self {
        State::Listen;
    }
}

impl State {
    pub fn on_packet<'a>(&mut self, iph:etherparse::Ipv4HeaderSlice<'a>, tcph:etherparse::TcpHeaderSlice<'a>, data: &'a[u8]){

        match *self {
            State::Closed => {
                return;
            }
            State::Listen => {
                if != tcph.syn() {
                    //if not snc 
                    continue;
                }
                let syn_ack = etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(),0,0);
                syn_ack.syn() = true;
                syn_ack.ack() = true;
                
                let ip = etherparse::Ipv4Header::new(syn_ack.slice().len, 64, etherparse::IpNumber::TCP, iph.destination_addr(), iph.source_addr())
            }
        }
        eprintln!("{}:{} -> {}:{} {}b of Tcp", iph.source_addr(),tcph.source_port(), iph.destination_addr(),tcph.destination_port(), data.len());
    }
}
