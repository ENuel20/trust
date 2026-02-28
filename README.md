# Trust - TCP Implementation

This is a TCP implementation based on RFC 793 https://www.rfc-editor.org/rfc/rfc793.html

## How to Run

### Step 1: Start the Server
In one terminal, run the server script:
```bash
./run.sh
```

The server will start and listen for TCP connections on the tun0 interface.

### Step 2: Monitor Network Traffic with tshark
In another terminal, set up tshark to view the network handshake and TCP metrics:
```bash
sudo tshark -i tun0
```

This will capture and display all network packets on the tun0 interface, allowing you to see the TCP handshake and communication details.

### Step 3: Test the Connection
in another terminal
You can test the server with either of these approaches:

#### Option 1: Send a Single Message (One Packet)
```bash
echo "foo" | nc 192.168.0.2 8000
```
Expected output:
```
hello from rust-tcp!
```
This sends "foo" to the server, which reads it and closes the connection immediately.

#### Option 2: Interactive Connection (Multiple Packets)
```bash
nc 192.168.0.2 8000
```
Then type messages interactively:
```

read
write to me
ok good job
```

### Key Differences
- **Option 1**: Sends a single message. The server reads it and stops immediately. This results in minimal packet exchange.

## Learning Resources

Follow this learning path to understand the implementation:

### Phase 1: Protocol Overview & Fundamentals
1. **RFC 1180 - TCP/IP Protocol Suite Tutorial** (Overview)
   - https://datatracker.ietf.org/doc/html/rfc1180?hl=en-US
   - Start here for a high-level understanding of TCP/IP concepts

2. **YouTube: TCP Trace Files & Packet Analysis** (Video)
   - https://youtu.be/xdQ9sgpkrX8?si=gzkFGBdGDD7ZlaTm
   - Learn how to read TCP traces, understand handshakes, and track packet flow between client and server

3. **YouTube: TCP Deep Dive** (Video)
   - https://youtu.be/rmFX1V49K8U?si=eZzkhkJYzu3nWxxK
   - Reinforces key terminologies and packet movement concepts

### Phase 2: Main Implementation Reference (Core)
**RFC 793 - Transmission Control Protocol** ⭐ **MAIN REFERENCE**
   - https://www.rfc-editor.org/rfc/rfc793.html
   - The primary specification for this implementation
   - Essential reading for understanding the code architecture

### Phase 3: Supplementary
4. **RFC 791 - Internet Protocol** (Optional)
   - https://www.rfc-editor.org/rfc/rfc791.html
   - Provides context on the IP layer that TCP operates over

5. **YouTube: TCP Retransmission** (Advanced)
   - https://youtu.be/NdvWI6RH1eo?si=eU5co2Itd41YWbpH
   - Deep dive into retransmission mechanisms and timeout handling

