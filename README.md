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
- **Option 2**: Creates an interactive connection and exchanges multiple packets (3+ additional packets) with the server, allowing for back-and-forth communication.

## References
- RFC 793: Transmission Control Protocol - https://www.rfc-editor.org/rfc/rfc793.html
