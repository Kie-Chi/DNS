import socket
import time

# --- Configuration ---
# Listen on all network interfaces. This is best practice in Docker containers.
HOST = '0.0.0.0'
# Listen on the standard DNS port
PORT = 53
# Delay time in seconds
DELAY = 0.5  # 500 milliseconds

print("--- Slow DNS Echo Server ---")
print(f"[*] Preparing to listen on {HOST}:{PORT}...")
print(f"[*] Each request will be responded to after a {DELAY} second delay")

# Create a UDP socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
except PermissionError:
    print("\n[!] Error: Permission denied to bind to port 53.")
    print("[!] Please try running this script with root privileges using 'sudo python3 slow_dns_echo.py'.")
    exit(1)
except OSError as e:
    print(f"\n[!] Error: An error occurred while binding to the port: {e}")
    print("[!] The port might already be in use by another program.")
    exit(1)


print(f"\n[*] Server started successfully, listening on port {PORT}...")

try:
    while True:
        # Wait for and receive a data packet
        # recvfrom returns the data itself (bytes) and the sender's address (ip, port)
        data, addr = sock.recvfrom(1024)  # 1024 byte buffer is sufficient for DNS

        print(f"\n[+] Received packet from {addr} with length {len(data)} bytes.")

        # Print delay information
        print(f"[*] Waiting for {DELAY} seconds...")

        # Implement the delay
        time.sleep(DELAY)

        # Send the received **raw data** back to the **original address**
        sock.sendto(data, addr)

        print(f"[*] Echoed the same packet back to {addr}.")

except KeyboardInterrupt:
    print("\n\n[*] Ctrl+C detected, shutting down the server...")
    sock.close()
    print("[*] Server has been shut down.")