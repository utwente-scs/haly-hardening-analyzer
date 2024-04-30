import telnetlib

class TelnetReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tn = None
        self.connect()

    def is_connected(self):
        return self.tn is not None and self.tn.sock is not None

    def send_command(self, command):
        try:
            self.tn.write(command.encode('ascii') + b'\n')
            return self.tn.read_until(b'# ').decode('ascii')
        except Exception as e:
            print(f"An error occurred while sending command: {str(e)}")

    def close(self):
        try:
            self.tn.close()
        except Exception as e:
            print(f"An error occurred while closing the connection: {str(e)}")


    def connect(self):
        try:
            self.tn = telnetlib.Telnet(self.host, self.port)
            self.tn.read_until(b'# ')
        except ConnectionRefusedError:
            print("Connection refused. Please check the host and port.")
        except Exception as e:
            print(f"An error occurred while connecting: {str(e)}")
