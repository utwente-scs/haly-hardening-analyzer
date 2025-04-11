import telnetlib
import logging

logger = logging.getLogger("hardeninganalyzer")

class TelnetReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.tn = None
        self.connect()

    def is_connected(self):
        if self.tn is None or self.tn.sock is None:
            return False
        try:
            self.tn.read_until(b'# ', timeout=10)
            return True
        except EOFError as e:
            logger.warning(f"An error occurred while checking connection: {str(e)}")
            return False
        return False

    def send_command(self, command):
        try:
            self.tn.write(command.encode('ascii') + b'\n')
            return self.tn.read_until(b'# ').decode('ascii')
        except Exception as e:
            logger.error(f"An error occurred while sending command: {str(e)}")

    def close(self):
        try:
            self.tn.close()
        except Exception as e:
            logger.error(f"An error occurred while closing the connection: {str(e)}")


    def connect(self):
        try:
            self.tn = telnetlib.Telnet(self.host, self.port, timeout=10)
            self.tn.read_until(b'# ', timeout=10)
        except TimeoutError:
            logger.warning("Connection timed out. Probably need to start server with root.")
        except ConnectionRefusedError:
            logger.warning("Connection refused. Please check the host and port.")
        except Exception as e:
            logger.error(f"An error occurred while connecting: {str(e)}")
