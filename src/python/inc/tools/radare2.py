from r2pipe.open_base import OpenBase
import subprocess
import time
import os
import select
import paramiko
import scp
import uuid
import logging

logger = logging.getLogger('hardeninganalyzer')

class open_with_timeout_and_memlimit(OpenBase):
    """
    A copy of r2pipe.open with timeout and memory limit support.
    """
    def __init__(self, host: str, filename: str, timeout: int = None, mem_limit_gb: int = None, flags = [], radare2home = None):
        """
        Open a file in radare2
        :param host: The host to connect to
        :param filename: The file to open
        :param timeout: The timeout in seconds
        :param mem_limit_gb: The memory limit in GB
        :param flags: Flags to pass to radare2
        :param radare2home: The path to radare2
        """

        if os.name == "nt":
            raise Exception("This class is not supported on Windows. Use r2pipe.open instead.")

        super(open_with_timeout_and_memlimit, self).__init__(filename, flags)

        logger.debug(f'Opening {filename} in radare2 on {host} with timeout {timeout}s and memory limit {mem_limit_gb} GB')

        self.local = host in ['localhost', 'local']

        if not self.local:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            server = host.split('@')[1] if '@' in host else host
            username = host.split('@')[0] if '@' in host else None
            password = username.split(':')[1] if ':' in username else None

            while True:
                try:
                    self.client.connect(server, username=username, password=password)
                    self.remote_filename = '/tmp/'+uuid.uuid4().hex

                    # Upload file to analyze to remote
                    scpclient = scp.SCPClient(self.client.get_transport())
                    scpclient.put(filename, self.remote_filename)
                    scpclient.close()

                    break
                except TimeoutError:
                    logger.error(f'Timeout reached connecting to remote server {server}. Is host accessible? Retrying in 30 seconds...')
                    time.sleep(30)

        self.timeout = timeout
        self.pending = b''
        self._cmd = self._cmd_process

        cmd = ''
        if mem_limit_gb is not None:
            cmd = f'ulimit -Sv {int(mem_limit_gb * 1024 * 1024)}; '

        if radare2home is not None:
            if self.local and not os.path.isdir(radare2home):
                raise Exception(
                    "`radare2home` passed is invalid, leave it None or put a valid path to r2 folder"
                )
            r2e = os.path.join(radare2home, "radare2")
        else:
            r2e = "radare2"

        if not self.local:
            cmd += 'echo $$; '

        cmd += f'{r2e} '
        cmd += ' '.join(flags)
        if self.local:
            cmd += f' -q0 "{filename}" '
        else:
            cmd += f' -q0 "{self.remote_filename}" '
        try:
            if self.local:
                self.process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0, shell=True)
            else:
                self.channel = self.client.get_transport().open_session()
                self.channel.exec_command(cmd)

                # Get process ID from stdout
                self.pid = ''
                while True:
                    ch = self.channel.recv(1).decode('utf-8')
                    if ch == '\n':
                        break
                    self.pid += ch
        except Exception:
            self.cleanup()
            raise Exception("ERROR: Cannot find radare2 in PATH")
        
        if self.local:
            self.stdout_poll = select.poll()
            self.stdout_poll.register(self.process.stdout, select.POLLIN)

        try:
            start_time = time.time()
            timed_out = True
            while self.timeout is not None and time.time() - start_time < self.timeout:
                # Read initial \x00
                if self.read(1) is not None:
                    timed_out = False
                    break
                time.sleep(0.1)
        except Exception:
            self.cleanup()
            raise Exception("ERROR: Cannot open %s" % filename)

        if timed_out:
            self.cleanup()
            raise TimeoutError('Radare2 took too long to open the file')

        try:
            self.write(("?V\n").encode("utf8"))
            start_time = time.time()
            timed_out = True
            while self.timeout is not None and time.time() - start_time < self.timeout:
                ch = self.read(1)
                if ch == b'\x00':
                    timed_out = False
                    break
                time.sleep(0.1)
        except Exception:
            self.cleanup()
            raise Exception("ERROR: Cannot open %s" % filename)

        if timed_out:
            self.cleanup()
            raise TimeoutError('Radare2 took too long to open the file')
    
    def _cmd_process(self, cmd):
        """
        Process a command
        :param cmd: The command to process
        """
        cmd = cmd.strip().replace("\n", ";")

        # Clear stdout
        while True:
            data = self.read(4096)
            if data is None or len(data) == 0:
                break

        try:
            self.write((cmd + "\n").encode("utf8"))
        except Exception:
            return ''
        start_time = time.time()
        out = bytearray()
        buff = None
        while True:
            try:
                null_start = False
                if len(self.pending) > 0:
                    buff = self.pending
                    self.pending = b""
                else:
                    timed_out = True
                    while self.timeout is not None and time.time() - start_time < self.timeout:
                        data = self.read(4096)
                        if data is not None:
                            buff = data
                            timed_out = False
                            break
                        time.sleep(0.1)

                    if timed_out:
                        raise TimeoutError('Radare2 took too long to respond')
                if buff:
                    zro = buff.find(b"\x00")
                    if zro != -1:
                        out += buff[0:zro]
                        if zro  < len(buff):
                            self.pending = buff[zro + 1:]
                        break
                    out += buff
                elif null_start:
                    break
            except TimeoutError as e:
                # Send Ctrl^C to radare2
                if self.local:
                    self.process.send_signal(2)
                else:
                    self.client.exec_command(f'kill -2 {self.pid}')
                raise e
        return out.decode("utf-8", errors="ignore")
    
    def read(self, bytes: int, wait: bool=False) -> bytes | None:
        if self.local:
            if not wait and not self.stdout_poll.poll(0):
                return None
            return self.process.stdout.read(bytes)
        else:
            if self.channel.closed:
                raise Exception("ERROR: Cannot read from closed channel")
            if not wait and not self.channel.recv_ready():
                return None
            return self.channel.recv(bytes)
        
    def write(self, data: bytes, flush: bool=True) -> None:
        if self.local:
            self.process.stdin.write(data)
            if flush:
                self.process.stdin.flush()
        else:
            if self.channel.closed:
                raise Exception("ERROR: Cannot write to closed channel")
            self.channel.send(data)

    def cleanup(self):
        if self.local:
            if hasattr(self, 'process'):
                self.process.kill()
        else:
            self.client.exec_command(f'kill -9 {self.pid}')
            self.client.exec_command(f'rm -f {self.remote_filename}')
            self.client.close()

    def quit(self):
        super().quit()

        self.cleanup()