from detectors.detector import Detector
from inc.context import Context
from inc.config import Config
from models.message import NetworkDynamicMessage, NetworkConfigStaticMessage
import os
import logging
import subprocess
import pyshark
from pyshark.capture import capture
from time import sleep
import signal, psutil

logger = logging.getLogger('hardeninganalyzer')

def kill_process(parent_pid, signal=signal.SIGTERM):
    """
    Kill a process and all its children
    :param parent_pid: The PID of the parent process
    :param signal: The signal to send to the process
    """
    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess:
        return
    children = parent.children(recursive=True)
    pids = [parent.pid] + [child.pid for child in children]
    for pid in pids[::-1]:
        subprocess.run(['sudo', 'kill', f'-{signal.value}', f'{pid}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class ConnectionDetector(Detector):
    tcpdump_session = None

    def get_id(self) -> str:
        return 'connection'

    def static_analyze_network_security_config(self, config_file: str, config_xml: str, config_dict: dict) -> None:
        self.static_results.append(NetworkConfigStaticMessage(config_file, 'nsc', config_xml))
        
        if 'cleartextTrafficPermitted="true"' in config_xml:
            self.static_results.append(NetworkConfigStaticMessage(config_file, 'plain_http', config_xml))

    def static_analyze_info_plist(self, plist: dict):
        # Find App Transport Security settings
        if 'NSAppTransportSecurity' in plist:
            self.static_results.append(NetworkConfigStaticMessage(Context().app.get_decompiled_path(), 'ats', plist['NSAppTransportSecurity']))

            arbitrary_loads = ['NSAllowsArbitraryLoads', 'NSAllowsArbitraryLoadsForMedia', 'NSAllowsArbitraryLoadsInWebContent']
            for key in arbitrary_loads:
                if key in plist['NSAppTransportSecurity'] and plist['NSAppTransportSecurity'][key] == True:
                    plist_with_keys = {k: plist['NSAppTransportSecurity'][k] for k in arbitrary_loads if k in plist['NSAppTransportSecurity']}
                    self.static_results.append(NetworkConfigStaticMessage(Context().app.get_decompiled_path(), 'plain_http', plist_with_keys))

    def dynamic_before_analysis(self):
        if Context().is_ios():
            logger.info('Waiting before starting analysis of iOS app to minimize background traffic')
            sleep(Config().dynamic_analysis_ios_start_timeout)

        # Start tcpdump
        logger.info('Starting tcpdump')
        ip = Context().get_device_ip()
        adapter = Config().network_adapter
        if ip is None or adapter is None:
            logger.error('Cannot start tcpdump because IP address or network adapter is not configured')
            return
        
        pcap_file = os.path.join(Context().app.get_result_path(), 'tcpdump.pcap')
        self.tcpdump_session = subprocess.Popen(['sudo', 'tcpdump', '-i', adapter, '-w', pcap_file, 'net', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def dynamic_after_analysis(self):
        if self.tcpdump_session is None:
            return
        
        # Stop tcpdump
        kill_process(self.tcpdump_session.pid, signal.SIGINT)
        try:
            code = self.tcpdump_session.wait(10)
        except subprocess.TimeoutExpired:
            logger.info('Killing tcpdump')
            kill_process(self.tcpdump_session.pid, signal.SIGKILL)
            code = self.tcpdump_session.wait()

        pcap_file = os.path.join(Context().app.get_result_path(), 'tcpdump.pcap')
        if not os.path.exists(pcap_file):
            logger.error(f'Tcpdump exited with {code} and did not produce a pcap file')
            return

        if os.path.getsize(pcap_file) == 0:
            # No internet traffic occured
            return
        
        sleep(1)

        # Fix pcap file
        fixed_pcap_file = os.path.join(Context().app.get_result_path(), 'tcpdump-fixed.pcap')
        subprocess.run(['pcapfix', '--keep-outfile', '--deep-scan', '-o', fixed_pcap_file, pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pcap_file = fixed_pcap_file
        
        if not os.path.exists(fixed_pcap_file):
            logger.error(f'Pcapfix did not produce a pcap file')
            return

        # Analyze pcap file
        logger.info('Analyzing pcap file')
        try:
            cap = pyshark.FileCapture(pcap_file)

            for pkt_i, pkt in enumerate(cap):
                try:
                    if 'tls' in pkt: # TLS
                        content_type = pkt.tls.record_content_type
                        
                        if content_type == '22': # Handshake
                            handshake_type = pkt.tls.handshake_type
                            if handshake_type == '2': # Server Hello
                                cipher_suite = pkt.tls.handshake_ciphersuite.showname_value
                                tls_version = pkt.tls.record_version.showname_value

                                self.dynamic_results.append(NetworkDynamicMessage({
                                    'type': 'tls_conn',
                                    'packet': pkt_i,
                                    'data': {
                                        'cipher': cipher_suite,
                                        'version': tls_version
                                    },
                                    'detector': self.get_id()
                                }))

                    if 'http' in pkt: # HTTP
                        http_method = pkt.http.request_method
                        if http_method != 'CONNECT':
                            req = pkt.http.request_method + ' ' + pkt.http.request_uri + ' ' + pkt.http.request_version
                            self.dynamic_results.append(NetworkDynamicMessage({
                                'type': 'plain_http',
                                'packet': pkt_i,
                                'data': req,
                                'detector': self.get_id()
                            }))
                except AttributeError:
                    pass

            cap.close()
        except capture.TSharkCrashException as e:
            if 'appears to have been cut short in the middle of a packet' in str(e):
                # Capture might not have been stopped properly, ignore
                pass
            else:
                logger.error(f'Failed to analyze pcap file: {e}')
            try:
                cap.close()
            except Exception:
                pass
