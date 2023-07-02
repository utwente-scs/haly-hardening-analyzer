# Formats for results of static and dynamic analysis. Each message indicates a specific implementation of a hardening method.
from os.path import basename

class StaticMessage:
    def __init__(self, type: str, source: str, confident: bool = True):
        """ 
        Create a static result message
        :param type: type of the message
        :param source: source file
        :param confident: if true, we are quite confident that the result is not a false positive
        """
        self.type = type
        self.source = source
        self.confident = confident

    def to_dict(self) -> dict:
        """
        Convert the message to a dict
        :return: dict containing the message data
        """
        return self.__dict__.copy()
    
    def should_group(self, other: 'StaticMessage') -> bool:
        """
        Check if two messages should be grouped together during reporting
        :param other: The other message
        :return: True if the messages should be grouped, False otherwise
        """
        return self.type == other.type and self.confident == other.confident
    
    def summary(self) -> str:
        """
        Get a human-readable summary of the message
        :return: The summary
        """
        return f'{self.type} ' + ('(not confident)' if not self.confident else '')
    
    @staticmethod
    def from_dict(message: dict) -> 'StaticMessage':
        """
        Convert a dict to a message
        """
        match message['type']:
            case 'string':
                return StringStaticMessage(message['source'], message['pattern'], message, message['confident'])
            case 'native':
                return NativeFunctionStaticMessage(message['source'], message['function'], message, message['confident'])
            case 'svc':
                return SvcStaticMessage(message['source'], message['svc_id'], message['svc_syscall'], message['offset'], message['confident'])
            case 'smali':
                return SmaliStaticMessage(message['source'], message['function'], message, message['confident'])
            case _:
                return StaticMessage(message['type'], message['source'], message['confident'])

class StringStaticMessage(StaticMessage):
    def __init__(self, source: str, pattern: str, match: dict, confident: bool = True):
        """
        Create a static string result message
        :param source: file in which the string was found
        :param pattern: pattern that was matched
        :param match: match dict containing the line and line number where the match was found
        :param confident: if true, we are quite confident that the result is not a false positive
        """
        super().__init__('string', source, confident)
        self.pattern = pattern
        for field in ['line', 'line_nr']:
            setattr(self, field, match[field])

    def should_group(self, other: 'StaticMessage') -> bool:
        return super().should_group(other) and self.pattern == other.pattern
    
    def summary(self) -> str:
        return f'{self.pattern} ' + ('(not confident)' if not self.confident else '')

class NativeFunctionStaticMessage(StaticMessage):
    def __init__(self, source: str, function: str, results: dict, confident: bool = True):
        """
        Create a static native function / syscall / instruction result message
        :param source: file in which the function / syscall / instruction was found
        :param function: function that was matched
        :param results: results dict containing the offset of the function call and passed arguments
        :param confident: if true, we are quite confident that the result is not a false positive
        """
        super().__init__('native', source, confident)
        self.function = function
        for field in ['args', 'offset']:
            setattr(self, field, results[field])
    
    def should_group(self, other: 'StaticMessage') -> bool:
        return super().should_group(other) and self.function == other.function
    
    def summary(self) -> str:
        return f'{self.function} ' + ('(not confident)' if not self.confident else '')

class SvcStaticMessage(StaticMessage):
    def __init__(self, source: str, svc_id: int | None, svc_syscall: str | None, offset: int, confident: bool = True):
        """
        Create a static svc result message
        :param source: file in which the svc was found
        :param svc_id: svc syscall id
        :param svc_syscall: svc syscall name
        :param offset: offset of the svc call
        :param confident: if true, we are quite confident that the result is not a false positive
        """
        super().__init__('svc', source, confident)
        self.svc_id = svc_id
        self.svc_syscall = svc_syscall
        self.module = basename(source)
        self.offset = offset

    def should_group(self, other: 'StaticMessage') -> bool:
        return False
    
    def summary(self) -> str:
        return f'{self.svc_syscall} ' if self.svc_syscall else 'Unknown syscall ' + ('(not confident)' if not self.confident else '')

class SmaliStaticMessage(StaticMessage):
    def __init__(self, source: str, function: str, results: dict, confident: bool = True):
        """
        Create a static smali result message
        :param source: file in which the smali was found
        :param function: function that was matched
        :param results: results dict containing the line number and line where the match was found
                        as well as possibly arguments passed to the function and a list of items the result is compared to
        :param confident: if true, we are quite confident that the result is not a false positive
        """
        super().__init__('smali', source, confident)
        self.function = function
        for field in ['line_nr', 'line', 'java_line_nr']:
            setattr(self, field, results[field])
        for field in ['args', 'comparisons']:
            if field in results:
                setattr(self, field, results[field])
            else:
                setattr(self, field, [])

    def should_group(self, other: 'StaticMessage') -> bool:
        return super().should_group(other) and self.function == other.function
    
    def summary(self) -> str:
        return f'{self.function} ' + ('(not confident)' if not self.confident else '')
    
class NetworkConfigStaticMessage(StaticMessage):
    def __init__(self, source: str, type: str, data: dict):
        """
        Create a static network config result message
        :param source: file in which the network config was found
        :param type: type of network config
        :param data: data dict containing the network config data
        """
        super().__init__('network_config', source, True)
        self.config_type = type
        self.data = data

class DynamicMessage:
    def __init__(self, message):
        """
        Create a dynamic result message
        :param message: dict containing the message data
        """
        self.type = message['type']
        self.context = message['context'] # native / java / objc
        self.function = message['function']
        self.args = message['args']
        self.backtrace = message['backtrace']
        self.java_backtrace = message['java_backtrace'] if 'java_backtrace' in message else None
        self.confident = message['confident']
        if 'detector' in message:
            self.detector = message['detector']

    @staticmethod
    def from_dict(message: dict) -> 'DynamicMessage':
        """
        Construct a message from a dict
        :param message: DynamicMessage dict
        :return: DynamicMessage
        """
        match message['type']:
            case 'function':
                return FunctionDynamicMessage(message)
            case 'build':
                return BuildDynamicMessage(message)
            case 'file':
                return FileDynamicMessage(message)
            case 'app':
                return AppDynamicMessage(message)
            case 'svc': 
                return SvcDynamicMessage(message)
            case 'info':
                return InfoDynamicMessage(message)
            case 'tls_conn' | 'plain_http':
                return NetworkDynamicMessage(message)
            case _:
                return DynamicMessage(message)

    def to_dict(self) -> dict:
        """
        Convert the message to a dict
        :return: dict containing the message data
        """
        data = self.__dict__.copy()
        if 'detector' in data:
            data.pop('detector')
        return data
    
    def should_group(self, other: 'DynamicMessage') -> bool:
        """
        Check if two messages should be grouped together during reporting
        :param other: The other message
        :return: True if the messages should be grouped, False otherwise
        """
        return self.type == other.type and self.context == other.context and self.function == other.function and self.args == other.args
    
    def summary(self) -> str:
        """
        Get a human-readable summary of the message
        :return: The summary
        """
        return f'{self.function} ' + ('(not confident)' if not self.confident else '')

class FunctionDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic function result message
        :param message: dict containing the message data
        """
        super().__init__(message)
        assert self.type == 'function'

    def should_group(self, other: DynamicMessage) -> bool:
        # Group _dyld_get_image_name and _dyld_image_count
        return self.function == other.function and (self.args == other.args or self.function.startswith('_dyld_'))
    
    def summary(self) -> str:
        return f'{self.function} ' + ('(not confident)' if not self.confident else '')

class BuildDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic build result message
        :param message: dict containing the message data
        """
        super().__init__(message)
        assert self.type == 'build'
        self.field = message['field']

    def should_group(self, other: 'DynamicMessage') -> bool:
        return self.field == other.field
    
    def summary(self) -> str:
        return f'{self.field} ' + ('(not confident)' if not self.confident else '')

class FileDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic file result message
        :param message: dict containing the message data
        """
        super().__init__(message)
        assert self.type == 'file'
        self.file = message['file']

    def should_group(self, other: 'DynamicMessage') -> bool:
        return self.file == other.file or ('proc' in self.file and 'proc' in other.file and 'task' in self.file and 'task' in other.file)
    
    def summary(self) -> str:
        return f'{self.file} ' + ('(not confident)' if not self.confident else '')

class AppDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic app result message
        :param message: dict containing the message data
        """
        super().__init__(message)
        assert self.type == 'app'
        self.app = message['app']

    def should_group(self, other: 'DynamicMessage') -> bool:
        return self.app == other.app
    
    def summary(self) -> str:
        return f'{self.app} ' + ('(not confident)' if not self.confident else '')

class SvcDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic svc result message
        :param message: dict containing the message data
        """
        super().__init__(message)
        assert self.type == 'svc'
        self.svc_id = message['svc_id']
        self.svc_syscall = message['svc_syscall']

    def should_group(self, other: 'DynamicMessage') -> bool:
        return self.svc_id == other.svc_id
    
    def summary(self) -> str:
        return f'{self.svc_syscall} (svc {self.svc_id}) ' + ('(not confident)' if not self.confident else '')

class InfoDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic info result message
        :param message: dict containing the message data
        """
        # This message only has a detector, type and info field
        # Fill the rest of the default fields with None
        for field in ['context', 'function', 'args', 'backtrace', 'confident']:
            message[field] = None
        super().__init__(message)
        assert self.type == 'info'
        self.info = message['info']

class NetworkDynamicMessage(DynamicMessage):
    def __init__(self, message):
        """
        Create a dynamic info result message
        :param message: dict containing the message data
        """
        # This message only has a detector, type, and packet, data field
        # Fill the rest of the default fields with None
        for field in ['context', 'function', 'args', 'confident']:
            message[field] = None
        message['backtrace'] = []
        super().__init__(message)
        assert self.type in ['tls_conn', 'plain_http']
        self.packet = message['packet']
        self.data = message['data']

    def should_group(self, other: 'DynamicMessage') -> bool:
        return self.type == other.type

    def summary(self) -> str:
        if self.type == 'tls_conn':
            return 'TLS Connection'
        else:
            return 'Plaintext HTTP Request'