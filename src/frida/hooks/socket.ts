import { logFunction } from "../inc/log";
import { CallbackData, addPostHook, addPreHook } from "./native";

/**
 * Will pretend that the given port is unused even if it might be open, and log checks for this
 * @param port 
 */
export function addOpenPortHook(port: number) {
    let openPortHandler = (data: CallbackData, sockaddr: NativePointer) => {
        if (sockaddr.isNull()) return;

        let ntohs = new NativeFunction(Module.findExportByName(null, 'ntohs'), 'uint', ['uint']);
        let ntohl = new NativeFunction(Module.findExportByName(null, 'ntohl'), 'uint', ['uint']);

        let sockFamily = sockaddr.readShort();
        let sockPort = ntohs(sockaddr.add(2).readUShort());
        let sockAddr = ntohl(sockaddr.add(4).readU32());

        if (sockFamily == 2 && sockPort == port && (sockAddr == 0 || sockAddr == 0x7f000001)) {
            logFunction({
                ...data,
                args: [
                    {
                        family: sockFamily,
                        port: sockPort,
                        addr: sockAddr
                    },
                ]
            });
            
            return true;
        }

        return false;
    }

    // Signature: int sockfd, struct sockaddr *addr, socklen_t addrlen
    let sockFunctions1 = ['connect', 'bind', 'accept', 'getpeername', 'getsockname'];
    addPreHook(sockFunctions1, ['int', 'ptr', 'ptr'], (data) => {
        let sockaddr = data.args[1];

        if (openPortHandler(data, sockaddr)) {
            // Assign random port
            sockaddr.add(2).writeUShort(0); 
        }
    });

    addPostHook(sockFunctions1, ['int', 'ptr', 'ptr'], (data) => {
        let sockaddr = data.args[1];

        if (openPortHandler(data, sockaddr)) {
            // Restore port
            sockaddr.add(2).writeUShort(port);
        }
    });

    // Signature: int sockfd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addrlen
    let sockFunctions2 = ['recvfrom', 'sendto'];
    addPreHook(sockFunctions2, ['int', 'ptr', 'int', 'int', 'ptr', 'ptr'], (data) => {
        let sockaddr = data.args[4];

        if (openPortHandler(data, sockaddr)) {
            // Assign random port
            sockaddr.add(2).writeUShort(0); 
        }
    });

    addPostHook(sockFunctions2, ['int', 'ptr', 'int', 'int', 'ptr', 'ptr'], (data) => {
        let sockaddr = data.args[4];

        if (openPortHandler(data, sockaddr)) {
            // Restore port
            sockaddr.add(2).writeUShort(port);
        }
    });
}