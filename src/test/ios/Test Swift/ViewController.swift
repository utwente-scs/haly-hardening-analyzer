//
//  ViewController.swift
//  Test Swift
//
//  Created by Wilco van Beijnum on 05/04/2023.
//

import UIKit
import Darwin
import DeviceCheck
import MachO.dyld
import Alamofire

class ViewController: UIViewController {
    
    @IBOutlet var helloWorldLabel: UITextView!
    let PT_DENY_ATTACH: CInt = 31
    let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
    
    var session: Session? = nil

    override func viewDidLoad() {
        super.viewDidLoad()

        ///////////
        // Debug //
        ///////////
        setText("DEBUG", "")

        // Block tracing with ptrace
        let ptrace = dlsym(RTLD_DEFAULT, "ptrace")
        typealias ptraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptraceFunction = unsafeBitCast(ptrace, to: ptraceType.self)
        let result = ptraceFunction(PT_DENY_ATTACH, getpid(), 0, 0)
        setText("ptrace", result == 0)
        
        // Check if getppid returns launchd (1)
        setText("getppid", getppid() == 1)

        // Check if P_TRACED flag is not set using sysctl
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        setText("P_TRACED", info.kp_proc.p_flag & P_TRACED == 0)

        ///////////////
        // Emulation //
        ///////////////
        setText("\nEMULATION", "")

        // Check if SIMULATOR_RUNTIME_VERSION is not set using getenv
        let simulator = getenv("SIMULATOR_RUNTIME_VERSION")
        setText("getenv", simulator == nil)

        // Check if SIMULATOR_RUNTIME_VERSION is not set using processInfo.environment
        let environment = ProcessInfo.processInfo.environment
        setText("environment", environment["SIMULATOR_RUNTIME_VERSION"] == nil)

        // List all environment variables
        for (key, value) in environment {
            setText(key, value)
        }

        // Check if /Applications/Xcode.app is not present
        let xcode = FileManager.default.fileExists(atPath: "/Applications/Xcode.app")
        setText("Xcode", !xcode)

        /////////////
        // Hooking //
        /////////////
        setText("\nHOOKING", "")
        // Check if frida-server is not present
        let frida = FileManager.default.fileExists(atPath: "/usr/sbin/frida-server")
        setText("frida-server", !frida)

        // Check if /usr/lib/frida is not present
        let fridaLib = FileManager.default.fileExists(atPath: "/usr/lib/frida")
        setText("frida", !fridaLib)

        // Check if Cydia substrate is not present
        let substrate = FileManager.default.fileExists(atPath: "/Library/MobileSubstrate")
        setText("substrate", !substrate)
        
        // Loop through loaded dylibs and check that MobileSubstrate is not loaded
        let imageList = _dyld_image_count()
        var loaded = false
        for i in 0..<imageList {
            let name = _dyld_get_image_name(i)
            // setText("Lib: ", String(cString: name!))
            if String(cString: name!).lowercased().contains("substrate") {
                loaded = true
            }
        }
        setText("MobileSubstrate", !loaded)

        ///////////////
        // Keylogger //
        ///////////////
        setText("\nKEYLOGGER", "")

        let textInputMode = helloWorldLabel.textInputMode?.value(forKey: "displayName")
        setText("textInputMode", true)

        let activeInputModes = UITextInputMode.activeInputModes
        setText("activeInputModes", true)

        helloWorldLabel.inputView = UIView()
        setText("inputView", true)

        //////////
        // Root //
        //////////
        setText("\nROOT", "")

        // Check if /var/lib/cydia is not present
        let cydia = FileManager.default.fileExists(atPath: "/var/lib/cydia")
        setText("Cydia", !cydia)

        // Check if /Applications/Sileo.app is not present
        let sileo = FileManager.default.fileExists(atPath: "/Applications/Sileo.app")
        setText("Sileo", !sileo)

        // Check if /cores/binpack/Applications/palera1nLoader.app is not present
        let palera1nLoader = FileManager.default.fileExists(atPath: "/cores/binpack/Applications/palera1nLoader.app")
        setText("palera1nLoader", !palera1nLoader)

        // Check if /Applications is read-only
        let applications = FileManager.default.isWritableFile(atPath: "/Applications")
        setText("/Applications rw", !applications)

        // Check if can write a file to /Applications
        let testFile = "/Applications/test.txt"
        let testText = "test"
        var writable = false
        do {
            try testText.write(toFile: testFile, atomically: true, encoding: String.Encoding.utf8)
            writable = true
            try FileManager.default.removeItem(atPath: testFile)
        } catch {
        }
        setText("/Applications write", !writable)

        // Check if sileo:// is not present
        let sileoURL = UIApplication.shared.canOpenURL(URL(string: "sileo://")!)
        setText("sileo://", !sileoURL)

        // Check if cydia:// is not present
        let cydiaURL = UIApplication.shared.canOpenURL(URL(string: "cydia://")!)
        setText("cydia://", !cydiaURL)

        // Check if fork() is blocked
        let fork = dlsym(RTLD_DEFAULT, "fork")
        typealias forkType = @convention(c) () -> pid_t
        let forkFunction = unsafeBitCast(fork, to: forkType.self)
        let forkResult = forkFunction()
        setText("fork", forkResult == -1)

        //////////////////
        // Screenreader //
        //////////////////
        // Not implemented for iOS

        /////////
        // SVC //
        /////////
        // Already tested on Android

        ////////////
        // Tamper //
        ////////////
        setText("\nTAMPER", "")

        // Check if DCAppAttestService succeeds
        if #available(iOS 14.0, *) {
            DCAppAttestService.shared.attestKey("", clientDataHash: Data()) { (key, error) in
                if (error != nil) {
                    self.setText("DCAppAttestService", false)
                } else {
                    self.setText("DCAppAttestService", true)
                }
            }
        } else {
            self.setText("DCAppAttestService", "Unavailable")
        }
        
        /////////////
        // Pinning //
        /////////////
        setText("\nPINNING", "")

        // Get https://google.com with pinned certificate (google.der) using Alamofire 5.6.4
        let pinnedCertificates: [SecCertificate] = [SecCertificateCreateWithData(nil, NSData(contentsOfFile: Bundle.main.path(forResource: "google", ofType: "der")!)! as CFData)!]
        let serverTrustManager = ServerTrustManager(evaluators: ["www.google.com": PinnedCertificatesTrustEvaluator(certificates: pinnedCertificates, acceptSelfSignedCertificates: true, performDefaultValidation: true, validateHost: true)])
        session = Session(serverTrustManager: serverTrustManager)
        session!.request("https://www.google.com").response { response in
            if let error = response.error {
                self.setText("Alamofire TLS pinning", false)
                self.setText(error.localizedDescription, "")
            } else {
                self.setText("Alamofire TLS pinning", true)
            }
        }
    }

    @objc func setText(_ key: String, _ text: Any) {
        var value: String
        if (text is Bool) {
            value = (text as! Bool) ? "OK" : "NOT OK"
        } else {
            value = String(describing: text)
        }

        if (helloWorldLabel.text == nil || helloWorldLabel.text == "") {
            helloWorldLabel.text = key + ": " + value
        } else {
            helloWorldLabel.text! += "\n" + key + ": " + value
        }
    }
}

