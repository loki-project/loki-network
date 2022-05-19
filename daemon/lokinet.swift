import AppKit
import Foundation
import NetworkExtension

let app = NSApplication.shared

let START = "--start"
let STOP = "--stop"

let HELP_STRING = "usage: lokinet [--start|--stop]"

class LokinetMain: NSObject, NSApplicationDelegate {
    var vpnManager = NETunnelProviderManager()
    let lokinetComponent = "com.loki-project.lokinet.network-extension"
    var mode = ""

    func applicationDidFinishLaunching(_: Notification) {
        if self.mode == START {
            setupVPNTunnel()
        }
        else if self.mode == STOP {
            tearDownVPNTunnel()
        } else {
            self.result(msg: HELP_STRING)
        }

    }

    func bail() {
        app.terminate(self)
    }

    func result(msg: String) {
        NSLog(msg)
        // TODO: does lokinet continue after this?
        self.bail()
    }

    func tearDownVPNTunnel() {
        NSLog("Stopping Lokinet")
        NETunnelProviderManager.loadAllFromPreferences { [self] (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
                self.result(msg: error.localizedDescription)
                return
            }

            if let savedManagers = savedManagers {
                for manager in savedManagers {
                    if (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.lokinetComponent {
                        manager.isEnabled = false
                        self.result(msg: "Lokinet Down")
                        return
                    }
                }
            }
            self.result(msg: "Lokinet is not up")
        }
    }

    func setupVPNTunnel() {
        NSLog("Starting up Lokinet")
        NETunnelProviderManager.loadAllFromPreferences { [self] (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
                self.result(msg: error.localizedDescription)
                return
            }

            if let savedManagers = savedManagers {
                for manager in savedManagers {
                    if (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.lokinetComponent {
                        NSLog("Found saved VPN Manager")
                        self.vpnManager = manager
                    }
                }
            }
            let providerProtocol = NETunnelProviderProtocol()
            providerProtocol.serverAddress = "loki.loki" // Needs to be set to some non-null dummy value
            providerProtocol.username = "anonymous"
            providerProtocol.providerBundleIdentifier = self.lokinetComponent
            providerProtocol.enforceRoutes = true
            // macos seems to have trouble when this is true, and reports are that this breaks and
            // doesn't do what it says on the tin in the first place.  Needs more testing.
            providerProtocol.includeAllNetworks = false
            self.vpnManager.protocolConfiguration = providerProtocol
            self.vpnManager.isEnabled = true
            // self.vpnManager.isOnDemandEnabled = true
            self.vpnManager.localizedDescription = "lokinet"
            self.vpnManager.saveToPreferences(completionHandler: { [self] error -> Void in
                if error != nil {
                    NSLog("Error saving to preferences")
                    self.result(msg: error!.localizedDescription)
                } else {
                    self.vpnManager.loadFromPreferences(completionHandler: { error in
                        if error != nil {
                            NSLog("Error loading from preferences")
                            self.result(msg: error!.localizedDescription)
                        } else {
                            do {
                                NSLog("Trying to start")
                                self.initializeConnectionObserver()
                                try self.vpnManager.connection.startVPNTunnel()
                            } catch let error as NSError {
                               self.result(msg: error.localizedDescription)
                            } catch {
                                self.result(msg: "There was a fatal error")
                            }
                        }
                    })
                }
            })
        }
    }

    func initializeConnectionObserver() {
        NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object: vpnManager.connection, queue: OperationQueue.main) { [self] _ -> Void in
            if self.vpnManager.connection.status == .invalid {
                self.result(msg: "VPN configuration is invalid")
            } else if self.vpnManager.connection.status == .disconnected {
                self.result(msg: "VPN is disconnected.")
            } else if self.vpnManager.connection.status == .connecting {
                NSLog("VPN is connecting...")
            } else if self.vpnManager.connection.status == .reasserting {
                NSLog("VPN is reasserting...")
            } else if self.vpnManager.connection.status == .disconnecting {
                NSLog("VPN is disconnecting...")
            } else if self.vpnManager.connection.status == .connected {
                self.result(msg: "VPN Connected")
            }
        }
    }
}

let args = CommandLine.arguments

if args.count > 1 {
    let delegate = LokinetMain()
    delegate.mode = args[1]
    app.delegate = delegate
    app.run()
} else {
    NSLog(HELP_STRING)
}
