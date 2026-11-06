import SwiftUI

@main
struct VPNTLSApp: App {
    @StateObject private var vpn = VPNManager()

    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(vpn)
        }
    }
}
