import Foundation
import NetworkExtension

/// Профиль VPN в настройках iOS: сохранение строки подключения, включение, статус.
final class VPNManager: ObservableObject {
    static let tunnelBundleID = "tech.extree.vpntls.tunnel"

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var link: String = ""
    @Published var error: String?

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    var hasProfile: Bool { manager != nil && !link.isEmpty }
    var profileName: String { URL(string: link)?.fragment ?? "" }
    var serverHost: String { URL(string: link)?.host ?? "" }
    var isOn: Bool { [.connected, .connecting, .reasserting].contains(status) }

    init() { load() }

    func load() {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            DispatchQueue.main.async {
                self.manager = managers?.first
                let proto = self.manager?.protocolConfiguration as? NETunnelProviderProtocol
                self.link = proto?.providerConfiguration?["link"] as? String ?? ""
                self.observe()
            }
        }
    }

    /// Сохраняет строку vpntls:// как профиль VPN. iOS спросит разрешение при первом сохранении.
    func save(link raw: String) {
        let link = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: link), url.scheme == "vpntls", let host = url.host, url.user != nil else {
            error = "Это не строка подключения vpntls://"
            return
        }
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.tunnelBundleID
        proto.serverAddress = host
        proto.providerConfiguration = ["link": link]
        m.protocolConfiguration = proto
        m.localizedDescription = "VPN-TLS"
        m.isEnabled = true
        m.saveToPreferences { err in
            DispatchQueue.main.async {
                if let err {
                    self.error = err.localizedDescription
                    return
                }
                // После сохранения профиль нужно перечитать, иначе первый запуск может не сработать.
                m.loadFromPreferences { _ in
                    DispatchQueue.main.async {
                        self.manager = m
                        self.link = link
                        self.error = nil
                        self.observe()
                    }
                }
            }
        }
    }

    func toggle() {
        guard let m = manager else { return }
        if isOn {
            m.connection.stopVPNTunnel()
            return
        }
        do {
            try m.connection.startVPNTunnel()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func remove() {
        manager?.connection.stopVPNTunnel()
        manager?.removeFromPreferences { _ in
            DispatchQueue.main.async {
                self.manager = nil
                self.link = ""
                self.status = .invalid
            }
        }
    }

    private func observe() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        guard let m = manager else {
            status = .invalid
            return
        }
        status = m.connection.status
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            self?.status = m.connection.status
        }
    }
}
