import Foundation
import NetworkExtension
import Mobile

/// Системное расширение VPN: поднимает туннель через Go-ядро (Mobile.xcframework)
/// и гоняет пакеты между iOS и туннелем.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: MobileTunnel?
    private lazy var bridge = Bridge(provider: self)

    private struct Settings: Decodable {
        let ip: String
        let dns: [String]
        let mtu: Int
        let server: String
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let link = proto.providerConfiguration?["link"] as? String else {
            completionHandler(Self.error("Нет строки подключения"))
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            var err: NSError?
            guard let t = MobileConnect(link, self.bridge, self.bridge, &err) else {
                completionHandler(err ?? Self.error("Не удалось подключиться"))
                return
            }
            guard let s = try? JSONDecoder().decode(Settings.self, from: Data(t.settings().utf8)),
                  let (addr, mask) = Self.parseCIDR(s.ip) else {
                t.close()
                completionHandler(Self.error("Неверные настройки от сервера"))
                return
            }
            self.tunnel = t

            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: s.server)
            let v4 = NEIPv4Settings(addresses: [addr], subnetMasks: [mask])
            v4.includedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = v4
            // Туннель только IPv4. Весь IPv6 тоже забираем в туннель и там отбрасываем,
            // чтобы он не ушёл мимо VPN.
            let v6 = NEIPv6Settings(addresses: ["fd00:7670:6e74::2"], networkPrefixLengths: [64])
            v6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = v6
            let dns = NEDNSSettings(servers: s.dns)
            dns.matchDomains = [""] // все DNS-запросы — через туннель
            settings.dnsSettings = dns
            settings.mtu = NSNumber(value: s.mtu)

            self.setTunnelNetworkSettings(settings) { error in
                if let error {
                    t.close()
                    completionHandler(error)
                    return
                }
                completionHandler(nil)
                self.readPackets()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        tunnel?.close()
        tunnel = nil
        completionHandler()
    }

    /// Пакеты от iOS → в туннель.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let t = self.tunnel else { return }
            for p in packets { t.writePacket(p) }
            self.readPackets()
        }
    }

    fileprivate func failed(_ detail: String) {
        cancelTunnelWithError(Self.error(detail))
    }

    static func error(_ text: String) -> NSError {
        NSError(domain: "VPNTLS", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    /// "10.8.0.2/24" → ("10.8.0.2", "255.255.255.0")
    static func parseCIDR(_ cidr: String) -> (String, String)? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let bits = Int(parts[1]), (0...32).contains(bits) else { return nil }
        let m: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - UInt32(bits))
        let mask = [24, 16, 8, 0].map { String((m >> UInt32($0)) & 0xff) }.joined(separator: ".")
        return (String(parts[0]), mask)
    }
}

/// Мост для Go: пакеты из туннеля → iOS, состояние соединения → система.
final class Bridge: NSObject, MobilePacketWriterProtocol, MobileListenerProtocol {
    private weak var provider: PacketTunnelProvider?

    init(provider: PacketTunnelProvider) { self.provider = provider }

    func writePacket(_ p: Data?) {
        guard let p, let provider else { return }
        provider.packetFlow.writePackets([p], withProtocols: [NSNumber(value: AF_INET)])
    }

    func onStatus(_ state: String?, detail: String?) {
        guard let provider else { return }
        switch state {
        case "reconnecting": provider.reasserting = true
        case "connected": provider.reasserting = false
        case "failed": provider.failed(detail ?? "Подключение отклонено")
        default: break
        }
    }
}
