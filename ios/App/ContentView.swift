import SwiftUI
import NetworkExtension
import UIKit

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var input = ""

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                if vpn.hasProfile {
                    connected
                } else {
                    setup
                }
                if let error = vpn.error {
                    Text(error).foregroundColor(.red).font(.footnote).multilineTextAlignment(.center)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("VPN-TLS")
        }
    }

    /// Экран с профилем: большая кнопка и статус.
    private var connected: some View {
        VStack(spacing: 20) {
            Spacer().frame(height: 20)
            Button(action: vpn.toggle) {
                ZStack {
                    Circle().fill(vpn.isOn ? Color.green : Color.gray.opacity(0.3)).frame(width: 180, height: 180)
                    Image(systemName: "power").font(.system(size: 64, weight: .bold)).foregroundColor(.white)
                }
            }
            Text(statusText).font(.title3).bold()
            VStack(spacing: 4) {
                if !vpn.profileName.isEmpty { Text(vpn.profileName).font(.headline) }
                Text(vpn.serverHost).font(.subheadline).foregroundColor(.secondary)
            }
            Button("Удалить профиль", role: .destructive) { vpn.remove() }
                .padding(.top, 30)
        }
    }

    /// Экран без профиля: вставка строки vpntls://.
    private var setup: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Вставьте строку подключения vpntls:// — её выдаёт команда «vpn-server client add».")
                .font(.subheadline).foregroundColor(.secondary)
            TextEditor(text: $input)
                .font(.system(.footnote, design: .monospaced))
                .frame(height: 140)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.4)))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            HStack {
                Button("Вставить из буфера") {
                    input = UIPasteboard.general.string ?? ""
                }
                Spacer()
                Button("Сохранить") { vpn.save(link: input) }
                    .buttonStyle(.borderedProminent)
                    .disabled(input.isEmpty)
            }
        }
    }

    private var statusText: String {
        switch vpn.status {
        case .connected: return "Подключено"
        case .connecting: return "Подключение…"
        case .reasserting: return "Переподключение…"
        case .disconnecting: return "Отключение…"
        case .disconnected: return "Отключено"
        default: return "Не настроено"
        }
    }
}
