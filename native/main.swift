// Hôte de messagerie native : fait demander Touch ID par macOS pour l'extension.
//
// Une clé P-256 est créée dans la Secure Enclave, utilisable seulement après Touch ID
// (empreintes actuelles). Elle ne sort jamais de la puce : l'extension garde son « handle »
// (blob chiffré par la puce, inutilisable sur un autre Mac). Pour obtenir le secret,
// on fait un échange ECDH avec une clé publique fixe, puis HKDF : 32 octets qui emballent
// la clé du coffre. Sans le doigt, la puce refuse l'échange.
//
// Protocole Chrome : longueur sur 4 octets (ordre natif) + JSON, sur stdin/stdout.
import CryptoKit
import Foundation
import LocalAuthentication

let VERSION = 1

func readMessage() -> [String: Any]? {
  let stdin = FileHandle.standardInput
  let header = stdin.readData(ofLength: 4)
  guard header.count == 4 else { return nil }
  let length = header.withUnsafeBytes { $0.load(as: UInt32.self) }
  guard length > 0, length < 1_000_000 else { return nil }
  let body = stdin.readData(ofLength: Int(length))
  return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
}

func send(_ message: [String: Any]) {
  let body = try! JSONSerialization.data(withJSONObject: message)
  var length = UInt32(body.count)
  FileHandle.standardOutput.write(Data(bytes: &length, count: 4))
  FileHandle.standardOutput.write(body)
}

func fail(_ code: String, _ message: String) -> [String: Any] {
  ["ok": false, "code": code, "error": message]
}

func context(_ reason: String) -> LAContext {
  let ctx = LAContext()
  ctx.localizedReason = reason
  ctx.localizedCancelTitle = "Annuler"
  return ctx
}

func deriveSecret(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey, peer: P256.KeyAgreement.PublicKey) throws -> String {
  let shared = try key.sharedSecretFromKeyAgreement(with: peer)
  let secret = shared.hkdfDerivedSymmetricKey(
    using: SHA256.self, salt: Data("authenticator-touchid".utf8), sharedInfo: Data("dek-wrap v1".utf8), outputByteCount: 32)
  return secret.withUnsafeBytes { Data($0).base64EncodedString() }
}

func describe(_ error: Error) -> [String: Any] {
  if let la = error as? LAError {
    switch la.code {
    case .userCancel, .appCancel, .systemCancel: return fail("cancel", "Touch ID annulé.")
    case .biometryLockout: return fail("lockout", "Touch ID est bloqué après trop d’essais : déverrouille ton Mac avec son mot de passe, puis réessaie.")
    case .biometryNotEnrolled: return fail("unavailable", "Aucune empreinte n’est enregistrée sur ce Mac.")
    case .biometryNotAvailable: return fail("unavailable", "Touch ID n’est pas disponible (Mac fermé ou clavier sans Touch ID ?).")
    default: break
    }
  }
  let ns = error as NSError
  // -25293 / -128 : annulation remontée par la Secure Enclave
  if ns.code == -128 || ns.code == Int(errSecUserCanceled) { return fail("cancel", "Touch ID annulé.") }
  return fail("error", "\(ns.localizedDescription) (\(ns.domain) \(ns.code))")
}

func handle(_ msg: [String: Any]) -> [String: Any] {
  let reason = (msg["reason"] as? String) ?? "déverrouiller Authenticator"
  switch msg["cmd"] as? String {
  case "ping":
    var err: NSError?
    let ok = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    return ["ok": true, "version": VERSION, "secureEnclave": SecureEnclave.isAvailable, "biometry": ok,
            "biometryError": err?.localizedDescription ?? NSNull()]

  case "enroll":
    guard SecureEnclave.isAvailable else { return fail("unavailable", "Ce Mac n’a pas de Secure Enclave.") }
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfErr)
    else { return fail("error", "Contrôle d’accès impossible à créer.") }
    do {
      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context(reason))
      let peer = P256.KeyAgreement.PrivateKey().publicKey // clé publique fixe, son privé est jeté
      let secret = try deriveSecret(key, peer: peer)
      return ["ok": true, "key": key.dataRepresentation.base64EncodedString(),
              "peer": peer.rawRepresentation.base64EncodedString(), "secret": secret]
    } catch { return describe(error) }

  case "derive":
    guard let keyB64 = msg["key"] as? String, let keyData = Data(base64Encoded: keyB64),
          let peerB64 = msg["peer"] as? String, let peerData = Data(base64Encoded: peerB64)
    else { return fail("error", "Requête incomplète.") }
    do {
      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData, authenticationContext: context(reason))
      let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerData)
      return ["ok": true, "secret": try deriveSecret(key, peer: peer)]
    } catch {
      let ns = error as NSError
      // Clé invalidée (empreintes modifiées) ou blob d'un autre Mac
      if ns.domain == "CryptoTokenKit" || ns.code == -3 || ns.code == Int(errSecItemNotFound) {
        return fail("invalid", "La clé Touch ID n’est plus valable (empreintes modifiées ou autre Mac) : réactive Touch ID dans les réglages.")
      }
      return describe(error)
    }

  default:
    return fail("error", "Commande inconnue.")
  }
}

if let msg = readMessage() { send(handle(msg)) } else { send(fail("error", "Message illisible.")) }
