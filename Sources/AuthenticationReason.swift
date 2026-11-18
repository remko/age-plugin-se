import Foundation

#if os(macOS)
  import Darwin
#endif

/// Builds the text shown in the Touch ID / password prompt, so the user can tell
/// what they are approving before they approve it.
///
/// The goal is to prevent approving by reflex, not to stop a deliberate attacker:
/// any process that can read the identity file can use the Secure Enclave key
/// directly and show whatever prompt it likes. For that reason the facts the plugin
/// can look up itself (which key, which processes) come first, and the text
/// supplied by the caller comes last and is labelled as such.
enum AuthenticationReason {
  static let callerReasonVariable = "AGE_SE_REASON"
  static let maxAncestors = 5

  static func describe(
    _ recipient: Recipient,
    environment env: [String: String] = ProcessInfo.processInfo.environment
  ) -> String {
    var lines: [String] = []

    if let name = keyName(for: recipient, environment: env) {
      lines.append("unlock key “\(clean(name))”")
    } else {
      let id = recipient.ageRecipient(type: .se)
      lines.append("unlock unnamed key \(id.prefix(12))…\(id.suffix(6))")
    }

    let chain = ancestorNames()
    if !chain.isEmpty {
      lines.append("Requested by: " + chain.map(clean).joined(separator: " › "))
    }

    if let reason = env[callerReasonVariable], !clean(reason).isEmpty {
      lines.append("Caller says: \(clean(reason))")
    }

    return lines.joined(separator: "\n")
  }

  /// Looks the key up in a names file with lines of the form
  /// `<recipient> <name>`. Blank lines and lines starting with `#` are ignored.
  static func keyName(for recipient: Recipient, environment env: [String: String]) -> String? {
    let configHome =
      env["XDG_CONFIG_HOME"].flatMap { $0.isEmpty ? nil : $0 }
      ?? (NSHomeDirectory() + "/.config")
    let path = configHome + "/age-plugin-se/names"
    guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
      return nil
    }

    var ids = [recipient.ageRecipient(type: .se), recipient.ageRecipient(type: .tag)]
    if recipient.mlkem768PublicKey != nil, let pq = try? recipient.ageTagPQRecipient {
      ids.append(pq)
    }

    for line in contents.split(whereSeparator: \.isNewline) {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      if trimmed.isEmpty || trimmed.hasPrefix("#") {
        continue
      }
      let parts = trimmed.split(maxSplits: 1, whereSeparator: \.isWhitespace)
      if parts.count == 2, ids.contains(String(parts[0])) {
        return parts[1].trimmingCharacters(in: .whitespaces)
      }
    }
    return nil
  }

  /// Names of the processes above the plugin, outermost first, ending with the
  /// process that started the plugin (normally `age`).
  static func ancestorNames() -> [String] {
    #if os(macOS)
      var names: [String] = []
      var pid = getppid()
      while pid > 1 && names.count < maxAncestors {
        guard let (name, parent) = processInfo(pid) else {
          break
        }
        names.append(name)
        pid = parent
      }
      return names.reversed()
    #else
      return []
    #endif
  }

  #if os(macOS)
    private static func processInfo(_ pid: pid_t) -> (name: String, parent: pid_t)? {
      var info = kinfo_proc()
      var size = MemoryLayout<kinfo_proc>.stride
      var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
      guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0, size > 0 else {
        return nil
      }
      let parent = info.kp_eproc.e_ppid

      // Prefer the name the process was started as (what `ps` shows), because some
      // programs live at paths that say little, e.g. Claude Code's executable is
      // named after its version number. The process chooses this name itself, which
      // is fine here: the prompt guards against approving by mistake, not forgery.
      if let name = launchName(pid) {
        return (name, parent)
      }

      // Otherwise the executable path; p_comm is cut off at 16 bytes.
      var buffer = [CChar](repeating: 0, count: 4096)
      if proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 {
        let path = String(
          decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return ((path as NSString).lastPathComponent, parent)
      }
      let comm = withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
        String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
      }
      return (comm, parent)
    }

    /// File name of argv[0], without the leading "-" of login shells.
    /// KERN_PROCARGS2 returns argc, then the executable path, padding NULs, then argv.
    private static func launchName(_ pid: pid_t) -> String? {
      var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
      var size = 0
      guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
        return nil
      }
      var bytes = [UInt8](repeating: 0, count: size)
      guard sysctl(&mib, u_int(mib.count), &bytes, &size, nil, 0) == 0 else {
        return nil
      }
      var i = MemoryLayout<Int32>.size
      while i < size && bytes[i] != 0 { i += 1 }  // executable path
      while i < size && bytes[i] == 0 { i += 1 }  // padding
      let start = i
      while i < size && bytes[i] != 0 { i += 1 }  // argv[0]
      guard i > start else {
        return nil
      }
      var name = (String(decoding: bytes[start..<i], as: UTF8.self) as NSString).lastPathComponent
      if name.hasPrefix("-") {
        name.removeFirst()
      }
      return name.isEmpty ? nil : name
    }
  #endif

  /// Removes line breaks, control characters and bidirectional overrides, so one
  /// part of the prompt cannot pass itself off as another, and keeps it short.
  static func clean(_ text: String) -> String {
    let kept = text.unicodeScalars.filter {
      $0.properties.generalCategory != .control && $0.properties.generalCategory != .format
    }
    let result = String(String.UnicodeScalarView(kept)).trimmingCharacters(in: .whitespaces)
    return result.count > 80 ? String(result.prefix(80)) + "…" : result
  }
}
