class AgePluginSe < Formula
  desc "Age plugin for Apple Secure Enclave"
  homepage "https://github.com/remko/age-plugin-se"
  url "https://github.com/remko/age-plugin-se/archive/refs/tags/v0.0.4.zip"
  version "0.0.4"
  sha256 "7b8ffbd6ad771fb249b4d59fff45b2aa8def9478c31871ab760a440617943c39"
  license "MIT"
  head "https://github.com/remko/age-plugin-se.git", branch: "main"

  depends_on :macos
  depends_on xcode: ["14.0", :build]
  depends_on "age" => :test

  def install
    system "make", "PREFIX=#{prefix}", "RELEASE=1", "all"
    system "make", "PREFIX=#{prefix}", "RELEASE=1", "install"
  end

  test do
    out = `age-plugin-se keygen`
    have_se = $CHILD_STATUS.exitstatus == 0 || !out.include?("Secure Enclave not supported on this device")
    if have_se
      recipient = shell_output("age-plugin-se keygen --access-control=none -o key.txt").split[2]
      system "age", "--encrypt", "-r", recipient, "-o", "key.txt.age", "key.txt"
      system "age", "--decrypt", "-i", "key.txt", "-o", "key.decrypted.txt", "key.txt.age"
      assert_equal (testpath/"key.txt").read, (testpath/"key.decrypted.txt").read
    else
      opoo "No Secure Enclave detected. Only testing encryption."
      (testpath/"secret.txt").write "My secret"
      system "age", "--encrypt", "-r", "age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp", "-o", "secret.txt.age", "secret.txt"
      assert_predicate testpath/"secret.txt.age", :exist?
    end
  end
end
