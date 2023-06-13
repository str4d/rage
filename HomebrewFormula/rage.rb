class Rage < Formula
    desc "[BETA] A simple, secure, and modern encryption tool."
    homepage "https://str4d.xyz/rage"
    url "https://github.com/str4d/rage/archive/refs/tags/v0.9.2.tar.gz"
    sha256 "3bd287372eb6226b246459c1b5c39ecdb36b3495d7af4d2bee93bb3aad9ccf65"
    version "0.9.2"

    depends_on "rust" => :build

    def install
        system "cargo", "install", *std_cargo_args(path: './rage')
    end

    test do
        # Test key generation
        system "#{bin}/rage-keygen -o #{testpath}/output.txt"
        assert_predicate testpath/"output.txt", :exist?

        # Test encryption
        (testpath/"test.txt").write("Hello World!\n")
        system "#{bin}/rage -r age1y8m84r6pwd4da5d45zzk03rlgv2xr7fn9px80suw3psrahul44ashl0usm -o #{testpath}/test.txt.age #{testpath}/test.txt"
        assert_predicate testpath/"test.txt.age", :exist?
        assert File.read(testpath/"test.txt.age").start_with?("age-encryption.org")

        # Test decryption
        (testpath/"test.key").write("AGE-SECRET-KEY-1TRYTV7PQS5XPUYSTAQZCD7DQCWC7Q77YJD7UVFJRMW4J82Q6930QS70MRX")
        assert_equal "Hello World!", shell_output("#{bin}/rage -d -i #{testpath}/test.key #{testpath}/test.txt.age").strip
    end
end
