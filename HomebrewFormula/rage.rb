class Rage < Formula
    desc "[BETA] A simple, secure, and modern encryption tool."
    homepage "https://str4d.xyz/rage"
    url "https://github.com/str4d/rage/archive/v0.8.0.tar.gz"
    sha256 "727719d0d308998bb2600e730f7c287e40d0d9f77e77817bac03fe037c436449"
    version "0.8.0"

    depends_on "rust" => :build

    def install
        system "cargo", "build", "--release", "--package", "rage"
        bin.install "target/release/rage"
        bin.install "target/release/rage-keygen"
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
