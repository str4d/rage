class Rage < Formula
    desc "[BETA] A simple, secure, and modern encryption tool."
    homepage "https://str4d.xyz/rage"
    url "https://github.com/str4d/rage/archive/refs/tags/v0.10.0.tar.gz"
    sha256 "34c39c28f8032c144a43aea96e58159fe69526f5ff91cb813083530adcaa6ea4"
    license any_of: ["MIT", "Apache-2.0"]
    version "0.10.0"

    depends_on "rust" => :build

    def install
        system "cargo", "install", *std_cargo_args(path: './rage')

        install_completions("rage")
        install_completions("rage-keygen")

        man.install Dir["target/release/manpages/*"]
    end

    def install_completions(base_name)
        src_dir = "target/release/completions"

        bash_completion.install { "#{src_dir}/#{base_name}.bash" => base_name}
        fish_completion.install "#{src_dir}/#{base_name}.fish"
        zsh_completion.install "#{src_dir}/_#{base_name}"
    end

    def caveats
        "rage bash completion depends on the bash-completion package"
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
