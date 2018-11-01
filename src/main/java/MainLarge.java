import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.Random;

public class MainLarge {

    private static final int FILE_READ_BUF_SIZE = 16 * 1024; // 16KB

    private static int ITERATIONS = -1;

    private static final long[] FILE_SIZES_KB = {
            4,
            8,
            16,
            32,
            64,
            128,
            256,
            512,
            1024,       // 1 MB
            1024 * 10,  // 10MB
            1024 * 100  // 100MB
    };

    private static final byte BUFS[][] = {
            new byte[32],
            new byte[64],
            new byte[128],
            new byte[512],
            new byte[1024 * 1],
            new byte[1024 * 2],
            new byte[1024 * 4],
            new byte[1024 * 8],
            new byte[1024 * 16],
            new byte[1024 * 32],
            new byte[1024 * 64]
    };

    private static final Random RANDOM = new Random();

    public static void main(final String[] args) throws IOException, InterruptedException {

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new gnu.crypto.jce.GnuCrypto());

        // for debugging
//        for (final Provider provider : Security.getProviders()) {
//            System.out.println(provider.getName());
//            for (final Provider.Service service : provider.getServices()) {
//                if (service.getType().equals("MessageDigest")) {
//                    System.out.println("\t\t" + service.getAlgorithm());
//                }
//            }
//        }

        if (args.length > 0 && args[0].equals("files")) {

            ITERATIONS = 100;

            System.out.println("FILES BENCHMARK (iterations=" + ITERATIONS + ")");
            final Path[] files = createTempFiles();

            benchmark(new JavaSha256("SUN"), files);
            benchmark(new JavaSha256("GNU-CRYPTO"), files);
            benchmark(new GnuCryptoSha256(), files);
            benchmark(new JavaSha256("BC"), files);
            benchmark(new BouncyCastleSha256(), files);

            benchmark(new JavaRipemd160("GNU-CRYPTO"), files);
            benchmark(new GnuCryptoRipemd160(), files);
            benchmark(new JavaRipemd160("BC"), files);
            benchmark(new BouncyCastleRipemd160(), files);

            benchmark(new JavaRipemd256("BC"), files);
            benchmark(new BouncyCastleRipemd256(), files);

            benchmark(new JavaBlake256("BC"), files);
            benchmark(new BouncyCastleBlake256(), files);

        } else {

            ITERATIONS = 10_000;

            System.out.println("BUFS BENCHMARK (iterations=" + ITERATIONS + ")");

            benchmark(new JavaSha256("SUN"));
            benchmark(new JavaSha256("GNU-CRYPTO"));
            benchmark(new GnuCryptoSha256());
            benchmark(new JavaSha256("BC"));
            benchmark(new BouncyCastleSha256());

            benchmark(new JavaRipemd160("GNU-CRYPTO"));
            benchmark(new GnuCryptoRipemd160());
            benchmark(new JavaRipemd160("BC"));
            benchmark(new BouncyCastleRipemd160());

            benchmark(new JavaRipemd256("BC"));
            benchmark(new BouncyCastleRipemd256());

            benchmark(new JavaBlake256("BC"));
            benchmark(new BouncyCastleBlake256());
        }

    }

    private static Path[] createTempFiles() throws IOException, InterruptedException {
        final Path[] files = new Path[FILE_SIZES_KB.length];
        for (int i = 0; i < files.length; i++) {
            final Path path = Files.createTempFile("hash-perf-test", "bin");
            final Process process = Runtime.getRuntime().exec(new String[]{
                    "dd",
                    "if=/dev/urandom",
                    "of=" + path.toAbsolutePath().toString(),
                    "bs=1024",
                    "count=" + FILE_SIZES_KB[i]
            });
            final int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("Could not generate temp file. exit code=" + exitCode);
            }

            files[i] = path;

            //System.out.println("Created file " + ((float)Files.size(path) / 1024 / 1024) + "MB: " + path.toAbsolutePath().toString());
        }

        return files;
    }

    private static void benchmark(final ILargeHash ihash, final Path[] files) throws IOException {
        for (final Path file : files) {

            byte[] checksum = null;
            long computationTime = 0;
            for (int i = 0; i < ITERATIONS; i++) {

                int read = -1;
                final byte[] buf = new byte[FILE_READ_BUF_SIZE];
                try (final InputStream is = new BufferedInputStream(Files.newInputStream(file, StandardOpenOption.READ), FILE_READ_BUF_SIZE * 2)) {
                    while ((read = is.read(buf)) > -1) {
                        // update the hash
                        final long start = System.nanoTime();
                        ihash.update(buf, 0, read);
                        computationTime += System.nanoTime() - start;
                    }

                    final long start = System.nanoTime();
                    checksum = ihash.getValue();
                    computationTime += System.nanoTime() - start;

                    if (checksum == null) {
                        throw new IllegalStateException();
                    }

                    ihash.reset();
                }
            }

            //System.out.println(ihash.getName() + " (checksum=" + Arrays.toString(checksum) + ") avg time for " + buf.length + " bytes: " + computationTime / ITERATIONS);
            System.out.println(ihash.getName() + "," + Files.size(file) + "," + (computationTime / ITERATIONS));
        }
    }

    private static void benchmark(final ILargeHash ihash) {
        for (final byte[] buf : BUFS) {
            byte[] checksum = null;
            long computationTime = 0;
            for (int i = 0; i < ITERATIONS; i++) {

                // new random bytes per iteration
                RANDOM.nextBytes(buf);

                final long start = System.nanoTime();
                ihash.hash(buf);
                checksum = ihash.getValue();
                computationTime += System.nanoTime() - start;

                if (checksum == null) {
                    throw new IllegalStateException();
                }

                ihash.reset();
            }

            //System.out.println(ihash.getName() + " (checksum=" + Arrays.toString(checksum) + ") avg time for " + buf.length + " bytes: " + computationTime / ITERATIONS);
            System.out.println(ihash.getName() + "," + buf.length + "," + (computationTime / ITERATIONS));
        }
    }

    private interface ILargeHash {
        String getName();
        void hash(final byte[] buf);
        void update(final byte[] buf, final int offset, final int length);
        byte[] getValue();
        void reset();
    }

    private static class JavaMD implements ILargeHash {
        private final MessageDigest md;

        public JavaMD(final String algorithm, final String provider) {
            try {
                this.md =  MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        }

        public String getName() {
            return "md-" + md.getAlgorithm() + "-" + md.getProvider().getName();
        }

        public void hash(final byte[] buf) {
            md.update(buf);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            md.update(buf, offset, length);
        }

        public byte[] getValue() {
            final byte[] buf = new byte[md.getDigestLength()];
            md.digest(buf);
            return buf;
        }

        public void reset() {
            md.reset();
        }
    }

    private final static class JavaSha256 extends JavaMD {
        public JavaSha256(final String provider) {
            super("sha-256", provider);
        }
    }

    private final static class JavaRipemd160 extends JavaMD {
        public JavaRipemd160(final String provider) {
            super("RIPEMD160", provider);
        }
    }

    private final static class JavaRipemd256 extends JavaMD {
        public JavaRipemd256(final String provider) {
            super("RIPEMD256", provider);
        }
    }

    private final static class JavaBlake256 extends JavaMD {
        public JavaBlake256(final String provider) {
            super("BLAKE2B-256", provider);
        }
    }

    private static class GnuCryptoRipemd160 implements ILargeHash {
        private final gnu.crypto.hash.IMessageDigest md = new gnu.crypto.hash.RipeMD160();

        public String getName() {
            return "direct-RIPEMD160-GNU-CRYPTO";
        }

        public void hash(final byte[] buf) {
            md.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            md.update(buf, offset, length);
        }

        public byte[] getValue() {
            return md.digest();
        }

        public void reset() {
            md.reset();
        }
    }

    private static class GnuCryptoSha256 implements ILargeHash {
        private final gnu.crypto.hash.IMessageDigest md = new gnu.crypto.hash.Sha256();

        public String getName() {
            return "direct-sha-256-GNU-CRYPTO";
        }

        public void hash(final byte[] buf) {
            md.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            md.update(buf, offset, length);
        }

        public byte[] getValue() {
            return md.digest();
        }

        public void reset() {
            md.reset();
        }
    }

    private static class BouncyCastleRipemd160 implements ILargeHash {
        private final org.bouncycastle.crypto.digests.GeneralDigest gd = new org.bouncycastle.crypto.digests.RIPEMD160Digest();

        public String getName() {
            return "direct-RIPEMD160-BC";
        }

        public void hash(final byte[] buf) {
            gd.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            gd.update(buf, offset, length);
        }

        public byte[] getValue() {
            final byte[]  digestBytes = new byte[gd.getDigestSize()];
            gd.doFinal(digestBytes, 0);

            return digestBytes;
        }

        public void reset() {
            gd.reset();
        }
    }

    private static class BouncyCastleRipemd256 implements ILargeHash {
        private final org.bouncycastle.crypto.digests.GeneralDigest gd = new org.bouncycastle.crypto.digests.RIPEMD256Digest();

        public String getName() {
            return "direct-RIPEMD256-BC";
        }

        public void hash(final byte[] buf) {
            gd.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            gd.update(buf, offset, length);
        }

        public byte[] getValue() {
            final byte[]  digestBytes = new byte[gd.getDigestSize()];
            gd.doFinal(digestBytes, 0);

            return digestBytes;
        }

        public void reset() {
            gd.reset();
        }
    }

    private static class BouncyCastleSha256 implements ILargeHash {
        private final org.bouncycastle.crypto.digests.GeneralDigest gd = new org.bouncycastle.crypto.digests.SHA256Digest();

        public String getName() {
            return "direct-sha256-BC";
        }

        public void hash(final byte[] buf) {
            gd.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            gd.update(buf, offset, length);
        }

        public byte[] getValue() {
            final byte[]  digestBytes = new byte[gd.getDigestSize()];
            gd.doFinal(digestBytes, 0);

            return digestBytes;
        }

        public void reset() {
            gd.reset();
        }
    }

    private static class BouncyCastleBlake256 implements ILargeHash {
        private final org.bouncycastle.crypto.ExtendedDigest ed = new org.bouncycastle.crypto.digests.Blake2bDigest();

        public String getName() {
            return "direct-blake2b-256-BC";
        }

        public void hash(final byte[] buf) {
            ed.update(buf, 0, buf.length);
        }

        public void update(final byte[] buf, final int offset, final int length) {
            ed.update(buf, offset, length);
        }

        public byte[] getValue() {
            final byte[]  digestBytes = new byte[ed.getDigestSize()];
            ed.doFinal(digestBytes, 0);

            return digestBytes;
        }

        public void reset() {
            ed.reset();
        }
    }
}
