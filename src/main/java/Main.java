import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;
import net.openhft.hashing.LongHashFunction;

import java.util.Random;
import java.util.zip.Adler32;

public class Main {

    private static final int ITERATIONS = 10_000;

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

    public static void main(final String[] args) {

//        benchmark(new Adler32Hash());

//        benchmark(new OpenHftXXHash());

//        benchmark(new Lz4XXHash32());

        benchmark(new Lz4XXHash64());
    }

    private static void benchmark(final IHash ihash) {
        for (final byte[] buf : BUFS) {
            long checksum = -1;
            long computationTime = 0;
            for (int i = 0; i < ITERATIONS; i++) {

                // new random bytes per iteration
                RANDOM.nextBytes(buf);

                final long start = System.nanoTime();
                ihash.hash(buf);
                checksum = ihash.getValue();
                computationTime += System.nanoTime() - start;

                if (checksum == 0) {
                    throw new IllegalStateException();
                }

                ihash.reset();
            }

            //System.out.println(ihash.getName() + " (checksum=" + checksum + ") avg time for " + buf.length + " bytes: " + computationTime / ITERATIONS);
            System.out.println(ihash.getName() + "," + buf.length + "," + (computationTime / ITERATIONS));
        }
    }

    private interface IHash {
        String getName();
        void hash(final byte[] buf);
        long getValue();
        void reset();
    }

    private final static class Adler32Hash implements IHash {
        private final Adler32 adler32 = new Adler32();

        public String getName() {
            return "adler32";
        }

        public void hash(final byte[] buf) {
            adler32.update(buf);
        }

        public long getValue() {
            return adler32.getValue();
        }

        public void reset() {
            adler32.reset();
        }
    }

    private final static class OpenHftXXHash implements IHash {
        private final LongHashFunction xx = LongHashFunction.xx();
        private long checksum = 0;

        public String getName() {
            return "openhft-xxhash";
        }

        public void hash(final byte[] buf) {
            checksum = xx.hashBytes(buf);
        }

        public long getValue() {
            return checksum;
        }

        public void reset() {
            checksum = -1;
        }
    }

    private static class Lz4XXHash32 implements IHash {
        private final XXHashFactory factory = XXHashFactory.fastestInstance();
        private final XXHash32 xx32 = factory.hash32();
        private long checksum = 0;


        public String getName() {
            return "lz4-xxhash32";
        }

        public void hash(final byte[] buf) {
            checksum = xx32.hash(buf, 0, buf.length, 0);
        }

        public long getValue() {
            return checksum;
        }

        public void reset() {
            checksum = -1;
        }
    }

    private static class Lz4XXHash64 implements IHash {
        private final XXHashFactory factory = XXHashFactory.fastestInstance();
        private final XXHash64 xx64 = factory.hash64();
        private long checksum = 0;


        public String getName() {
            return "lz4-xxhash64";
        }

        public void hash(final byte[] buf) {
            checksum = xx64.hash(buf, 0, buf.length, 0);
        }

        public long getValue() {
            return checksum;
        }

        public void reset() {
            checksum = -1;
        }
    }
}
