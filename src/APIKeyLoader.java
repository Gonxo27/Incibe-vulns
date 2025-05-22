import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;

public class APIKeyLoader {
    public static String loadApiKey(String path) {
        try {
            return Files.readString(Paths.get(path)).trim();
        } catch (IOException e) {
            throw new RuntimeException("Error reading API key from " + path, e);
        }
    }
}
