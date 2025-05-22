import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Scanner;

public class ProxyConfigurator {

    public static void configuration(Scanner scanner) {
        System.out.println("Wanna use proxy? (y/n)");
        String response = scanner.nextLine().trim().toLowerCase();

        if (!response.equals("y")) {
            return;
        }

        System.out.print("Proxy host (e.g., proxy.company.com): ");
        String proxyHost = scanner.nextLine().trim();

        System.out.print("Proxy port (e.g., 8080): ");
        int proxyPort;
        try {
            proxyPort = Integer.parseInt(scanner.nextLine().trim());
            if (proxyPort < 1 || proxyPort > 65535) {
                System.err.println("[ERROR] Invalid port. It must be between 1 and 65535.");
                return;
            }
        } catch (NumberFormatException e) {
            System.err.println("[ERROR] Proxy port must be a number.");
            return;
        }

        System.out.print("Proxy username: ");
        String user = scanner.nextLine();

        char[] password;
        if (System.console() != null) {
            password = System.console().readPassword("Proxy password: ");
        } else {
            System.out.print("Proxy password (visible): ");
            password = scanner.nextLine().toCharArray();
        }

        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", String.valueOf(proxyPort));
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", String.valueOf(proxyPort));

        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(user, password);
            }
        });

        Arrays.fill(password, ' ');
        System.out.println("Proxy configured successfully: " + proxyHost + ":" + proxyPort);
    }
}
