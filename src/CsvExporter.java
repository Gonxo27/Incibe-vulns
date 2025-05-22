import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class CsvExporter {

    public static void export(List<Vulnerability> vulnerabilities, String filePath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.append("CVE,Date,Severity,CVSS,Description,Url\n");

            for (Vulnerability vuln : vulnerabilities) {
                String scoreText = (vuln.getSeverity() < 0) ? "Sin asignar" : String.format(Locale.US, "%.1f", vuln.getSeverity());

                writer.write(String.join(",",
                        vuln.getCVE(),
                        vuln.getDate().toString(),
                        scoreText,
                        vuln.getCvss_version(),
                        "\"" + vuln.getDescription().replace("\"", "\"\"") + "\"",
                        vuln.getUrl()
                ));
                writer.newLine();
            }


            System.out.println(" File exported successfully on path " + filePath);
        } catch (IOException e) {
            System.err.println("[ERROR] There has been an error exporting the CSV: " + e.getMessage());
    }

    }
}
