import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class CsvExporter {

    public static void export(List<Vulnerability> vulnerabilities, String filePath) throws IOException {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.append("CVE,Date,Severity,CVSS,Description,Url\n");

            for (Vulnerability v : vulnerabilities) {
                writer.append(v.getCVE()).append(",");
                writer.append(v.getDate().toString()).append(",");
                writer.append(String.valueOf(v.getSeverity())).append(",");
                writer.append(v.getCvss_version()).append(",");
                writer.append("\"").append(v.getDescription().replace("\"", "'")).append("\"");
                writer.append(v.getUrl()).append("\n");
            }

            System.out.println(" File exported successfully on path " + filePath);
        } catch (IOException e) {
            System.err.println("[ERROR] There has been an error exporting the CSV: " + e.getMessage());
    }

    }
}
