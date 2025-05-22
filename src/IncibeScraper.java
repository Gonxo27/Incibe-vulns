import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

import exceptions.VulnerabilityException;
import org.jsoup.select.Elements;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Document;

public class IncibeScraper {
    private static final DateTimeFormatter INPUT_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter HTML_DATE_FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy");
    private static final String BASE_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        ProxyConfigurator.configuration(scanner);
        LocalDate minDate = requestDate(scanner);

        int page = 0;
        List<Vulnerability> filtered = new ArrayList<>();
        String apiKey = APIKeyLoader.loadApiKey("api_key.txt");

        while(true) {
            String url = makeURL(minDate, page);
            System.out.println("Processing page " + page + ": " + url);

            try {
                Document doc = SSLHelper.getConnection(url).get();
                Elements entries = doc.select("div.node-vulnerabilities-teaser");

                if (entries.isEmpty()) {
                    break;
                }

                for (Element entry : entries) {
                    try {
                        String cve = entry.selectFirst("h2.node-title").text().trim();
                        String link = "https://www.incibe.es" + entry.selectFirst("a").attr("href");

                        String rawDate = entry.selectFirst(".field-publication-date .date").text().trim();
                        LocalDate date = LocalDate.parse(rawDate, HTML_DATE_FORMAT);

                        if (date.isBefore(minDate)) {
                            continue;
                        }

                        String description = entry.selectFirst(".field-description").text().trim();

                        String rawSeverity = entry.selectFirst(".field-vulnerability-severity-text").text();

                        String[] parts = rawSeverity.split(":");
                        if(parts.length != 2) continue;

                        String cvssVersion = parts[0].replaceAll("[^\\d.]", "").trim();
                        String severityText = parts[1].trim().toUpperCase().replaceAll("[^A-ZÁÉÍÓÚ]", "");

                        System.out.println("RAW: " + cve + " | " + rawDate + " | " + rawSeverity);

                        if(!(cvssVersion.equals("3.1") || cvssVersion.equals("4.0"))) {
                            continue;
                        }
                        if(!(severityText.equals("ALTA") ||severityText.equals("CRÍTICA"))) {
                            continue;
                        }

                        Double severity = NISTAPIClient.getCvssScore(cve, apiKey);
                        if (severity == null) {
                            System.out.println("[WARNING] Could not fetch CVSS score for " + cve + ". Using placeholder...");
                            severity = -1.0;
                        }

                        Vulnerability vuln = new Vulnerability(cve, date, severity, cvssVersion, description, link);
                        filtered.add(vuln);
                        System.out.println(vuln);
                        System.out.println("--------------------------------------------------");
                    } catch (VulnerabilityException ve) {
                        System.err.println(ve.getMessage());
                    }
                }

                Element next = doc.selectFirst("li.pager__item--next:not(.is-disabled)");
                if (next == null) {
                    break;
                }
                page++;
            } catch (Exception e) {
                System.err.println("[ERROR] There was an error processing the page: " + e.getMessage());
                break;
            }
        }
        if (!filtered.isEmpty()) {
            String outputFile = "incibe_vulns_" + LocalDate.now() + ".csv";
            try {
                CsvExporter.export(filtered, outputFile);
            } catch (IOException e) {
                throw new RuntimeException("[ERROR] There was an error processing the csv file: " + e.getMessage());
            }
        } else {
            System.out.println("No vulnerabilities found.");
        }
    }

    private static LocalDate requestDate(Scanner scanner) {
        while (true) {
            System.out.println("Provide the minimum date for searching (YYYY-MM-DD): ");
            String date = scanner.nextLine();
            try {
                return LocalDate.parse(date, INPUT_FORMAT);
            } catch (DateTimeParseException e) {
                System.out.println("[ERROR] Invalid date: " + date);
            }
        }
    }

    private static String makeURL(LocalDate minDate, int page) {
        return BASE_URL +
                "?field_vulnerability_title_es=" +
                "&field_vul_publication_date%5Bmin%5D=" + minDate +
                "&field_vul_publication_date%5Bmax%5D=" +
                "&name=" +
                "&field_vul_product=" +
                "&field_vul_severity_txt_40=All" +
                "&field_vul_severity_txt_31=4" +
                "&field_vulnerability_severity_txt=All" +
                "&field_vul_vendor=" +
                "&page=" + page;
    }

    private static boolean existsNextPage(Document doc) {
        Element nextButton = doc.selectFirst(".pager__item--next");
        return nextButton != null && !nextButton.hasClass("is-disabled");
    }

}
