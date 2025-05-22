import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class NISTAPIClient {

    public static Double getCvssScore(String cve, String apiKey) {
        try {
            String apiURL= "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve;
            URL url = new URL(apiURL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("apikey", apiKey);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                System.err.println("Failed to get data from NIST API: HTTP response code: " + responseCode);
                return null;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder jsonBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonBuilder.append(line);
            }
            reader.close();

            JSONObject root = new JSONObject(jsonBuilder.toString());
            JSONArray vulns = root.getJSONArray("vulnerabilities");

            if (vulns.isEmpty()) {
                System.err.println("No vulnerabilities found for " + cve);
                return null;
            }

            JSONObject cveObject = vulns.getJSONObject(0).getJSONObject("cve");
            JSONObject metrics = cveObject.getJSONObject("metrics");

            if (metrics.has("cvssMetricV31")) {
                JSONArray cvssArray = metrics.getJSONArray("cvssMetricV31");
                return cvssArray.getJSONObject(0).getJSONObject("cvssData").getDouble("baseScore");
            } else if (metrics.has("cvssMetricV30")) {
                JSONArray cvssArray = metrics.getJSONArray("cvssMetricV30");
                return cvssArray.getJSONObject(0).getJSONObject("cvssData").getDouble("baseScore");
            } else if (metrics.has("cvssMetricV2")) {
                JSONArray cvssArray = metrics.getJSONArray("cvssMetricV2");
                return cvssArray.getJSONObject(0).getJSONObject("cvssData").getDouble("baseScore");
            }

            System.err.println("No CVSS metrics found for " + cve);

        } catch (Exception e) {
            System.err.println("Exception retrieving CVSS for " + cve + ": " + e.getMessage());
        }
        return null;
    }
}
