import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class ct {
    public enum PairLabel {
        DUPLICATE,
        RELATED,
        UNRELATED
    }

    public static class CtiRecord {
        public final String id;
        public final String sourceProvider;
        public final String title;
        public final String narrativeText;
        public final Set<String> rawIndicators;
        public final Set<String> threatActors;
        public final Set<String> malwareFamilies;
        public final Set<String> mitreTechniques;
        public final String campaignClaim;

        public CtiRecord(
                String id,
                String sourceProvider,
                String title,
                String narrativeText,
                Set<String> rawIndicators,
                Set<String> threatActors,
                Set<String> malwareFamilies,
                Set<String> mitreTechniques,
                String campaignClaim
        ) {
            this.id = id;
            this.sourceProvider = sourceProvider;
            this.title = title;
            this.narrativeText = narrativeText;
            this.rawIndicators = new LinkedHashSet<>(rawIndicators);
            this.threatActors = new LinkedHashSet<>(threatActors);
            this.malwareFamilies = new LinkedHashSet<>(malwareFamilies);
            this.mitreTechniques = new LinkedHashSet<>(mitreTechniques);
            this.campaignClaim = campaignClaim;
        }
    }

    public static class SimilarityFeatures {
        public final double tokenSimilarity;
        public final double actorSimilarity;
        public final double malwareSimilarity;
        public final double techniqueSimilarity;
        public final double campaignSimilarity;

        public SimilarityFeatures(
                double tokenSimilarity,
                double actorSimilarity,
                double malwareSimilarity,
                double techniqueSimilarity,
                double campaignSimilarity
        ) {
            this.tokenSimilarity = tokenSimilarity;
            this.actorSimilarity = actorSimilarity;
            this.malwareSimilarity = malwareSimilarity;
            this.techniqueSimilarity = techniqueSimilarity;
            this.campaignSimilarity = campaignSimilarity;
        }
    }

    public static class ComparisonResult {
        public final PairLabel label;
        public final double score;

        public ComparisonResult(PairLabel label, double score) {
            this.label = label;
            this.score = score;
        }
    }

    private static final Set<String> STOP_WORDS = new HashSet<>(Arrays.asList(
            "the", "and", "for", "with", "from", "into", "this", "that", "there",
            "have", "has", "was", "were", "which", "their", "them", "they", "then",
            "also", "using", "about", "over", "under", "after", "before", "while",
            "through", "these", "those", "such", "same", "more", "most", "into"
    ));

    public static void main(String[] args) {
        CtiRecord recordA = new CtiRecord(
                "CTI-1001",
                "Acme SOC",
                "Phishing campaign targeting finance users",
                "A phishing campaign abused fake login pages to harvest credentials from finance staff.",
                new HashSet<>(Arrays.asList("login.acme-secure-check.com", "invoice-update", "banking-login")),
                new HashSet<>(Arrays.asList("APT-28", "FIN7")),
                new HashSet<>(Arrays.asList("Emotet", "Qakbot")),
                new HashSet<>(Arrays.asList("T1059", "T1566")),
                "Operation Nightwatch"
        );

        CtiRecord recordB = new CtiRecord(
                "CTI-1002",
                "Threat Intel",
                "Finance phishing operation impersonating login portal",
                "The analyst noted credential harvesting via fake banking and payroll login portals using Emotet delivery infrastructure.",
                new HashSet<>(Arrays.asList("financial-login", "portal-login", "emotet")),
                new HashSet<>(Arrays.asList("APT-28")),
                new HashSet<>(Arrays.asList("Emotet", "Qakbot")),
                new HashSet<>(Arrays.asList("T1566", "T1059")),
                "Operation Nightwatch"
        );

        CtiRecord recordC = new CtiRecord(
                "CTI-2001",
                "External Feed",
                "Ransomware attack against logistics",
                "The network was compromised through exposed Remote Desktop services and power shell abuse.",
                new HashSet<>(Arrays.asList("rdp", "powershell", "exposed-service")),
                new HashSet<>(Arrays.asList("APT-29")),
                new HashSet<>(Arrays.asList("LockBit")),
                new HashSet<>(Arrays.asList("T1021", "T1059")),
                "Separate cluster"
        );

        ComparisonResult resultAB = compare(recordA, recordB);
        ComparisonResult resultAC = compare(recordA, recordC);

        System.out.println("A vs B => " + resultAB.label + " (score=" + String.format(Locale.US, "%.3f", resultAB.score) + ")");
        System.out.println("A vs C => " + resultAC.label + " (score=" + String.format(Locale.US, "%.3f", resultAC.score) + ")");
    }

    public static ComparisonResult compare(CtiRecord a, CtiRecord b) {
        SimilarityFeatures features = computeSimilarityFeatures(a, b);

        double score = 0.35 * features.tokenSimilarity
                + 0.25 * features.actorSimilarity
                + 0.20 * features.malwareSimilarity
                + 0.15 * features.techniqueSimilarity
                + 0.05 * features.campaignSimilarity;

        PairLabel label;
        if (score >= 0.78 || (features.tokenSimilarity >= 0.70 && features.actorSimilarity >= 0.50)) {
            label = PairLabel.DUPLICATE;
        } else if (score >= 0.45) {
            label = PairLabel.RELATED;
        } else {
            label = PairLabel.UNRELATED;
        }

        return new ComparisonResult(label, score);
    }

    public static SimilarityFeatures computeSimilarityFeatures(CtiRecord a, CtiRecord b) {
        Set<String> tokensA = tokenize(a.title + " " + a.narrativeText + " " + String.join(" ", a.rawIndicators));
        Set<String> tokensB = tokenize(b.title + " " + b.narrativeText + " " + String.join(" ", b.rawIndicators));

        double tokenSimilarity = jaccard(tokensA, tokensB);
        double actorSimilarity = jaccard(a.threatActors, b.threatActors);
        double malwareSimilarity = jaccard(a.malwareFamilies, b.malwareFamilies);
        double techniqueSimilarity = jaccard(a.mitreTechniques, b.mitreTechniques);
        double campaignSimilarity = stringSimilarity(a.campaignClaim, b.campaignClaim);

        return new SimilarityFeatures(tokenSimilarity, actorSimilarity, malwareSimilarity, techniqueSimilarity, campaignSimilarity);
    }

    private static Set<String> tokenize(String text) {
        String cleaned = text.toLowerCase(Locale.US)
                .replaceAll("[^a-z0-9\\s]", " ")
                .replaceAll("\\s+", " ")
                .trim();

        if (cleaned.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> tokens = new LinkedHashSet<>();
        for (String token : cleaned.split("\\s+")) {
            if (!token.isBlank() && !STOP_WORDS.contains(token)) {
                tokens.add(token);
            }
        }
        return tokens;
    }

    private static double jaccard(Set<String> left, Set<String> right) {
        if (left == null || right == null || left.isEmpty() && right.isEmpty()) {
            return 1.0;
        }
        if (left.isEmpty() || right.isEmpty()) {
            return 0.0;
        }

        Set<String> union = new HashSet<>(left);
        union.addAll(right);
        Set<String> intersection = new HashSet<>(left);
        intersection.retainAll(right);

        return union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
    }

    private static double stringSimilarity(String left, String right) {
        if (left == null || right == null) {
            return 0.0;
        }

        left = left.toLowerCase(Locale.US).trim();
        right = right.toLowerCase(Locale.US).trim();

        if (left.isEmpty() && right.isEmpty()) {
            return 1.0;
        }
        if (left.isEmpty() || right.isEmpty()) {
            return 0.0;
        }
        if (left.equals(right)) {
            return 1.0;
        }

        int maxLength = Math.max(left.length(), right.length());
        if (maxLength == 0) {
            return 1.0;
        }

        int commonPrefix = 0;
        while (commonPrefix < left.length() && commonPrefix < right.length() && left.charAt(commonPrefix) == right.charAt(commonPrefix)) {
            commonPrefix++;
        }

        return (double) commonPrefix / maxLength;
    }
}
