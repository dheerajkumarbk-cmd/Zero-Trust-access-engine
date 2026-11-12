package dev.dwarpal.directory;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reads the source, not the behaviour. The rules for the database layer are about how the code is written, so a test
 * that looks at the code is the only one that notices someone breaking them: all SQL lives in one small package, every
 * statement is a constant with {@code ?} for values, nothing is joined from strings, and only standard SQL is used.
 */
class DirectorySourceTest {

    private static final Path MAIN = Path.of("src", "main", "java");
    private static final Path MIGRATIONS = Path.of("src", "main", "resources", "db", "migrations");
    private static final String LAYER = "dev/dwarpal/directory/";

    private static List<Path> sources() throws IOException {
        try (Stream<Path> s = Files.walk(MAIN)) {
            return s.filter(p -> p.toString().endsWith(".java")).toList();
        }
    }

    private static String rel(Path p) {
        return MAIN.relativize(p).toString().replace(java.io.File.separatorChar, '/');
    }

    private static String text(Path p) throws IOException {
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    @Test
    void onlyTheDirectoryPackageTouchesJdbc() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path p : sources()) {
            String t = text(p);
            if ((t.contains("import java.sql.") || t.contains("import javax.sql.")) && !rel(p).startsWith(LAYER)) {
                offenders.add(rel(p));
            }
        }
        assertEquals(List.of(), offenders, "database access belongs in dev.dwarpal.directory only");
    }

    @Test
    void everyPreparedStatementIsBuiltFromALiteralOrAConstant() throws IOException {
        Pattern call = Pattern.compile("prepareStatement\\(\\s*([^,)]*)");
        Pattern constant = Pattern.compile("\"[^\"]*\"|[A-Z][A-Z0-9_]*");
        List<String> offenders = new ArrayList<>();
        int seen = 0;
        for (Path p : sources()) {
            Matcher m = call.matcher(text(p));
            while (m.find()) {
                seen++;
                String arg = m.group(1).strip();
                if (!constant.matcher(arg).matches()) {
                    offenders.add(rel(p) + ": prepareStatement(" + arg + ")");
                }
            }
        }
        assertTrue(seen > 5, "the scan found the statements it is meant to check");
        assertEquals(List.of(), offenders);
    }

    @Test
    void plainStatementsAreOnlyInTheMigratorAndRunOnlyConstantsOrTheShippedScript() throws IOException {
        List<String> offenders = new ArrayList<>();
        Pattern run = Pattern.compile("\\.(execute|executeQuery|executeUpdate|addBatch)\\(\\s*([^)]+)\\)");
        for (Path p : sources()) {
            String t = text(p);
            if (t.contains("createStatement(") && !rel(p).equals(LAYER + "Migrator.java")) {
                offenders.add(rel(p) + " creates a plain Statement");
            }
            Matcher m = run.matcher(t);
            while (m.find()) {
                String arg = m.group(2).strip();
                boolean constant = arg.matches("[A-Z][A-Z0-9_]*");
                boolean script = arg.equals("sql") && rel(p).equals(LAYER + "Migrator.java");
                if (rel(p).startsWith(LAYER) && !constant && !script) {
                    offenders.add(rel(p) + ": " + m.group(0));
                }
            }
        }
        assertEquals(List.of(), offenders);
    }

    @Test
    void noSqlAnywhereInTheProjectIsJoinedFromStrings() throws IOException {
        // a literal that starts a statement, then + something that is not a constant or another literal
        Pattern literalThenVariable = Pattern.compile("\"[^\"]*\\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|DROP TABLE)\\b[^\"]*\"\\s*\\+\\s*([^\\s\"][^\\s;)]*)");
        Pattern variableThenSqlWord = Pattern.compile("([A-Za-z_][A-Za-z0-9_.()]*)\\s*\\+\\s*\"[^\"]*\\b(FROM|WHERE|VALUES|SET|AND|OR)\\b");
        Pattern formatted = Pattern.compile("(String\\.format|\\.formatted)\\(\\s*\"[^\"]*\\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\\b");
        List<String> offenders = new ArrayList<>();
        for (Path p : sources()) {
            String t = text(p);
            Matcher a = literalThenVariable.matcher(t);
            while (a.find()) {
                String operand = a.group(2);
                if (!operand.matches("[A-Z][A-Z0-9_]*")) {
                    offenders.add(rel(p) + ": " + a.group(0).strip());
                }
            }
            Matcher b = variableThenSqlWord.matcher(t);
            while (b.find()) {
                if (!b.group(1).matches("[A-Z][A-Z0-9_]*") && rel(p).startsWith(LAYER)) {
                    offenders.add(rel(p) + ": " + b.group(0).strip());
                }
            }
            if (formatted.matcher(t).find()) {
                offenders.add(rel(p) + " formats an SQL string");
            }
        }
        assertEquals(List.of(), offenders);
    }

    @Test
    void theSqlIsStandardSql() throws IOException {
        List<String> banned = List.of("::", "ILIKE", "RETURNING", "SERIAL", "JSONB", "ON CONFLICT", "SHOW ", "NOW()", "pg_", "ARRAY[",
                "UNNEST", "STRING_AGG", "LIMIT ", "COPY ");
        List<String> offenders = new ArrayList<>();
        List<String> texts = new ArrayList<>();
        try (Stream<Path> s = Files.list(MIGRATIONS)) {
            for (Path p : s.toList()) {
                // comments may talk about anything; the statements may not use anything special
                texts.add(String.join("\n", Files.readAllLines(p).stream().filter(l -> !l.strip().startsWith("--")).toList()));
            }
        }
        for (Path p : sources()) {
            if (rel(p).startsWith(LAYER) && !rel(p).endsWith("Migrator.java")) {
                Matcher m = Pattern.compile("\"((?:SELECT|INSERT|UPDATE|DELETE)[^\"]*)\"").matcher(text(p));
                while (m.find()) {
                    texts.add(m.group(1));
                }
            }
        }
        for (String t : texts) {
            for (String word : banned) {
                if (t.contains(word)) {
                    offenders.add("'" + word + "' in: " + t.substring(0, Math.min(60, t.length())).replace('\n', ' '));
                }
            }
        }
        assertTrue(texts.size() > 5);
        assertEquals(List.of(), offenders);
    }

    @Test
    void theScriptListIsTheMigrationFolderInOrderWithNoGaps() throws IOException {
        List<String> inFolder;
        try (Stream<Path> s = Files.list(MIGRATIONS)) {
            inFolder = s.map(p -> "/db/migrations/" + p.getFileName()).sorted().toList();
        }
        assertEquals(inFolder, Migrator.SCRIPTS.stream().map(Migrator.Script::resource).sorted().toList());
        for (int i = 0; i < Migrator.SCRIPTS.size(); i++) {
            Migrator.Script s = Migrator.SCRIPTS.get(i);
            assertEquals(i + 1, s.version(), "versions count up from 1 with no gap");
            assertTrue(s.resource().matches("/db/migrations/V" + String.format("%03d", s.version()) + "__[a-z_]+\\.sql"), s.resource());
        }
    }

    @Test
    void noPasswordIsWrittenIntoTheDatabaseLayerOrItsScripts() throws IOException {
        Pattern assignment = Pattern.compile("(?i)password\\s*(=|:)\\s*\"[^\"]{4,}\"|PASSWORD\\s+'[^']+'");
        List<String> offenders = new ArrayList<>();
        for (Path p : sources()) {
            if (rel(p).startsWith(LAYER) && assignment.matcher(text(p)).find()) {
                offenders.add(rel(p));
            }
        }
        try (Stream<Path> s = Files.list(MIGRATIONS)) {
            for (Path p : s.toList()) {
                if (assignment.matcher(text(p)).find()) {
                    offenders.add(p.toString());
                }
            }
        }
        assertEquals(List.of(), offenders);
    }
}
