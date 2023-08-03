from configparser import ConfigParser
from datetime import datetime, timezone
from pathlib import Path
import psycopg2
import psycopg2.sql as sql
import re



MAX_LIMIT = 1000000



def config(filename, section):
    parser = ConfigParser()
    parser.read(filename)

    data = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            data[param[0]] = param[1]
    else:
        raise Exception(f"Section {section} not found in {filename}")

    return data

def connectToDb():
    params = config(Path(__file__).parent / "database.ini", "postgresql")
    conn = psycopg2.connect(**params)
    return conn

def executeStatement(conn, statement, params=None):
    try:
        cursor = conn.cursor()
        cursor.execute(statement, params)
        conn.commit()
        if cursor.description:
            return cursor.fetchall()
        return None
    except psycopg2.Error as e:
        conn.rollback()
        raise e



def isValidUuid(uuid):
    uuidRegex = "([a-fA-F0-9]{4}-?){7}[a-fA-F0-9]{4}"
    return isinstance(uuid, str) and re.fullmatch(uuidRegex, uuid)

def getSingleValue(data):
    return data[0][0]

def And(expressions):
    if len(expressions) == 0:
        return sql.SQL("TRUE")

    if not all(isinstance(e, sql.Composable) for e in expressions):
        raise Exception("AND expressions must all be of type Composable")
    
    conditionSql = sql.SQL(" AND ").join(
        [sql.SQL("({})").format(e) for e in expressions])

    return conditionSql

def Or(expressions):
    if len(expressions) == 0:
        return sql.SQL("TRUE")

    if not all(isinstance(e, sql.Composable) for e in expressions):
        raise Exception("OR expressions must all be of type Composable")
    
    conditionSql = sql.SQL(" OR ").join(
        [sql.SQL("({})").format(e) for e in expressions])

    return conditionSql

def Not(expression):
    if not isinstance(expression, sql.Composable):
        raise Exception("NOT condition must be a single of type Composable")

    conditionSql = sql.SQL("NOT (") + expression + sql.SQL(")")

    return conditionSql

def Query(table, filters, limit=MAX_LIMIT, offset=0):
    if filters == None:
        filters = sql.SQL("TRUE")

    if not isinstance(filters, sql.Composable):
        raise Exception("filters must be of type Composable")

    return sql.SQL("SELECT * FROM {} WHERE {} ORDER BY id DESC LIMIT {} OFFSET {}").format(
        sql.Identifier(table), filters, sql.Literal(limit), sql.Literal(offset))

def literalFiller(query, *args):
    return sql.SQL(query).format(*[sql.Literal(a) for a in args])

def timeRangeFilter(start, end):
    return literalFiller("timestamp >= {} AND timestamp < {}", start, end)

def includePathsFilter(paths):
    return Or([literalFiller("path LIKE {}", f"{path}%") for path in paths])

def excludePathsFilter(paths):
    return And([literalFiller("path NOT LIKE {}", f"{path}%") for path in paths])

def includeFileTypesFilter(fileTypes):
    return Or([literalFiller("path LIKE {}", f"%.{fileType}") for fileType in fileTypes])

def excludeFileTypesFilter(fileTypes):
    return And([literalFiller("path NOT LIKE {}", f"%.{fileType}") for fileType in fileTypes])

def osFilter(os):
    if os == None:
        return sql.SQL("os IS NULL")
    else:
        return literalFiller("os ILIKE {}", os)

def ipFilter(ip, mask):
    ipParts = ip.split(".")
    if len(ipParts) != 4:
        raise Exception(f"Bad IP format: {ip}")

    if mask not in [0, 8, 16, 24, 32]:
        raise Exception("Only multiples of 8 allowed for IP mask")

    if mask == 0:
        ipWithMask = "%"
    elif mask == 32:
        ipWithMask = ip
    else:
        usedIpParts = ipParts[:mask // 8]
        ipWithMask = "".join([p + "." for p in usedIpParts]) + "%"

    return literalFiller("ip LIKE {}", ipWithMask)

def tlsFilter():
    return sql.SQL("tls IS NOT NULL")

def hostFilter(host):
    return literalFiller("host = {}", host)

def httpMethodFilter(method):
    return literalFiller("http_method = {}", method)

def pathFilter(path):
    return literalFiller("path = {}", path)

def pathPrefixFilter(path):
    return literalFiller("path LIKE {}", path + "%")

def statusFilter(status):
    return literalFiller("status = {}", status)

def statusRangeFilter(start, end):
    return literalFiller("status >= {} AND status < {}", start, end)



def isValidApiKey(conn, key):
    if not isValidUuid(key):
        return False
    query = sql.SQL("SELECT EXISTS (SELECT 1 FROM api_keys WHERE api_key = {})").format(
        sql.Literal(key))
    isValid = executeStatement(conn, query)
    return getSingleValue(isValid)

def generateTimeBoxes(bucketInterval, numBuckets, chunkRounding):
    now = datetime.now(timezone.utc).isoformat()
    query = sql.SQL("""
        SELECT start_time, start_time + interval {bucketInterval} AS end_time
        FROM generate_series(
            date_bin(interval {bucketInterval},
                timestamptz {now} - interval {bucketInterval} * (({numBuckets}) - 1),
                timestamptz {chunkRounding}),
            timestamptz {now},
            interval {bucketInterval})
        AS start_time""").format(
        bucketInterval=sql.Literal(bucketInterval),
        now=sql.Literal(now),
        numBuckets=sql.Literal(numBuckets),
        chunkRounding=sql.Literal(chunkRounding)
    )
    return query

def chunkEntriesQuery(bucketInterval, numBuckets, chunkRounding, subquery):
    query = sql.SQL("""
        WITH t AS (
            {subquery}
        ), grid AS (
            {timeBoxQuery}
        )
        SELECT start_time, count(t.timestamp) AS events
        FROM grid g
        LEFT JOIN t ON t.timestamp >= g.start_time AND t.timestamp < g.end_time
        GROUP BY start_time
        ORDER BY start_time""").format(
        subquery=subquery,
        timeBoxQuery=generateTimeBoxes(bucketInterval, numBuckets, chunkRounding)
    )
    return query

def getLoadAvg(bucketInterval, numBuckets, chunkRounding, subquery):
    now = datetime.now(timezone.utc).isoformat()
    query = sql.SQL("""
        WITH t AS (
            {subquery}
        ), grid AS (
            {timeBoxQuery}
        )
        SELECT start_time, round(avg(t.one_min_avg)::numeric, 2) AS events
        FROM grid g
        LEFT JOIN t ON t.timestamp >= g.start_time AND t.timestamp < g.end_time
        GROUP BY start_time
        ORDER BY start_time""").format(
        subquery=subquery,
        timeBoxQuery=generateTimeBoxes(bucketInterval, numBuckets, chunkRounding)
    )
    return query

def addNewApiKey(conn):
    query = sql.SQL("INSERT INTO api_keys (api_key) VALUES (gen_random_uuid()) RETURNING api_key")
    newKey = executeStatement(conn, query)
    return getSingleValue(newKey)

