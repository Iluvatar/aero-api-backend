from bottle import error, get, post, route, hook, request, response, run
from datetime import datetime, timedelta, timezone
import json
import psycopg2
import pytz

import psqlFunctions as pf
from psqlFunctions import And, Or, Not, Query



def apiSuccess(payload=None):
    return {
        "status": "ok",
        "result": payload
    }

def apiError(reason):
    return {
        "status": "error",
        "reason": reason
    }

def raiseApiError(message, status=400):
    headers = {
        "Content-type": "application/json",
        "Access-Control-Allow-Origin": "*"
    }
    raise HTTPResponse(apiError(message), status, headers=headers)

def raiseApiUnauthorizedError():
    raiseApiError("unauthorized", 401)

def checkValidApiKey(conn, request):
    apiKey = request.get_header("X-API-Key")
    if not pf.isValidApiKey(conn, apiKey):
        raiseApiUnauthorizedError()

def loadRowToJson(row):
    (timestamp, avg) = row

    return {
        "timestamp": timestamp.isoformat(),
        "avg": float(avg)
    }

def logRowToJson(row):
    (psqlId, timestamp, ip, referer, userAgent, os, tls, host, request, httpMethod,
        path, status, bytesSent, requestTime, extra) = row
    return {
        "id": psqlId,
        "timestamp": timestamp.isoformat(),
        "ip": ip,
        "referer": referer if referer else "",
        "userAgent": userAgent if userAgent else "",
        "os": os if os else "",
        "tls": tls if tls else "",
        "host": host,
        "request": request,
        "httpMethod": httpMethod,
        "path": path,
        "status": status,
        "bytesSent": bytesSent,
        "requestTime": requestTime.total_seconds()
    }

def parseParam(request, name, default, paramType):
    value = request.query.get(name, default)
    try:
        value = paramType(value)
    except ValueError:
        value = default

    return value

def boolean(b):
    return b == "true"

def date(d):
    return datetime.fromisoformat(d).isoformat()

def commaList(entryType=str):
    return lambda l: [entryType(entry) for entry in l.split(",")] if l else []

def getFilters(request):
    excludeFailuresOpt = parseParam(request, "exclude_failures", False, boolean)
    excludeSpamOpt = parseParam(request, "exclude_spam", False, boolean)
    includedPaths = parseParam(request, "include_paths", [], commaList())
    excludedPaths = parseParam(request, "exclude_paths", [], commaList())
    includedFileTypes = parseParam(request, "include_file_types", [], commaList())
    excludedFileTypes = parseParam(request, "exclude_file_types", [], commaList())

    filters = []
    if excludeFailuresOpt:
        filters.append(pf.statusRangeFilter(100, 400))
    if excludeSpamOpt:
        filters.append(Not(pf.osFilter(None)))
        filters.append(Not(pf.statusFilter(444)))
    if len(includedPaths) > 0:
        filters.append(pf.includePathsFilter(includedPaths))
    if len(excludedPaths) > 0:
        filters.append(pf.excludePathsFilter(excludedPaths))
    if len(includedFileTypes) > 0:
        filters.append(pf.includeFileTypesFilter(includedFileTypes))
    if len(excludedFileTypes) > 0:
        filters.append(pf.excludeFileTypesFilter(excludedFileTypes))

    return filters

def getChunkingParams(request):
    interval = parseParam(request, "interval", "1 hour", str)
    numBuckets = parseParam(request, "num_buckets", 12, int)
    chunkRounding = parseParam(request, "chunk_rounding",
        datetime(2000, 1, 1, tzinfo=pytz.timezone("UTC")).isoformat(), date)
    return interval, numBuckets, chunkRounding

def getLimitAndOffset(request, defaultLimit=pf.MAX_LIMIT):
    limit = parseParam(request, "limit", defaultLimit, int)
    limit = min(limit, pf.MAX_LIMIT)
    offset = parseParam(request, "offset", 0, int)
    return limit, offset

@error(404)
@error(405)
def errorCatchAll(error):
    response.status = 401
    response.headers["Content-type"] = "application/json"
    return json.dumps(apiError("unauthorized"))

@get("/load")
def getLoad():
    checkValidApiKey(conn, request)

    interval, numBuckets, chunkRounding = getChunkingParams(request)
    subquery = Query("server_load", None, limit=pf.MAX_LIMIT)
    query = pf.getLoadAvg(interval, numBuckets, chunkRounding, subquery)

    rows = pf.executeStatement(conn, query)
    rows = [loadRowToJson(row) for row in rows]
    return apiSuccess(rows)

@get("/traffic")
def getTraffic():
    checkValidApiKey(conn, request)

    filters = getFilters(request)
    interval, numBuckets, chunkRounding = getChunkingParams(request)
    subquery = Query("aeromancer_log", And(filters), limit=pf.MAX_LIMIT)
    query = pf.chunkEntriesQuery(interval, numBuckets, chunkRounding, subquery)

    rows = pf.executeStatement(conn, query)
    rows = [{"time": str(time), "hits": hits} for time, hits in rows]
    return apiSuccess(rows)

@get("/requests")
def getRequests():
    checkValidApiKey(conn, request)

    startTime = parseParam(request, "start",
        (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), date)
    endTime = parseParam(request, "end",
        datetime.now(timezone.utc).isoformat(), date)
    limit, offset = getLimitAndOffset(request)
    filters = getFilters(request)
    filters.append(pf.timeRangeFilter(startTime, endTime))
    query = Query("aeromancer_log", And(filters), limit, offset)

    rows = pf.executeStatement(conn, query)
    rows = [logRowToJson(row) for row in rows]
    return apiSuccess(rows)

@post("/key")
def addApiKey():
    checkValidApiKey(conn, request)

    newKey = pf.addNewApiKey(conn)

    return apiSuccess({
        "apiKey": newKey
    })

@route("/<:re:.*>", method="OPTIONS")
def optionsIntercept():
    pass

@hook("after_request")
def applyCors():
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.set_header("Access-Control-Allow-Headers", "Access-Control-Allow-Origin, Content-Type, Accept, Accept-Language, Origin, User-Agent, X-API-Key")
    response.headers["Content-type"] = "application/json"



conn = pf.connectToDb()
run(host="0.0.0.0", port=10123, debug=False)

