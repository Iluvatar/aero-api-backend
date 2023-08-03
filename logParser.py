import asyncio
import configparser
import json
import psycopg2
import re

def config(filename, section):
    parser = configparser.ConfigParser()
    parser.read(filename)

    data = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            data[param[0]] = param[1]
    else:
        raise Exception(f"Section {section} not found in {filename}")

    return data

def initDb():
    global conn, cursor

    try:
        params = config("database.ini", "postgresql")
        conn = psycopg2.connect(**params)
        cursor = conn.cursor()
    except:
        print("Cannot connect to postgres")
        quit()

def parseLine(line):
    escapedLine = line.decode().replace("\\", "\\\\")
    return json.loads(escapedLine)

def parseOs(userAgent):
    if userAgent is None:
        return None
    if re.search("windows", userAgent, re.IGNORECASE):
        return "Windows"
    if re.search("macintosh", userAgent, re.IGNORECASE):
        return "Mac"
    if re.search("(linux|x11)", userAgent, re.IGNORECASE):
        return "Linux"
    if re.search("iphone", userAgent, re.IGNORECASE):
        return "iPhone"
    if re.search("android", userAgent, re.IGNORECASE):
        return "Android"
    if re.search("\+http", userAgent, re.IGNORECASE) or "Googlebot" in userAgent:
        return "Spider"
    return None

def parseParams(data):
    timestamp = data["time"]
    ip = data["ip"]
    referer = data["referer"]
    userAgent = data["user_agent"]
    tls = data["tls"]
    host = data["host"]
    request = data["request"]
    httpMethod = data["http_method"]
    path = data["path"]
    status = data["status"]
    bytesSent = data["body_bytes_sent"]
    requestTime = data["request_time"]

    if referer == "-":
        referer = None

    if tls == "-":
        tls = None

    if userAgent == "-":
        userAgent = None

    os = parseOs(userAgent)

    return (timestamp, ip, referer, userAgent, os, tls, host, request, httpMethod,
        path, status, bytesSent, requestTime)

def executeSql(data):
    global conn, cursor

    query = """
        INSERT INTO aeromancer_log (timestamp, ip, referer, user_agent, os, tls,
        host, request, http_method, path, status, bytes_sent, request_time)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"""

    params = parseParams(data)

    try:
        cursor.execute(query, params)
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e

async def handleMessage(reader, writer):
    while line := await reader.readline():
        data = parseLine(line)
        executeSql(data)

async def run_server():
    server = await asyncio.start_server(handleMessage, "localhost", 9123)
    async with server:
        await server.serve_forever()

initDb()
asyncio.run(run_server())

