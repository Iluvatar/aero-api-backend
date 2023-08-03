from datetime import datetime
import os

import psqlFunctions as pf

conn = pf.connectToDb()

one, five, fifteen = os.getloadavg()
timestamp = datetime.now().replace(second=0, microsecond=0).isoformat()

query = """
    DELETE FROM server_load WHERE timestamp < now() - interval '365 days'"""
pf.executeStatement(conn, query)

query = """
    INSERT INTO server_load (timestamp, one_min_avg, five_min_avg, fifteen_min_avg)
    VALUES (%s, %s, %s, %s)"""
pf.executeStatement(conn, query, (timestamp, one, five, fifteen))

conn.commit()

