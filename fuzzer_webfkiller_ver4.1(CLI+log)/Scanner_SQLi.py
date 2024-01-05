import sys
import DB_util
import ast
import Util


conn = DB_util.connect_DB()

random_hash = sys.argv[1]

(
    type,
    status_code,
    time,
    url,
    header,
    parms,
    parms_count,
    body_size,
    body,
) = DB_util.get_modified_request(conn, random_hash)
url = url.split("?")[0]
header = ast.literal_eval(header)
parms = ast.literal_eval(parms)
#####################################################################################################
# 여기부터 취약점 탐지 코드


errors = [  # sql 오류코드
    # ======== MySQL =========
    "you have an error in your sql",
    "mysql server version for the right syntax",
    "supplied argument is not a valid mysql result resource",
    "warning: mysql",
    "check the manual that corresponds to your mysql",
    # ======== SQL Server =========
    "unclosed quotation mark after the character string",
    "incorrect syntax",
    # ======== Oracle ========
    "quoted string not properly terminated",
    "sql command not properly ended",
    # ======== SQLite3 ========
    "sql error or missing database",
    "<b>warning</b>:  sqlite3",
    "unrecognized token:",
    "unable to prepare statement:",
    # ======== PostgreSQL ========
    "error:  syntax error",
]
payload = next((value for key, value in parms.items() if "webfkiller" in value), "")
if status_code == 500:
    Util.print_result(type, "SQLi", url, parms, payload)
elif time >= 5:
    Util.print_result(type, "SQLi", url, parms, payload)
else:
    for error in errors:
        if error in body.lower():
            Util.print_result(type, "SQLi", url, parms, payload)
