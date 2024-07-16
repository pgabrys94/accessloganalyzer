import os
import socket
from datetime import datetime

t_start = datetime.now()
file = os.path.join(os.getcwd(), "access.log")
report = os.path.join(os.getcwd(), datetime.now().strftime("%Y%m%d-%H%M%S") + "-report" + ".txt")
with open(file, "r") as logfile:
    log = logfile.read().splitlines()

log_parts = [log[i::4] for i in range(4)]


total = 0
bot_total_queries = 0
ips = {}
web_protocols = ['HTTP', 'HTTPS', 'FTP', 'SFTP', 'FTPS', 'SCP', 'SMTP',
                 'POP3', 'IMAP', 'LDAP', 'LDAPS', 'NNTP', 'SNMP', 'Telnet', 'SSH']

for line in log:

    print(" " * 100, end='\r', flush=True)
    print(f"PROGRESS: {total} of {len(log)} ({round(total * 100 / len(log), 2)}%)", end='\r', flush=True)

    hostname = ""
    bot_id = ""
    bot_queries = 0
    total += 1
    is_bot = False

    done = False
    for part in line.split('"')[::-1]:
        if "bot" in part.lower():
            if "get" in part.lower() or "post" in part.lower():
                break
            for s_part in part.split():
                is_bot = "bot" in s_part.lower() and "actionbot" not in s_part.lower()
                is_protocol = any(proto.lower() in s_part.lower() for proto in web_protocols)
                if is_bot and not is_protocol:
                    bot_id = s_part
                    bot_total_queries += 1
                    bot_queries = 1
                    done = True
                    break
        if done:
            break

    ip = line.split()[0]
    cred = ""
    cred_pos = 2
    while True:
        cred += line.split()[cred_pos]
        cred_pos += 1
        if line.split()[cred_pos].startswith("["):
            break
        else:
            cred += " "
    query_hour = line.split()[2 + len(cred.split())].split(":")[1]

    if ip not in ips:
        if bot_id:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "NX"
        ips[ip] = [1, bot_queries, [bot_id], {query_hour: 1}, [cred], hostname]
    else:
        ips[ip][0] += 1
        if bot_queries > 0:
            ips[ip][1] += 1
            if bot_id not in ips[ip][2]:
                ips[ip][2].append(bot_id)

        if (ips[ip][0] >= 500 or bot_queries > 0) and len(ips[ip][5]) == 0:
            try:
                ips[ip][5] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                ips[ip][5] = "NX"

        if query_hour in ips[ip][3]:
            ips[ip][3][query_hour] += 1
        else:
            ips[ip][3][query_hour] = 1

        if cred != "-":
            if cred not in ips[ip][4]:
                ips[ip][4].append(cred)


result = []
sorted_ips = sorted(ips.items(), key=lambda item: item[1][0], reverse=True)
result.append(f"Total lines: {total}")
result.append("\nBots: {} query lines [{}%]\n".format(bot_total_queries, round(bot_total_queries * 100 / total, 2)))

for ip, data in sorted_ips:
    status = ""
    if data[1] > 0:
        status = f"\nBot queries: {data[1]} ({round(data[1] * 100 / data[0], 2)}%)\nBot IDs: {data[2]}"
    else:
        if data[0] == data[1]:
            status = "BOT"

    sorted_hours = sorted(data[3].items(), key=lambda item: item[0], reverse=False)
    hits_on_hour = " \n\tTimings:\n"
    for hour, hits in sorted_hours:
        hits_on_hour += f"\t{hour}:xx - {hits} hits;\n"

    speed = round(data[0] / 24)
    result.append("\nIP: {} ({})  -  {} hits (~{}/h), {}{}{}\n"
                  .format(ip, data[5], data[0], speed if speed > 0 else 1, status,
                          f"\tCredentials: {data[4]}" if data[4][0] != "-" or len(data[4]) > 1 else "", hits_on_hour))

t_stop = datetime.now()
result.insert(1, "\nProcessed in {:.2f} seconds".format((t_stop - t_start).total_seconds()))

with open(report, "w") as report_file:
    report_file.writelines(result)
