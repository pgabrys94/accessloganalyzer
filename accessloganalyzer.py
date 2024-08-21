# v1.2.4

import os
import socket
import sys
import re
from datetime import datetime

t_start = datetime.now()


def log_open(logfile):
    """
    Function for loading log file.
    :param logfile: String -> path to log file
    :return: List of lines from logfile OR exit.
    """

    if os.path.exists(logfile):
        with open(logfile, "r") as logfile:
            return logfile.read().splitlines()
    else:
        print("Log file not found.")
        sys.exit()


def log_detect(webserver):
    """
    Function for detecting logfile based on directories in /var/log
    :param webserver: String | None -> predefined webserver
    :return: List of lines from logfile OR exit.
    """

    if webserver is None:
        f_name = "access.log.1"
        l_path = "/var/log"
        apache_path = os.path.join(l_path, 'apache')
        nginx_path = os.path.join(l_path, 'nginx')
        apache = os.path.exists(apache_path)
        nginx = os.path.exists(nginx_path)

        if apache and nginx:
            print("Detected Apache and NGINX log file directories, select your webserver by running script with"
                  "'apache' or 'nginx' as parameter.")
            sys.exit()
        elif not apache and not nginx:
            print("No webserver log directory detected. Exiting...")
            sys.exit()
        else:
            print("Detected {} webserver".format('apache' if apache else 'nginx'))
            file = os.path.join(apache_path if apache else nginx_path if nginx else None, f_name)

    else:
        file = os.path.join('/var/log/', webserver, "access.log.1")

    return log_open(file)


def main():
    """
    Main function for log analysis.
    :return:
    """

    help_text = """
Switches available:
\t-f --file\t provide access.log file path [/var/log/nginx|apache/access.log],
\t-l --limit\t makes report contain only IPs with >= [0] queries,
\t-q --query\t perform DNS reverse lookup on IPs with >= [500] queries (bots are always queried),
\t-r --response\t print query response codes counter,
\t-c --cred\t move queries containing credentials to top (also skips limit flag for those queries),

    """

    try:
        if "-l" in sys.argv or "--limit" in sys.argv:
            limit_flag = "-l" if "-l" in sys.argv else "--limit"
            limit_index = sys.argv.index(limit_flag) + 1
            limit = int(sys.argv[limit_index]) if sys.argv[limit_index].isnumeric() else 0
        else:
            limit = 0
        print(f"Report limit: >={limit} queries")

        if "-q" in sys.argv or "--query" in sys.argv:
            resolve_flag = "-q" if "-q" in sys.argv else "--query"
            resolve_index = sys.argv.index(resolve_flag) + 1
            resolve_limit = int(sys.argv[resolve_index]) if sys.argv[resolve_index].isnumeric() else 500
        else:
            resolve_limit = 500
        print(f"Queries needed to resolve: >={resolve_limit}")

        if "h" in sys.argv or "--help" in sys.argv:
            print(help_text)
            sys.exit()

        if limit == 0:
            report = os.path.join(os.getcwd(), datetime.now().strftime("%Y%m%d-%H%M%S") + "-report" + ".txt")
        else:
            report = os.path.join(os.getcwd(), datetime.now().strftime("%Y%m%d-%H%M%S") +
                                  f"-report-TOP{limit}" + ".txt")

        cred_flag = True if "-c" in sys.argv or "--cred" in sys.argv else False
        response_flag = True if "-r" in sys.argv or "--response" in sys.argv else False
        webserver = "apache" if "apache" in sys.argv else "nginx" if "nginx" in sys.argv else None

        total = 0
        bot_total_queries = 0
        ips = {}
        web_protocols = ['HTTP', 'HTTPS', 'FTP', 'SFTP', 'FTPS', 'SCP', 'SMTP',
                         'POP3', 'IMAP', 'LDAP', 'LDAPS', 'NNTP', 'SNMP', 'Telnet', 'SSH']
        botnt = ['actionbot', 'both']
        bot = ['bot', 'crawler', 'artemis', 'turnitin', 'barkrowler', 'bytespider', 'bytedance', 'buck']

        if limit:
            print(f"\nLIMIT: Report will only contain IPs with more than {limit} queries.")
        else:
            print("\n")

        if "-f" in sys.argv or "--file" in sys.argv:
            flag = "-f" if "-f" in sys.argv else "--file"
            supposed_path = os.path.normpath(sys.argv[sys.argv.index(flag) + 1])
            log = log_open(supposed_path)
        else:
            log = log_detect(webserver)

        for line in log:

            c_ret = line != log[-1]
            print(f"PROGRESS: {total} of {len(log)} ({round(total * 100 / len(log), 2):.2f}%)",
                  end='\r' if c_ret else '\n', flush=True)

            hostname = ""
            bot_id = ""
            bot_queries = 0
            total += 1

            done = False
            for part in line.split('"')[::-1]:
                if any(word in part.lower() for word in bot):
                    if "get" in part.lower() or "post" in part.lower():
                        break
                    for s_part in part.split():
                        is_bot = (any(word in s_part.lower() for word in bot) and
                                  any(keyword not in s_part.lower() for keyword in botnt))
                        is_protocol = any(proto.lower() in s_part.lower() for proto in web_protocols)
                        if is_bot and not is_protocol:
                            bot_id = s_part
                            bot_total_queries += 1
                            bot_queries = 1
                            done = True
                            break
                if done:
                    break

            parts = line.split()
            ip = parts[0]
            cred_end = parts.index(next(part for part in parts if part.startswith("[")))
            cred = " ".join(parts[2:cred_end]).strip()
            query_hour = parts[cred_end].split(":")[1]

            pattern = r'\"[A-Z]+\s.*?\"\s(\d{3})\s'
            match = re.search(pattern, line)
            status = match.group(1) if match else ""

            if ip not in ips:
                if bot_id:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = "NX"
                ips[ip] = [1, bot_queries, [bot_id], {query_hour: [1, {status: 1}]}, [cred], hostname]
            else:
                ips[ip][0] += 1
                if bot_queries > 0:
                    ips[ip][1] += 1
                    if bot_id not in ips[ip][2]:
                        ips[ip][2].append(bot_id)

                if (ips[ip][0] >= resolve_limit or bot_queries > 0) and len(ips[ip][5]) == 0:
                    try:
                        ips[ip][5] = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        ips[ip][5] = "NX"

                if query_hour in ips[ip][3]:
                    ips[ip][3][query_hour][0] += 1
                    if status in ips[ip][3][query_hour][1]:
                        ips[ip][3][query_hour][1][status] += 1
                    else:
                        ips[ip][3][query_hour][1][status] = 1
                else:
                    ips[ip][3][query_hour] = [1, {status: 1}]

                if cred != "-":
                    if cred not in ips[ip][4]:
                        ips[ip][4].append(cred)

        result = []
        skipped = 0
        sorted_ips = sorted(ips.items(), key=lambda item: item[1][0], reverse=True)
        if cred_flag:
            cred_ips = [(ip, data) for ip, data in sorted_ips if data[4][0] != "-" or len(data[4]) > 1]
            sorted_ips = cred_ips + [(ip, data) for ip, data in sorted_ips if (ip, data) not in cred_ips]

        result.append(f"Total lines: {total}")
        result.append("\nBots: {} query lines [{}%]\n".format(bot_total_queries,
                                                              round(bot_total_queries * 100 / total, 2)))

        for ip, data in sorted_ips:
            status = ""
            if data[1] > 0:
                status = f"\nBot queries: {data[1]} ({round(data[1] * 100 / data[0], 2)}%)\nBot IDs: {data[2]}"
            else:
                if data[0] == data[1]:
                    status = "BOT"

            sorted_hours = sorted(data[3].items(), key=lambda item: item[0], reverse=False)
            hits_on_hour = " \n\tTimings:\n"
            responses = ""
            for hour, hits in sorted_hours:
                sorted_responses = sorted(hits[1].items(), key=lambda item: item[1], reverse=True)
                if response_flag:
                    responses = "\tR: "
                    for code, counter in sorted_responses:
                        responses += f"{code}: {counter} | "
                hits_on_hour += f"\t{hour}:xx - {hits[0]} hit(s);{responses}\n"

            speed = round(data[0] / 24)
            if data[0] > limit:
                result.append("\nIP: {} ({})  -  {} hits (~{}/h), {}{}{}\n"
                              .format(ip, data[5], data[0], speed if speed > 0 else 1, status,
                                      f"\tCredentials: {data[4]}" if data[4][0] != "-" or len(data[4]) > 1
                                      else "", hits_on_hour))
            elif data[0] < limit and cred_flag:
                if data[4][0] != "-" or len(data[4]) > 1:
                    result.append("\nIP: {} ({})  -  {} hits (~{}/h), {}{}{}\n"
                                  .format(ip, data[5], data[0], speed if speed > 0 else 1, status,
                                          f"\tCredentials: {data[4]}", hits_on_hour))
                else:
                    skipped += 1
            else:
                skipped += 1

        t_stop = datetime.now()
        result.insert(1, "\nProcessed in {:.2f} seconds".format((t_stop - t_start).total_seconds()))
        if limit > 0:
            result.insert(3, f"\nSkipped {skipped} IPs due to limit set (minimum {limit} queries)\n")
        if cred_flag:
            result.insert(3, f"\nSORTING: queries with credentials first (including low number queries)\n")

        result.append("\n\n[END OF REPORT]")

        with open(report, "w") as report_file:
            report_file.writelines(result)

        print(f"Done, processed {total} lines in {int(round((t_stop - t_start).total_seconds(), 0))}s")

    except Exception as error:
        print(f"Unexpected exception occurred: {error}. Exiting...")
        sys.exit(1)


if __name__ == "__main__":
    main()
