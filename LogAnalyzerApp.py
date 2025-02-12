import glob, os, csv, re
from pathlib import Path
from collections import Counter

class LogAnalyzer:
    def __init__(self,log_folder):
        self.log_folder = log_folder

    def read_my_log(self,folderName,logNum):
        os.chdir("your path to folder with relevant logs")
        folder = Path(folderName)
        all_logs = list(folder.glob('access_*.log'))
        num = str(logNum)
        b = 0
        dataList = []
        for i in all_logs:
            curr_file = all_logs[b]
            folder_name = os.path.basename(curr_file)
            if num in folder_name: 
                with open(curr_file, 'r') as file:
                    readData = csv.reader(file)
                    dataList = list(readData)
            b = b+1
        return dataList

    def clientIP(self,clientIP,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        i = 0
        a = 0
        curLogList = []
        occ = 0
        for i in logData:
            currLogLIST = logData[a]
            a = a+1
            currLogSTR = str(currLogLIST)
            if clientIP in currLogSTR:
                occ = occ+1
        print("ClientIP ", clientIP, " occured: ",occ," times.")
                 
    def timeStamp(self,timeStamp,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        i = 0
        a = 0
        curLogList = []
        occ = 0
        for i in logData:
            currLogLIST = logData[a]
            a = a+1
            currLogSTR = str(currLogLIST)
            if timeStamp in currLogSTR:
                occ = occ+1   
        print("TimeStamp ", timeStamp, " occured: ",occ," times.")

    def httpActions(self,action,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        i = 0
        a = 0
        curLogList = []
        occ = 0
        for i in logData:
            currLogLIST = logData[a]
            a = a+1
            currLogSTR = str(currLogLIST)
            index = currLogSTR.find(action)
            if index != -1:
                occ = occ+1
        print("HTTP Action: ",action, " occured: ",occ," times.")

    def httpStatusCode(self, code, logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        i = 0
        a = 0
        currLogList = []
        occ = 0
        for i in logData:
            currLogLIST = logData[a]
            a = a+1
            currLogSTR = str(currLogLIST)
            index = currLogSTR.find(code)
            if index != -1:
                occ = occ+1
        print("HTTP Status Code ", code, " occured: ",occ," times.")

    def clientIPTimePeriod(self,n,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        delimiter = "-"
        a = 0
        tmpList = []
        for i in logData:
            currLogLIST = logData[a]
            a = a+1
            currLogSTR = str(currLogLIST)
            currIP1 = currLogSTR.index(delimiter)
            currIP2 = currLogSTR[:currIP1]
            currIP = currIP2[2:]
            tmpList.append(currIP)
        ip_count = {}
        for ip in tmpList:
            if ip in ip_count:
                ip_count[ip] += 1
            else:
                ip_count[ip] = 1
        ip_occ = [[ip, count] for ip, count in ip_count.items()]
        sorted_ip_occurrences = sorted(ip_occ, key=lambda x: x[1], reverse=True)
        del sorted_ip_occurrences[n:]
        print("Top", n, "ClientIPs: ",sorted_ip_occurrences)   
                
    def httpActionsTimePeriod(self,n,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        status_code_pattern = re.compile(r'HTTP/1\.\d"\s(\d{3})')
        status_code_count = Counter()
        for line in logData:
            lineA = str(line)
            match = status_code_pattern.search(lineA)
            if match:
                status_code = match.group(1)
                status_code_count[status_code] += 1
        sorted_occ = dict(sorted(status_code_count.items(), key=lambda item: item[1], reverse=True))
        print("All Status Codes: ",sorted_occ)
        
    def clientIPStatusCodes(self,n,statusCode,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?HTTP/1\.\d"\s(\d{3})')
        ip_count = Counter()
        for line in logData:
            lineA = str(line)
            match = log_pattern.search(lineA)
            if match:
                ip_address, log_status_code = match.groups()
                if log_status_code == statusCode:
                    ip_count[ip_address] += 1
        sorted_occ = dict(sorted(ip_count.items(), key=lambda item: item[1], reverse=True))
        keys_to_keep = list(sorted_occ.keys())[:n]
        new_dict = {key: sorted_occ[key] for key in keys_to_keep}
        print("Top",n,statusCode,"code occurrences: ",new_dict)

    def clientIPActionStatusCode(self,n,action,statusCode,logNum):
        logData = self.read_my_log(self.log_folder,logNum)
        log_pattern=re.compile(r'(\d+\.\d+\.\d+\.\d+)--\[.*?\]"(GET|POST|PUT|DELETE|PATCH|OPTIONS)/.*?HTTP/1\.\d"(\d{3})')
        ip_count = Counter()
        for line in logData:
            lineA = str(line)
            match = log_pattern.search(lineA)
            if match:
                ip_address, log_action, log_status_code = match.groups()
                if log_action == action and log_status_code == statusCode:
                    ip_count[ip_address] += 1
        sorted_occ = dict(sorted(ip_count.items(), key=lambda item: item[1], reverse=True))
        keys_to_keep = list(sorted_occ.keys())[:n]
        new_dict = {key: sorted_occ[key] for key in keys_to_keep}
        print("Top",n,"ClientIPs with HTPP action",action,"and status code",statusCode,":",new_dict)
        
log_folder = "log"
me = LogAnalyzer(log_folder)
me.clientIP("205.167.170.15 ",1)
me.timeStamp("09/Jan/2016",1)
me.httpActions("HEAD",1)
me.httpStatusCode(" 404 ",1)
me.clientIPTimePeriod(10,1)
me.httpActionsTimePeriod(3,1)
me.clientIPStatusCodes(5,'404',1)
me.clientIPActionStatusCode(5,'POST','200',1)
