# coding:utf-8
#!/bin/bash
import MySQLdb
from MySQL_Operate import DBConn
import Levenshtein
import datetime
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from Queue import Queue
import os
import time

"""
Duplicate Users Rule :
(E: excat , S:similar)
"""
LABEL_USERNAME = 0  # S
LABEL_PASSWD = 1    # E
LABEL_REALNAME = 2  # S/E
LABEL_MOBILE = 3    # E
LABEL_EMAIL = 4     # S
LABEL_CITY = 5      # E
LABEL_COUNTRY = 6   # E
LABEL_ADDRESS = 7   # E
LABEL_IP = 8        # E
LABEL_COOKIE =  9   # E
LABEL_DEVICE = 10   # E
LABEL_REFERER = 11  # E
LABEL_LOGINIP = 12  # E

LABEL_EXACT = 0
LABEL_SIMILAR = 1

MIN_MATCH_LEVEL = 3
BASE_PATH = os.path.abspath(".")
SLEEP_TIME = 8*60 # second

sUSER = "xxxx"
sPASS = "xxxx"
sHOST = "xxxx"
sDBNAME = "xxxx"
sPORT = 3306

def getIpMatching(input_userid):
    input_userid = str(input_userid)
    if input_userid == "" or not userid_ip_table.has_key(input_userid):
        return []

    chk_dict = {}
    try:
        for ip in userid_ip_table[input_userid].split(","):
            for userid in ip_userid_table[ip].split(","):
                if chk_dict.has_key(userid):
                    chk_dict[userid] += 1
                else:
                    chk_dict.__setitem__(userid,1)
        return chk_dict.keys()
    except:
        return []

def get_duplicated_account(cResults, id_results, userResults, scores, userid_device_table, userid_ref_table,
                           userid_ip_table, idip_type_table):
    cUserInfoDict = {}
    for i in range(9):
        cUserInfoDict.__setitem__(i, cResults[i])

    cRealName = cUserInfoDict[LABEL_REALNAME]
    cPasswd = cUserInfoDict[LABEL_PASSWD]
    cMobile = cUserInfoDict[LABEL_MOBILE]
    cCity = cUserInfoDict[LABEL_CITY]
    cCountry = cUserInfoDict[LABEL_COUNTRY]
    cAddress = cUserInfoDict[LABEL_ADDRESS]
    cRegIp = cUserInfoDict[LABEL_IP]
    cUserName = cUserInfoDict[LABEL_USERNAME]
    cEmail = cUserInfoDict[LABEL_EMAIL]
    cId = str(cResults[9])
    cLoginIps = set(userid_ip_table[cId].strip().split(","))
    cDevs = set(userid_device_table[cId].strip().split(","))
    cRefs = set(userid_ref_table[cId].strip().split(","))

    totalrates = {}

    for dResult in userResults:
        sRegIp = ""
        sDevice = ""
        sRef = ""
        sCookie = ""
        sPass = ""
        sRealName = ""
        sEmail = ""
        sCity = ""
        sCountry = ""
        sAddress = ""
        sLoginIp = ""
        sDepositIp = ""
        sWithdrawIp = ""
        sTranMain2Sub = ""
        sTranSub2Main = ""
        sMobile = ""
        sIpTypes = ""

        dUserInfoDict = {}
        for i in range(9):
            dUserInfoDict.__setitem__(i, dResult[i])

        dRealName = dUserInfoDict[LABEL_REALNAME]
        dPasswd = dUserInfoDict[LABEL_PASSWD]
        dMobile = dUserInfoDict[LABEL_MOBILE]
        dCity = dUserInfoDict[LABEL_CITY]
        dCountry = dUserInfoDict[LABEL_COUNTRY]
        dAddress = dUserInfoDict[LABEL_ADDRESS]
        dRegIp = dUserInfoDict[LABEL_IP]
        dUserName = dUserInfoDict[LABEL_USERNAME]
        dEmail = dUserInfoDict[LABEL_EMAIL]

        rate = 0
        dId = str(dResult[9])
        if dId == cId:
            continue
        #  先判IP是否相同，再判斷device, referrer
        if dId in id_results:
            dLoginIps = set(userid_ip_table[dId].strip().split(","))
            dupIp = list(cLoginIps.intersection(dLoginIps))[0]
            rate += scores[LABEL_LOGINIP][LABEL_EXACT]
            #  Ip type
            if idip_type_table.has_key(dId+'-'+dupIp):
                sIpTypes = idip_type_table[dId+'-'+dupIp]

            if "2" in sIpTypes:
                sLoginIp = dupIp
            if "3" in sIpTypes:
                sDepositIp = dupIp
            if "4" in sIpTypes:
                sWithdrawIp = dupIp
            if "5" in sIpTypes:
                sTranMain2Sub = dupIp
            if "6" in sIpTypes:
                sTranSub2Main = dupIp

            #  Device
            dDevs = set(userid_device_table[dId].strip().split(","))
            if len(cDevs.intersection(dDevs)) != 0:
                sDevice = list(cDevs.intersection(dDevs))[0]
                rate += scores[LABEL_DEVICE][LABEL_EXACT]

            #  Referrer
            dRefs = set(userid_ref_table[dId].strip().split(","))
            if len(cRefs.intersection(dRefs)) != 0:
                sRef = list(cRefs.intersection(dRefs))[0]
                rate += scores[LABEL_REFERER][LABEL_EXACT]
        # else:
        #     continue

        # Similar
        #   -UserName
        dist = Levenshtein.distance(cUserName, dUserName)
        if 0 < dist < MIN_MATCH_LEVEL:
            rate += scores[LABEL_USERNAME][LABEL_SIMILAR]
        # -RealName
        dist = Levenshtein.distance(cRealName, dRealName)
        if 0 < dist < MIN_MATCH_LEVEL:
            sRealName = dRealName
            rate += scores[LABEL_REALNAME][LABEL_SIMILAR]
        # -Email
        dist = Levenshtein.distance(cEmail, dEmail)
        if 0 < dist < MIN_MATCH_LEVEL:
            sEmail = dEmail
            rate += scores[LABEL_EMAIL][LABEL_SIMILAR]

        # Exact
        if cPasswd == dPasswd:
            sPass = dPasswd
            rate += scores[LABEL_PASSWD][LABEL_EXACT]
        if cMobile == dMobile:
            sMobile = dMobile
            rate += scores[LABEL_MOBILE][LABEL_EXACT]
        if cCity == dCity:
            sCity = dCity
            rate += scores[LABEL_CITY][LABEL_EXACT]
        if cCountry == dCountry:
            sCountry = dCountry
            rate += scores[LABEL_COUNTRY][LABEL_EXACT]
        if cAddress == dAddress:
            sAddress = dAddress
            rate += scores[LABEL_ADDRESS][LABEL_EXACT]
        if cRegIp == dRegIp:
            sRegIp = dRegIp
            rate += scores[LABEL_IP][LABEL_EXACT]
        sInfo = str(rate)+','+sRegIp+','+sLoginIp+','+sDepositIp+','+sWithdrawIp+','+sTranMain2Sub+','+sTranSub2Main+','+\
                sRealName+','+sPass+','+sEmail+','+sMobile+','+sAddress+','+sCity+','+sCountry+','+sCookie+','+sRef+','+sDevice
        if totalrates.has_key(dUserName):
            if rate > totalrates[dUserName]:
                totalrates[dUserName] = sInfo
        else:
            totalrates.__setitem__(dUserName, sInfo)

    sortRates = sorted(totalrates.items(), lambda x, y: cmp(int(x[1].split(",")[0]), int(y[1].split(",")[0])), reverse=True)
    db = DBConn(sHOST, sPORT, sUSER, sPASS, sDBNAME)
    db.dbConnect()

    state = "DELETE FROM duplicate_account_info WHERE userName='{}'".format(cUserName)
    db.exeDelete(state)

    data = ""
    for item in sortRates[:20]:
        data += u'("'+cUserName+u'","'+item[0]+u'","'+item[1].split(",")[1]+u'","'+item[1].split(",")[2]+u'","'+item[1].split(",")[3]+u'","'+ \
                item[1].split(",")[4]+u'","'+item[1].split(",")[5]+u'","'+item[1].split(",")[6]+u'","'+item[1].split(",")[7]+u'","'+ \
                item[1].split(",")[8]+u'","'+item[1].split(",")[9]+u'","'+item[1].split(",")[10]+u'","'+item[1].split(",")[11]+u'","'+\
                item[1].split(",")[12]+u'","'+item[1].split(",")[13]+u'","'+item[1].split(",")[14]+u'","'+item[1].split(",")[15]+u'","'+ \
                item[1].split(",")[16]+u'",'+item[1].split(",")[0]+u'),'
    data = data[0:len(data)-1] + u";"
    state = u"INSERT INTO duplicate_account_info (userName, dup_userName, dup_regIp, dup_loginIp, dup_depositIp, dup_withdrawIp, " \
            u"dup_TranMain2SubIp, dup_TranSub2MainIp, dup_realName, dup_passwd, dup_email, dup_mobile, dup_address, " \
            u"dup_city, dup_country, dup_cookie, dup_referrer, dup_device, total_rate) VALUES {}".format(data)
    db.exeInsert(state)

def sort_data(result):
    userid = str(result[0])
    ip = result[1]
    device = result[3]
    ref = result[4]
    iptype = str(result[5])
    if userid_ip_table.has_key(userid):
        if not userid_ip_table[userid].__contains__(ip):
            userid_ip_table[userid] += "," + ip
    else:
        userid_ip_table.__setitem__(userid, ip)

    if userid_device_table.has_key(userid):
        if not userid_device_table[userid].__contains__(device):
            userid_device_table[userid] += "," + device
    else:
        userid_device_table.__setitem__(userid, device)

    if userid_ref_table.has_key(userid):
        if not userid_ref_table[userid].__contains__(ref):
            userid_ref_table[userid] += "," + ref
    else:
        userid_ref_table.__setitem__(userid, ref)

    if ip_userid_table.has_key(ip):
        if not ip_userid_table[ip].__contains__(userid):
            ip_userid_table[ip] += "," + userid
    else:
        ip_userid_table.__setitem__(ip, userid)

    if idip_type_table.has_key(userid+'-'+ip):
        if not idip_type_table[userid+'-'+ip].__contains__(iptype):
            idip_type_table[userid+'-'+ip] += "," + iptype
    else:
        idip_type_table.__setitem__(userid+'-'+ip, iptype)

		
if __name__=="__main__":
    if os.path.exists(BASE_PATH + "/userid_ip_table.txt"):
        print "get 'http_request' history data ..."
        all_results = []
        with open(BASE_PATH + "/userid_ip_table.txt", "r") as f:
            for line in f.readlines():
                userid = int(line.split(",")[0])
                ips = line.split(",")[1]
                date = datetime.datetime.strptime(line.split(",")[2], '%Y-%m-%d %H:%M:%S')
                last_time = date
                device = line.split(",")[3]
                ref = line.split(",")[4]
                iptype = line.split(",")[5]
                tmp = userid, ips, date, device, ref, iptype
                all_results.append(tmp)
            f.close

        print "build userid => ip, ip => userid table..."
        userid_ip_table = {}
        with open(BASE_PATH + "/userid_table.txt","r") as f:
            for line in f.readlines():
                userid_ip_table.__setitem__(line.split(" : ")[0], line.split(" : ")[1].strip())
            f.close

        userid_device_table = {}
        with open(BASE_PATH + "/device_table.txt","r") as f:
            for line in f.readlines():
                userid_device_table.__setitem__(line.split(" : ")[0], line.split(" : ")[1].strip())
            f.close

        userid_ref_table = {}
        with open(BASE_PATH + "/ref_table.txt","r") as f:
            for line in f.readlines():
                userid_ref_table.__setitem__(line.split(" : ")[0], line.split(" : ")[1].strip())
            f.close

        ip_userid_table = {}
        with open(BASE_PATH + "/ip_table.txt","r") as f:
            for line in f.readlines():
                ip_userid_table.__setitem__(line.split(" : ")[0], line.split(" : ")[1].strip())
            f.close

        idip_type_table = {}
        with open(BASE_PATH + "/type_table.txt","r") as f:
            for line in f.readlines():
                idip_type_table.__setitem__(line.split(" : ")[0], line.split(" : ")[1].strip())
            f.close
    else:
        # 從資料庫重新抓取所有數據
        print "get 'http_request' history data ..."
        sDB = DBConn(sHOST, sPORT, sUSER, sPASS, sDBNAME)
        sDB.dbConnect()
        state = "SELECT  p1.playerid, p1.ip, p1.createdat, IFNULL(p1.device,''), IFNULL(p1.referrer,''), p1.type " \
                "FROM http_request p1;"
        all_results = list(sDB.exeQuery(state))
        sDB.dbClose()

        print "build userid => ip, ip => userid table..."
        userid_ip_table = {}
        userid_device_table = {}
        userid_ref_table = {}
        ip_userid_table = {}
        idip_type_table = {}
        for result in all_results:
            sort_data(result)

    print "get 'duplicate_account' rates..."
    sDB = DBConn(sHOST, sPORT, sUSER, sPASS, sDBNAME)
    sDB.dbConnect()
    state = "SELECT rate_exact, rate_similar, status " \
            "FROM duplicate_account_setting;"
    scores = sDB.exeQuery(state)
    sDB.dbClose()

    # 測試使用評分
    # scores = []
    # for score in scores_tmp:
    #     (x, y, status) = score
    #     scores.append((x + 1, y + 1, status))

    queue = Queue()
    cpus = multiprocessing.cpu_count()
    time_end = all_results[len(all_results)-1][2]
    # time_end = datetime.datetime.now()-datetime.timedelta(minutes=10)
    while True:
        try:
            print "========== program start... =========="
            time_start = time_end
            sDB = DBConn(sHOST, sPORT, sUSER, sPASS, sDBNAME)
            sDB.dbConnect()

            t1 = datetime.datetime.now()
            print "get 'http_request' data - from "+time_start.strftime("%Y-%m-%d %H:%M:%S")+" to now..."
            state = "SELECT  p1.playerid, p1.ip, p1.createdat, IFNULL(p1.device,''), IFNULL(p1.referrer,''), p1.type " \
                    "FROM http_request p1 " \
                    "WHERE createdat >= '{}'".format(time_start.strftime("%Y-%m-%d %H:%M:%S"))
            new_list = list(sDB.exeQuery(state))
            print len(new_list)
            new_userid_list = [item[0] for item in new_list]
            time_end = datetime.datetime.now()
            all_results.extend(new_list)

            print "build new userid => ip, ip => userid table..."
            for result in new_list:
                sort_data(result)

            print "query users data..."
            state = "SELECT  p1.username, p1.password, concat(IFNULL(p2.firstname,''),IFNULL(p2.lastname,'')) 'RealName', " \
                    "IFNULL(p2.phone,''), IFNULL(p1.email,''), IFNULL(p2.city,''), IFNULL(p2.country,''), IFNULL(p2.address,''), " \
                    "IFNULL(p2.registrationIP,''), p1.playerId " \
                    "FROM player p1 JOIN playerdetails p2 ON p1.playerid=p2.playerid ;"
            userResults = sDB.exeQuery(state)
            sDB.dbClose()
            t2 = datetime.datetime.now()
            print str(t2-t1)

            print "calculate duplicate users rate..."
            for cResult in userResults:
                if cResult[9] in new_userid_list:
                    queue.put(cResult)

            with ProcessPoolExecutor(max_workers=cpus) as executor:
                while not queue.empty():
                    cResults = queue.get()
                    cId = cResults[9]
                    id_results = getIpMatching(cId)
                    executor.submit(get_duplicated_account, cResults, id_results, userResults, scores,
                                    userid_device_table, userid_ref_table, userid_ip_table, idip_type_table)

            t3 = datetime.datetime.now()
            print str(t3 - t2)

        except MySQLdb.Error as e:
            print "Error %d: %s" % (e.args[0], e.args[1])
        finally:
            print "saving data..."
            with open(BASE_PATH + "/userid_ip_table.txt","w") as f:
                item = all_results[len(all_results)-1]
                f.writelines(str(item[0])+","+item[1]+","+item[2].strftime("%Y-%m-%d %H:%M:%S")+","+item[3]+","+item[4]+","+str(item[5])+"\n")
                f.close
            with open(BASE_PATH + "/userid_table.txt","w") as f:
                for item in userid_ip_table.iteritems():
                    f.writelines(item[0]+" : "+item[1]+"\n")
                f.close
            with open(BASE_PATH + "/ip_table.txt","w") as f:
                for item in ip_userid_table.iteritems():
                    f.writelines(item[0]+" : "+item[1]+"\n")
                f.close
            with open(BASE_PATH + "/device_table.txt","w") as f:
                for item in userid_device_table.iteritems():
                    f.writelines(item[0]+" : "+item[1]+"\n")
                f.close
            with open(BASE_PATH + "/ref_table.txt","w") as f:
                for item in userid_ref_table.iteritems():
                    f.writelines(item[0]+" : "+item[1]+"\n")
                f.close
            with open(BASE_PATH + "/type_table.txt","w") as f:
                for item in idip_type_table.iteritems():
                    f.writelines(item[0]+" : "+item[1]+"\n")
                f.close
            print "========== program sleeping... =========="
            time.sleep(SLEEP_TIME)
