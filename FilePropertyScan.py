# -*- coding: gbk -*-
'''
@version: v1.0 2014-10-20
@author : jenniwang
@brief: xxxx install file property scan
@param: filepath
@return: propertyDic = {"filepath_fullmd5_halfmd5":[ result],"file_funllmd5_halfmd5":[result]}
@result 1 denote file Property is as expected, result 0 means not meeting expectations;result BADNET means get safelevel
net timeout.
'''
import sys,os
import urllib2
import subprocess
import time
import datetime

class FilePropertyScan(object):

    def __init__(self,filepath):
        self.filepath = filepath
        global white, black, unkown
        white = 1
        black = 2
        unkown = 3
    '''
    @function: getSafelevel
    @brief: use background interface query the file property
    '''
    def getSafelevel(self,md5):
        query_url = 'http://xxx.xxx.xxx.xxx/get_cmem_by_md5.do?md5=%s' % md5
        try:
            content = urllib2.urlopen(query_url).read()
        except Exception, e:
            print Exception,":",e
            return -1
        safe = content.split('<safelevel>')
        #print "\n"+content
        if len(safe)==2:
            safelevel=safe[1].split('</safelevel>')[0]
            return safelevel
        else:
            return "failed"

    def ExecCmd(self,cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell = True)
        while True:
            ret =p.stdout.readline().strip('\n')
            if(ret):
                return ret
            else:
                time.sleep(0.001)

    def getMD5(self,type,fpath):
        cmdLine = 'CalcHash\CalcHash.exe '+type+" \""+fpath+"\""
        ret = self.ExecCmd(cmdLine)
        ret=ret.strip('\n')
        return ret

    def isGreaterThan3M(self,filename):
        filesize = os.path.getsize(filename)
        if(filesize >= 3145728):
            return 1
        else:
            return 0

    '''
    @function: judgeRule
    @brief: greater than 3M PE file check full text md5 and half text md5, other file check full text md5 only.
    @PE file equals white, other file not equals black, otherwise return 0.return BADNET means get safelevel
    @net timeout.
    @大于3M的PE文件全文和半文都查，其他只查全文,小于3M的PE文件查全文
    @PE文件属性必须为白，其他文件不为黑，否则返回失败
    @param: path, input file path
    @return: return 1 denote file Property is as expected, return 0 means not meeting expectations.
    '''
    def judgeRule(self,path):
        global fullmd5, halfmd5
        fullmd5 = self.getMD5('1',path)
        halfmd5 = self.getMD5('2',path)
        if((not cmp(halfmd5, 'failed')) and  (self.isGreaterThan3M(path) == 1)):
            fullSafeLevel = self.getSafelevel(fullmd5)
            halfSafeLevel = self.getSafelevel(halfmd5)
            if((fullSafeLevel == white) and (halfSafeLevel == white)):
                return 1
            else:
                return 0
        elif((not cmp(halfmd5, 'failed')) and  (self.isGreaterThan3M(path) == 0)):
            fullSafeLevel = self.getSafelevel(fullmd5)
            if(fullSafeLevel == white):
                return 1
            else:
                return 0
        else:
            fullSafeLevel = self.getSafelevel(fullmd5)
            if( fullSafeLevel == '-1'):
                return BADNET
            elif(not (fullSafeLevel == black)):
                return 1
            else:
                return 0
    def traverseDir(self,rootpath):
        propertyDic = {}
        if(os.path.exists(rootpath) == 0):
            print 'please input a valid path'
            sys.exit(0)
        if(os.path.isdir(rootpath) == 1):
            for parent,dirnames,filenames in os.walk(rootpath):
                for filename in filenames:
                    list = os.path.join(parent,filename)
                    filePrope = self.judgeRule(list)
                    propertyDic.setdefault(list+'_'+fullmd5+'_'+halfmd5,filePrope)
        else:
            filePrope = self.judgeRule(rootpath)
            propertyDic.setdefault(rootpath+'_'+fullmd5+'_'+halfmd5,filePrope)
        return propertyDic


if __name__ == "__main__":
    fpath = r"D:\Program Files (x86)\Tencent\QQPCMgr\10.2.33367.501"
    #fpath = r"D:\Program Files (x86)\Tencent\QQPCMgr\10.2.33367.501\qmspeedupplugin\phonerocket\condition.xml"
    starttime = datetime.datetime.now()
    fa = FilePropertyScan(fpath)
    propertyDic = fa.traverseDir(fpath)
    print propertyDic
    print len(propertyDic)
    endtime = datetime.datetime.now()
    t = endtime - starttime
    print ' time'
    print starttime
    print endtime
    print t
