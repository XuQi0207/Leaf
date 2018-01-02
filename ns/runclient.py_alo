from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.simple_httpclient import SimpleAsyncHTTPClient
import tornado.ioloop
import tornado.web
import os,sys,re,time
from tornado import gen
from functools import partial
import urllib.parse
import mimetypes
import math
from concurrent.futures import ThreadPoolExecutor
import tornado.iostream
from tornado.escape import utf8
from tornado.log import gen_log
from ctypes import *
import struct
import logging
import subprocess

readchunky = False
total_downloaded = 0

DEBUG = False

logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='/usr/spool/ns/client_log',
                filemode='a+')

def geturlread(action,host,filepath,uid,gid,pos,size):
    if action=="read":
        url = "http://"+host+"/read?filepath="+filepath+"&uid="+uid+"&gid="+gid+"&pos="+str(pos)+"&size="+str(size)
        logging.debug(url) 
        return url

def sizebwchunky(chunk):
   global FILESIZE
   FILESIZE = int(chunk)

@gen.coroutine
def sizebw(host,filepath):
   url = "http://"+host+"/sizebw?filepath="+filepath
   logging.debug(url)
   request = HTTPRequest(url, streaming_callback=partial(sizebwchunky), request_timeout=300)
   AsyncHTTPClient.configure('tornado.simple_httpclient.SimpleAsyncHTTPClient', max_body_size=1024*1024*1024)
   http_client = AsyncHTTPClient(force_instance=True)
   response = yield http_client.fetch(request)
   tornado.ioloop.IOLoop.instance().stop()

@gen.coroutine
def writer(host,filepath,targetdir,uid,gid,pos,size):
   file_name = targetdir
   path = file_name
   chunk_size = 80*1024*1024
   no = int(size) // chunk_size
   i = 0
   global total_downloaded
   global readchunky
#   lib=cdll.LoadLibrary('./libpycall.so')
#   func=lib.update_bitmap
#   func.argtypes=(c_int,c_int,c_char_p,c_int)
   while i<no:
       request = HTTPRequest(geturlread("read",host,filepath,uid,gid,pos,str(chunk_size)),request_timeout=300)
       pos = str(int(pos)+chunk_size)
       i = i+1
       http_client = AsyncHTTPClient()
       response = yield http_client.fetch(request)
       response = response.body
       logging.debug("chunk length"+str(len(response)))
       f = open(path,'rb+')
       chunklength = len(response)-8
       posnew,chunknew = struct.unpack('l%ds'%chunklength,response)
       logging.debug("posnew is"+str(posnew)) 
       logging.debug("chunkleng"+str(len(chunknew)))
       logging.debug("filesize"+str(FILESIZE))
       f.seek(posnew)
       f.write(chunknew)
       total_downloaded=total_downloaded+len(chunknew)
       f.close()
#       func= lib.update_bitmap(int(posnew),int(len(chunknew)),filepath.encode("utf-8"),FILESIZE)
       logging.debug("total bytes downloaded was"+str(total_downloaded))

   if (int(size) % chunk_size) != 0:
       last = int(size) % chunk_size
       request = HTTPRequest(geturlread("read",host,filepath,uid,gid,pos,str(last)),request_timeout=300)
       http_client = AsyncHTTPClient()
       response = yield http_client.fetch(request)
       response = response.body
       f = open(path,'rb+')
       chunklength = len(response)-8
       posnew,chunknew = struct.unpack('l%ds'%chunklength,response)
       f.seek(posnew)
       f.write(chunknew)
       total_downloaded=total_downloaded+len(chunknew)
       f.close() 
#       func= lib.update_bitmap(int(posnew),int(len(chunknew)),filepath.encode("utf-8"),FILESIZE)
       logging.debug("total bytes downloaded was"+ str(total_downloaded))
   tornado.ioloop.IOLoop.instance().stop()

def readentrance(host,filepath,targetdir,uid,gid,pos,size):
    sizebw(host,filepath)	 
    tornado.ioloop.IOLoop.instance().start()
    filesize = FILESIZE
    start_time = time.time()
    global realsize
    if(int(size)>=filesize):
        realsize = filesize
    else:
        realsize = int(size)
    writer(host,filepath,targetdir,uid,gid,int(pos),realsize)
    tornado.ioloop.IOLoop.instance().start()
    end_time = time.time()
    logging.debug("Total time :{}"+format(end_time-start_time))
    logging.debug("-------2p.pid: "+str(os.getpid()))
    

if __name__=="__main__":
	logging.debug("pid: "+str(os.getpid()))
	readentrance(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6],sys.argv[7])
