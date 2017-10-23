from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.simple_httpclient import SimpleAsyncHTTPClient
import tornado.ioloop
import tornado.web
import os,sys,re,time
import threading
from tornado import gen
from functools import partial
import urllib.parse
import mimetypes
import math
from concurrent.futures import ThreadPoolExecutor
import tornado.iostream
from tornado.escape import utf8
from tornado.log import gen_log
import struct
import os
from ctypes import *

readchunky = False
total_downloaded = 0

DEBUG = False


def geturlread(action,host,filepath,uid,gid,pos,size):
    if action=="read":
        url = "http://"+host+"/read?filepath="+filepath+"&uid="+uid+"&gid="+gid+"&pos="+str(pos)+"&size="+str(size)
        print(url) 
        return url

def sizebwchunky(chunk):
   global FILESIZE
   FILESIZE = int(chunk)

@gen.coroutine
def sizebw(host,filepath):
   url = "http://"+host+"/sizebw?filepath="+filepath
   print(url)
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
       print("chunk length",len(response))
       f = open(path,'rb+')
       chunklength = len(response)-8
       posnew,chunknew = struct.unpack('l%ds'%chunklength,response)
       print("posnew is",posnew) 
       print("chunkleng",len(chunknew))
       print("filesize",FILESIZE)
       f.seek(posnew)
       f.write(chunknew)
       total_downloaded=total_downloaded+len(chunknew)
       f.close()
#       func= lib.update_bitmap(int(posnew),int(len(chunknew)),filepath.encode("utf-8"),FILESIZE)
       print ("finish")
       print("total bytes downloaded was", total_downloaded)
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
       print ("finish")
       print("total bytes downloaded was", total_downloaded)
   tornado.ioloop.IOLoop.instance().stop()


def readentrance(host,filepath,targetdir,uid,gid,pos,size):
    print(host,filepath,targetdir,uid,gid,pos,size)
    sizebw(host,filepath)	 
    tornado.ioloop.IOLoop.instance().start()
    filesize = FILESIZE
    streamno = 10
    start_time = time.time()
    global realsize
    if(int(size)>=filesize):
        realsize = filesize
        streamsize = (filesize-int(pos)) // (streamno-1)
    else:
        realsize = int(size)
        streamsize = (int(size)) // (streamno-1)
    i = 0
    threads = []
    while i < (streamno-1):
        threads.append(threading.Thread(target=writer,args=(host,filepath,targetdir,uid,gid,int(pos)+streamsize*i,streamsize)))
        i=i+1
    if (streamsize*i) < realsize:
        threads.append(threading.Thread(target=writer,args=(host,filepath,targetdir,uid,gid,int(pos)+streamsize*i,realsize-streamsize*i)))
    for t in threads:
        t.setDaemon(True)
        print("thread name is :",t.getName())
        t.start()
    tornado.ioloop.IOLoop.instance().start()
    for t in threads:
        t.join()
    end_time = time.time()
    print("Total time :{}".format(end_time-start_time))

if __name__=="__main__":
    readentrance("202.122.37.90:28001","/root/leaf/pytoc/upload/test.log","/dev/shm/test.log","0","0","0","104857600")

