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
import uuid
from concurrent.futures import ThreadPoolExecutor
import tornado.iostream
from tornado.escape import utf8
from tornado.log import gen_log
from ctypes import *
import struct
import struct
import os
#import time,datat

readchunky = False
total_downloaded = 0
threadpool = ThreadPoolExecutor(1)  # A thread for reading chunks from the file

DEBUG = False

class NoQueueTimeoutHTTPClient(SimpleAsyncHTTPClient):
    def fetch_impl(self, request, callback):
        key = object()

        self.queue.append((key, request, callback))
        self.waiting[key] = (request, callback, None)

        self._process_queue()

        if self.queue:
            gen_log.debug("max_clients limit reached, request queued. %d active, %d queued requests." % (len(self.active), len(self.queue)))


class Client:
    def _gen_boundary(self, file_size):
        if file_size < 1024:
            blen = 10
        else:
            blen = math.ceil(math.log(file_size, 2))
        bcnt = max(blen / 32, 1)
        return "".join([str(uuid.uuid1()).replace("-", "") for _ in range(bcnt)])
        print("_gen_boundary file_size",file_size)
    def put_stream(self, url, pos, size, filename, on_response, chunk_size=1024):
        '''Uploads file to provided url.
        :param url: URL to PUT the file data to
        :param filename: Name of the file (Content-Disposition header)
        :param file_size: Size of the file in bytes. Used to produce a Content-Size header from file_size.
        :param on_response: See AsyncHTTPClient.fetch
        :return: Future content value under the provided url as binary string.
        '''
        uploadpos = pos        
        #file_size = os.path.getsize(filename)  # Be aware: this could also block! In production, you need to do this in a separated thread too!
        file_size = size  # Be aware: this could also block! In production, you need to do this in a separated thread too!

        print("filesize in put_stream is :",file_size)
        ext = os.path.splitext(filename)[1].lower()
        if ext:
            content_type = mimetypes.types_map.get(ext, "application/octet-stream")
        else:
            content_type = "application/octet-stream"

        enc_filename = urllib.parse.quote(filename)
        # http://stackoverflow.com/questions/4526273/what-does-enctype-multipart-form-data-mean/28380690#28380690
        boundary = self._gen_boundary(file_size)
        CRLF = '\r\n'
        post_head = b''.join(map(utf8, [
            '--', boundary, CRLF,
            # See https://tools.ietf.org/html/rfc5987 section 3.2.2 examples
            'Content-Disposition: form-data; name="file"; filename*=utf-8\'\'%s' % enc_filename, CRLF,
            'Content-Type: ', content_type, CRLF,
            'Content-Transfer-Encoding: binary', CRLF,
            CRLF,
        ]))
        post_tail = b''.join(map(utf8, [
            CRLF, '--', boundary, '--', CRLF
        ]))
        content_length = len(post_head) + int(file_size) + len(post_tail)
        #print("content_length is:",content_length)
        headers = {
            'Content-Type': 'multipart/form-data; boundary=' + boundary,
            'Content-Transfer-Encoding': 'binary',
            'Content-Length': str(content_length),
        }

        @gen.coroutine
        def body_producer(write):
            if DEBUG:
                sys.stdout.write(post_head.decode('ascii'))
            write(post_head)
            remaining = file_size
            #print("remaining in body_produceris :",remaining)
            with open(filename, "rb") as fileobj:
                fileobj.seek(int(uploadpos))
                while remaining > 0:
                    #print("uploadpos in while is :",int(uploadpos))
                  #  data = yield threadpool.submit(fileobj.read(int(remaining)), chunk_size)
                    data = fileobj.read(int(remaining))
                 #   print(str(data,encoding = "utf-8"))
                    if data:
                        remaining -= len(data)
                        print("len(data) in if is :",len(data),"uploadpos in while is :",int(uploadpos),"remaining in if is :",len(data))
                        #print("data in if is :",data)
                        #print("remaining in if is :",len(data))
                        if DEBUG:
                            sys.stdout.write(data.decode('utf-8'))
                        yield write(data)
                    else:
                        break
            if DEBUG:
                sys.stdout.write(post_tail.decode('ascii'))
            write(post_tail)
        
        request = tornado.httpclient.HTTPRequest(url=url, request_timeout=1200, method='POST', headers=headers,body_producer=body_producer)
        print("before1:"+threading.current_thread().getName()+url)

        return tornado.httpclient.AsyncHTTPClient().fetch(request, callback=on_response)


def geturlread(action,host,filepath,uid,gid,pos,size):
    if action=="read":
        url = "http://"+host+"/read?filepath="+filepath+"&uid="+uid+"&gid="+gid+"&pos="+str(pos)+"&size="+str(size)
        print(url) 
        return url

def geturlupload(action,host,targetpath,pos,size,totalsize):
    if action=="upload":
        url = "http://"+host+"/upload?targetpath="+targetpath+"&pos="+str(pos)+"&size="+str(size)+"&totalsize="+str(totalsize)
        print(url) 
        return url

'''def chunky(path,pos,totalsize,chunk):
    #print("self._max_body_size",self._max_body_size)
    print("chunk length",len(chunk))
    global total_downloaded
    global readchunky
    if readchunky == False and os.path.exists(path):
        os.remove(path)
        readchunky = True
    if not os.path.exists(path):
        f = open(path,'w')
        f.close()
    f = open(path,'rb+')
    chunklength = len(chunk)-8
    pos,chunknew = struct.unpack('l%ds'%chunklength,chunk)
    print("decode pos is",pos) 
    f.seek(pos)
    f.write(chunknew)
    print("after write  position,chunksize",f.tell(),len(chunknew)) 
    pos = pos+len(chunknew)
    #f.flush()
    if pos==totalsize:
        f.close()
    total_downloaded += len(chunknew)'''
   # the OS blocks on file reads + writes -- beware how big the chunks is as it could effect things

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
   #AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
   #http_client = AsyncHTTPClient()
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
   #if readchunky == False and os.path.exists(path):
   #     os.remove(path)
   #     readchunky = True
   #if not os.path.exists(path):
   #     f = open(path,'w')
   #     f.close()
   while i<no:
       request = HTTPRequest(geturlread("read",host,filepath,uid,gid,pos,str(chunk_size)),request_timeout=300)
       pos = str(int(pos)+chunk_size)
       i = i+1
       http_client = AsyncHTTPClient()
       response = yield http_client.fetch(request)
       response = response.body
       print("chunk length",len(response))
       #print("chunk length",len(response))
       f = open(path,'rb+')
       chunklength = len(response)-8
       posnew,chunknew = struct.unpack('l%ds'%chunklength,response)
       #print("posnew is",posnew) 
       f.seek(posnew)
       f.write(chunknew)
       total_downloaded=total_downloaded+len(chunknew)
       #print("after write  position,chunksize",f.tell(),len(chunknew)) 
       f.close()
       print("total bytes downloaded was", total_downloaded)
   if (int(size) % chunk_size) != 0:
       last = int(size) % chunk_size
       request = HTTPRequest(geturlread("read",host,filepath,uid,gid,pos,str(last)),request_timeout=300)
       http_client = AsyncHTTPClient()
       response = yield http_client.fetch(request)
       response = response.body
       #print("chunk length",len(response))
       f = open(path,'rb+')
       chunklength = len(response)-8
       posnew,chunknew = struct.unpack('l%ds'%chunklength,response)
       #print("posnew is",posnew) 
       f.seek(posnew)
       f.write(chunknew)
       total_downloaded=total_downloaded+len(chunknew)
       #print("after write  position,chunksize",f.tell(),len(chunknew)) 
       f.close() 
       print("total bytes downloaded was", total_downloaded)
   if total_downloaded==realsize:
       tornado.ioloop.IOLoop.instance().stop()
   if total_downloaded==FILESIZE:
       tornado.ioloop.IOLoop.instance().stop()
'''   lib=cdll.LoadLibrary('./libpycall.so')
   lib=cdll.LoadLibrary('./libpycall.so')
   print("start")
   func=lib.update_bitmap
   func.argtypes=(c_int,c_int,c_char_p)
   func=lib.update_bitmap(int(pos),int(size),filepath.encode("utf-8"))
   print("finish")
'''
@gen.coroutine
def upload(host,filepath,targetpath,pos,size):
    def on_response(request):
        print("on_response:"+threading.current_thread().getName())

        print("=============== GOT RESPONSE ======")
        print(request.body.decode('ascii'))
        #print(request.body)
        print("===================================")
        tornado.ioloop.IOLoop.current().stop() # Stop the loop when the upload is complete.

    client = Client()
    print("before"+threading.current_thread().getName())
    #tornado.ioloop.IOLoop.instance().start()
    yield client.put_stream(geturlupload("upload",host,targetpath,pos,size,os.path.getsize(filepath)), pos, size, filepath, on_response)
    print("after:"+threading.current_thread().getName())
    #tornado.ioloop.IOLoop.current().stop() # Stop the loop when the upload is complete.



def readentrance(host,filepath,targetdir,uid,gid,pos,size):
    print(host,filepath,targetdir,uid,gid,pos,size)
    sizebw(host,filepath) 
    tornado.ioloop.IOLoop.instance().start()
    filesize = FILESIZE
    start_time = time.time()
    global realsize
    streamno = 10
    start_time = time.time()
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
        threads.append(threading.Thread(target=writer,args=(host,filepath,targetdir,uid,gid,streamsize*i,streamsize)))
        i=i+1
    if (streamsize*i) < filesize:
        threads.append(threading.Thread(target=writer,args=(host,filepath,targetdir,uid,gid,streamsize*i,filesize-streamsize*i)))
    for t in threads:
        t.setDaemon(True)
        print("thread name is :",t.getName())
        t.start()
    tornado.ioloop.IOLoop.instance().start()
    for t in threads:
        t.join()
    end_time = time.time()
    print("Total time :{}".format(end_time-start_time))

def uploadentrance(host,filepath,targetpath):
    streamno = 3
    start_time = time.time()
    filesize = os.path.getsize(filepath)
    streamsize = filesize // (streamno-1)
    i = 0
    threads = []
    while i < (streamno-1):
        threads.append(threading.Thread(target=upload,args=(host,filepath,targetpath,streamsize*i,streamsize)))
        i=i+1
    if (streamsize*i) < filesize:
        threads.append(threading.Thread(target=upload,args=(host,filepath,targetpath,streamsize*i,filesize-streamsize*i)))
    
    for t in threads:
        t.setDaemon(True)
        print("thread name is :",t.getName())
        t.start()
    tornado.ioloop.IOLoop.instance().start()
    #for t in threads:
    t.join()
    end_time = time.time()
    print("Total time :{}".format(end_time-start_time))
    #tornado.ioloop.IOLoop.current().stop() # Stop the loop when the upload is complete.

