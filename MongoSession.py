'''
MongoSession 0.1
Copyright (c) 2015, Jason Steve Nguyen (conghauit@outlook.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this 
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this 
list of conditions and the following disclaimer in the documentation and/or other 
materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

'''


import hashlib
from uuid import uuid4
from datetime import datetime, timedelta

from flask.sessions import SessionInterface, SessionMixin
from flask import request
from werkzeug.datastructures import CallbackDict
from common.uncat import getRemoteIP



class MongoSession(CallbackDict, SessionMixin):
    def __init__(self, initial = None, on_update = None, sid=None):
        super().__init__(initial, on_update)
        self.sid = sid
        self.modified = False


class MongoSessionInterface(SessionInterface):    
    def __init__(self, DBClient, timeout=1):
        client  = DBClient
        self.store = client.db.Sess
        self.timeout = timeout

    def __checkSessIDValid(self, stored_session, remoteIP, remoteAgent):
        sessObj = MongoSession(initial=stored_session['data'],
                                sid=stored_session['_id'])
        if remoteIP!=sessObj.get('ip') or remoteAgent!=sessObj.get('agent'):
            return None

        if stored_session.get('expiration') \
                <= datetime.utcnow():
            return None

        return sessObj

    def open_session(self, app, request):
        remoteIP =  getRemoteIP()
        remoteAgent = request.headers['User-Agent']
        sid = request.cookies.get(app.session_cookie_name)
        sessObj = None

        if sid :
            stored_session = self.store.find_one({'_id': sid})
            if stored_session != None:
                sessObj = self.__checkSessIDValid(stored_session, remoteIP, remoteAgent)

        if sessObj != None:
            return sessObj

        preID = str( datetime.timestamp(datetime.now()) ) + ";" \
                + getRemoteIP() + ";" + request.headers['User-Agent']\
                + str(uuid4())
        hash = hashlib.md5(preID.encode())
        sid = hash.hexdigest()
        sessObj = MongoSession(sid=sid)
        sessObj['start'] = "ok"
        sessObj['ip'] = remoteIP 
        sessObj['agent'] = remoteAgent
        return sessObj

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if not session:
            response.delete_cookie(app.session_cookie_name, domain=domain)
            return
        if self.get_expiration_time(app, session):
            expiration = self.get_expiration_time(app, session)
        else:
            expiration = datetime.utcnow() + timedelta(hours=self.timeout)
        sess = self.store.find_one({'_id': session.sid})
        if sess==None :
            response.delete_cookie(app.session_cookie_name, domain=domain)
            self.store.insert(
                              {'_id': session.sid,
                               'data': session,
                               'expiration': expiration})
        else :
            self.store.update({'_id': session.sid},
                                { "$set": {
                               'data': session,
                               'expiration': expiration} })

        response.set_cookie(app.session_cookie_name, session.sid,
                            expires=self.get_expiration_time(app, session),
                            httponly=True, domain=domain)
