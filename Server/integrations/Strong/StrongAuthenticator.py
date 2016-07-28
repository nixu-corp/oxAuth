from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.jboss.seam.contexts import Context, Contexts
from datetime import datetime
from org.xdi.oxauth.service.net import HttpService
from javax.faces.context import FacesContext
from org.xdi.util import ArrayHelper, StringHelper
from org.xdi.oxauth.service import UserService, SessionStateService
from org.jboss.seam.security import Identity
from org.xdi.oxauth.model.common import User

from java.util import Arrays, UUID
from org.apache.http.entity import ContentType
from org.apache.http.util import EntityUtils

import xml.etree.ElementTree as ET

from java.nio.charset import Charset
from java.lang import Thread

import java
import hashlib
import string
import random
import re

from java.security.cert import CertificateFactory, X509Certificate
from java.io import FileInputStream
from sun.security.provider.certpath import OCSP
from java.net import URI
from java.lang import StringBuilder

try:
    import json
except ImportError:
    import simplejson as json

from javax.xml.crypto import KeySelector, KeySelectorException, KeySelectorResult
from javax.xml.crypto.dsig import XMLSignature, XMLSignatureFactory
from javax.xml.crypto.dsig.keyinfo import X509Data
from javax.xml.crypto.dsig.dom import DOMValidateContext

from javax.xml.parsers import DocumentBuilderFactory
  
from org.apache.commons.codec.binary import Base64InputStream
from java.io import ByteArrayInputStream

from org.bouncycastle.asn1 import ASN1InputStream
from org.bouncycastle.asn1.ocsp import OCSPResponse

from org.jboss.seam import Component
from org.xdi.oxauth.model.authorize import AuthorizeErrorResponseType
from org.jboss.seam.faces import FacesManager

from java.text import SimpleDateFormat
from java.util import Date, TimeZone

from org.jboss.seam.util import Base64
from java.security.spec import X509EncodedKeySpec
from java.security import KeyFactory
from java.security import Signature

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "StrongAuth. Initialization"
        print "StrongAuth. Initialized successfully"
        return True

    def destroy(self, configurationAttributes):
        print "StrongAuth. Destroy"
        print "StrongAuth. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
    
        context = Contexts.getEventContext()
        sessionContext = Contexts.getSessionContext()
        userService = UserService.instance()
        httpService = HttpService.instance()
        
        if (step == 1):
            print "StrongAuth. Authenticate for step 1"
            
            if requestParameters.get('tupas_op') != None:
                return self.handleTupasLogin(requestParameters, sessionContext, configurationAttributes, userService, context)
            elif requestParameters.get('digiid_op') != None:
                return self.handleDigiIDLogin(configurationAttributes, sessionContext)
            elif requestParameters.get('mobiilid_op') != None:
                return self.handleMobiilIDLogin(configurationAttributes, requestParameters, httpService, context, sessionContext)
            elif requestParameters.get('bankid_op') != None:
                return self.handleBankIDLogin(configurationAttributes, httpService, context, sessionContext, requestParameters)
            elif requestParameters.get('SRC') != None and requestParameters.get('TIME') and requestParameters.get('PERSON_CODE') != None:
                return self.handleIPasasLogin(requestParameters, sessionContext, configurationAttributes, userService, context)
            else:
                print "StrongAuth. Invalid authentication method requested."
                return False
                    
        elif (step == 2):
            print "StrongAuth. Authenticate for step 2"
            
            sessionAttributes = context.get("sessionAttributes")
            
            if sessionAttributes != None and sessionAttributes.containsKey("strongauth_tupas_user_id") and sessionAttributes.containsKey("strongauth_tupas_user_name") and sessionAttributes.get("strongauth_tupas_user_id") != None and sessionAttributes.get("strongauth_tupas_user_name") != None:
                return self.handleTupasAuth(sessionAttributes, userService, context)
            elif sessionContext.get('strongauth_digiid_serialNumber') != None:
                return self.handleDigiIDAuth(sessionContext, userService, context)
            elif sessionContext.get('strongauth_mobiilid_challengeID') != None:
                return self.handleMobiilIDAuth(configurationAttributes, context, httpService, userService, sessionContext)
            elif sessionContext.get('strongauth_bankid_auto_start_token') != None:
                return self.handleBankIDAuth(configurationAttributes, context, httpService, userService, sessionContext)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_ipasas_person_code") and sessionAttributes.get("strongauth_ipasas_person_code") != None:
                return self.handleIPasasAuth(sessionAttributes, userService, context)
            else:
                print "StrongAuth. Invalid authentication method requested."
                return False
        
        elif (step == 3):
            print "StrongAuth. Authenticate for step 3"
            
            sessionAttributes = context.get("sessionAttributes")
            
            approved = requestParameters.containsKey("loginForm:approveButton")
            
            if approved == False:
                sb = StringBuilder()
                redirect_uri = sessionAttributes.get("redirect_uri")
                sb.append(redirect_uri)
                if "?" in redirect_uri:
                    sb.append("&")
                else:
                    sb.append("?")
            
                errorResponseFactory = Component.getInstance("errorResponseFactory", True)
                sb.append(errorResponseFactory.getErrorAsQueryString(AuthorizeErrorResponseType.ACCESS_DENIED, sessionAttributes.get("state")))
            
                FacesManager.instance().redirectToExternalURL(sb.toString())
                return True
            
            if sessionAttributes != None and sessionAttributes.containsKey("strongauth_tupas_user_id") and sessionAttributes.containsKey("strongauth_tupas_user_name") and sessionAttributes.get("strongauth_tupas_user_id") != None and sessionAttributes.get("strongauth_tupas_user_name") != None:
                return self.handleTupasPostLogin(sessionAttributes, userService)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_digiid_serialNumber") and sessionAttributes.get("strongauth_digiid_serialNumber") != None:
                return self.handleDigiIDPostLogin(sessionAttributes, userService)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_mobiilid_userIDCode") and sessionAttributes.get("strongauth_mobiilid_userIDCode") != None:
                return self.handleMobiilIDPostLogin(sessionAttributes, userService)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_bankid_personalNumber") and sessionAttributes.get("strongauth_bankid_personalNumber") != None:
                return self.handleBankIDPostLogin(sessionAttributes, userService)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_ipasas_person_code") and sessionAttributes.get("strongauth_ipasas_person_code") != None:
                return self.handleIPasasPostLogin(sessionAttributes, userService)
            else:
                print "StrongAuth. Invalid authentication method requested."
                return False
                
        else:
            return False

    def handleBankIDPostLogin(self, sessionAttributes, userService):
        bankid_personalNumber = sessionAttributes.get("strongauth_bankid_personalNumber")
        bankid_surname = sessionAttributes.get("strongauth_bankid_surname")
        bankid_name = sessionAttributes.get("strongauth_bankid_name")
        bankid_givenName = sessionAttributes.get("strongauth_bankid_givenName")
        passed_step2 = StringHelper.isNotEmptyString(bankid_personalNumber)
        if (not passed_step2):
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", bankid_personalNumber)
        
        if (foundUser == None):
            print "StrongAuth. BankID Authenticate for step 3. There is no user in LDAP. Adding user to local LDAP"
            newUser = User()
            newUser.setAttribute("sn", bankid_surname)
            newUser.setAttribute("cn", bankid_name)
            if bankid_givenName != None:
                newUser.setAttribute("givenName", bankid_givenName)
            newUser.setAttribute("oxExternalUid", bankid_personalNumber)
            newUser.setAttribute("uid", UUID.randomUUID().toString())
            foundUser = userService.addUser(newUser, True)
            print "StrongAuth. BankID Authenticate for step 3. Added new user with UID", foundUser.getUserId()
            foundUserName = foundUser.getUserId()
            print "StrongAuth. BankID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. BankID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True
    
    def handleBankIDAuth(self, configurationAttributes, context, httpService, userService, sessionContext):
        print "StrongAuth. BankID Authenticate for step 2"
            
        configLocation = configurationAttributes.get("bankid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. BankID. Authenticate for step 2. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False
                            
        sessionAttributes = context.get("sessionAttributes")
        if (sessionAttributes == None) or not sessionAttributes.containsKey("strongauth_bankid_orderRef"):
            print "StrongAuth. BankID Authenticate for step 2. strongauth_bankid_orderRef is empty"
            return False
        
        bankid_orderRef = sessionAttributes.get("strongauth_bankid_orderRef")
        passed_step1 = StringHelper.isNotEmptyString(bankid_orderRef)
        if (not passed_step1):
            return False
            
        parameters = self.callCollect(httpService, configs['trustStorePath'], configs['trustStorePassword'], configs['keystorePath'], configs['keystorePassword'], bankid_orderRef, context, sessionContext, configs['bankidEndpoint'])
        if parameters == None:
            return False
 
        foundUser = userService.getUserByAttribute("oxExternalUid", parameters['personalNumber'])
            
        if (foundUser == None):
            print "StrongAuth. BankID. Authenticate for step 2. There is no user in LDAP."
            context.set("strongauth_bankid_surname", parameters['surname'])
            context.set("strongauth_bankid_name", parameters['name'])
            if (parameters['givenName'] != None):
                context.set("strongauth_bankid_givenName", parameters['givenName'])
            context.set('strongauth_bankid_personalNumber', parameters['personalNumber'])

            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. BankID Authenticate for step 2. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
                
            context.set("strongauth_count_login_steps", 2)
                
            return True
    
    def handleBankIDLogin(self, configurationAttributes, httpService, context, sessionContext, requestParameters):
        print "StrongAuth. BankID. Authenticate for step 1"
            
        configLocation = configurationAttributes.get("bankid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. BankID. Authenticate for step 1. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False
        
        personal_number = None
        personal_number_array = requestParameters.get("personal_number")
        if ArrayHelper.isEmpty(personal_number_array) == False:
            personal_number = personal_number_array[0]
        
        if personal_number == None:
            sessionContext.set('strongauth_bankid_show_iframe', 'true')
        else:
        
            if not re.match(r'^\d{12}$', personal_number):
                context.set("faultstring", 'bankid_error_INVALID_PERSONAL_NUMBER')
                return False
                
            sessionContext.set('strongauth_bankid_show_iframe', 'false')
        
        parameters = self.callAuthenticate(httpService, configs['trustStorePath'], configs['trustStorePassword'], configs['keystorePath'], configs['keystorePassword'], personal_number, context, configs['bankidEndpoint'])
        if (parameters == None):
            return False
            
        context.set('strongauth_bankid_orderRef', parameters['orderRef'])
            
        sessionContext.set("strongauth_bankid_auto_start_token", parameters['autoStartToken'])

        return True
    
    def handleMobiilIDPostLogin(self, sessionAttributes, userService):
        mobiilid_userIDCode = sessionAttributes.get("strongauth_mobiilid_userIDCode")
        mobiilid_userSurname = sessionAttributes.get("strongauth_mobiilid_userSurname")
        mobiilid_userGivenname = sessionAttributes.get("strongauth_mobiilid_userGivenname")
        passed_step2 = StringHelper.isNotEmptyString(mobiilid_userIDCode)
        if (not passed_step2):
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", mobiilid_userIDCode)
            
        if (foundUser == None):
            print "StrongAuth. MobiilID Authenticate for step 3. There is no user in LDAP. Adding user to local LDAP"
            newUser = User()
            newUser.setAttribute("sn", mobiilid_userSurname)
            if mobiilid_userGivenname != None:
                newUser.setAttribute("givenName", mobiilid_userGivenname)
                newUser.setAttribute("cn", mobiilid_userGivenname + ' ' + mobiilid_userSurname)
            else:
                newUser.setAttribute("cn", mobiilid_userSurname)
            newUser.setAttribute("oxExternalUid", mobiilid_userIDCode)
            newUser.setAttribute("uid", UUID.randomUUID().toString())
            foundUser = userService.addUser(newUser, True)
            print "StrongAuth. MobiilID Authenticate for step 3. Added new user with UID", foundUser.getUserId()
            foundUserName = foundUser.getUserId()
            print "StrongAuth. MobiilID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. MobiilID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True    
    
    def handleMobiilIDAuth(self, configurationAttributes, context, httpService, userService, sessionContext):
        print "StrongAuth. MobiilID. Authenticate for step 2"
            
        configLocation = configurationAttributes.get("mobiilid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. MobiilID. Authenticate for step 2. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False

        sessionAttributes = context.get("sessionAttributes")
        if (sessionAttributes == None) or not sessionAttributes.containsKey("strongauth_mobiilid_sessCode"):
            print "StrongAuth. MobiilID. Authenticate for step 2. mobiilid_sessCode is empty"
            return False
        
        mobiilid_sessCode = sessionAttributes.get("strongauth_mobiilid_sessCode")
        mobiilid_userIDCode = sessionAttributes.get("strongauth_mobiilid_userIDCode")
        mobiilid_userSurname = sessionAttributes.get("strongauth_mobiilid_userSurname")
        mobiilid_userGivenname = sessionAttributes.get("strongauth_mobiilid_userGivenname")
        passed_step1 = StringHelper.isNotEmptyString(mobiilid_sessCode)
        if (not passed_step1):
            return False
            
        status = self.callMobileAuthenticateStatus(httpService, mobiilid_sessCode, configs['trustStorePath'], configs['trustStorePassword'], context, sessionContext, configs['endpointUrl'])
        if status == False:
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", mobiilid_userIDCode)
            
        if (foundUser == None):
            print "StrongAuth. MobiilID. Authenticate for step 2. There is no user in LDAP."
            context.set("strongauth_mobiilid_userIDCode", mobiilid_userIDCode)
            context.set("strongauth_mobiilid_userSurname", mobiilid_userSurname)
            context.set("strongauth_mobiilid_userGivenname", mobiilid_userGivenname)

            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. MobiilID Authenticate for step 2. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
                
            context.set("strongauth_count_login_steps", 2)
                
            return True

    
    def handleMobiilIDLogin(self, configurationAttributes, requestParameters, httpService, context, sessionContext):
        
        configLocation = configurationAttributes.get("mobiilid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. MobiilID. Prepare for step 1. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False
                            
        phone_no_array = requestParameters.get("phone_no")
        if ArrayHelper.isEmpty(phone_no_array):
            print "StrongAuth. MobiilID. Authenticate for step 1. phone_no is empty"
            return False

        phone_no = phone_no_array[0]
            
        personal_number = None
        personal_number_array = requestParameters.get("personal_number")
        if ArrayHelper.isEmpty(personal_number_array) == False:
            personal_number = personal_number_array[0]
        
        mobiilid_lang = "ENG"
        if (sessionContext.get('org.jboss.seam.international.localeSelector') != None):
            lang_code = sessionContext.get('org.jboss.seam.international.localeSelector').getLanguage()
            if (lang_code == 'et'):
                mobiilid_lang = 'EST'
            elif (lang_code == 'ru'):
                mobiilid_lang = 'RUS'
            elif (lang_code == 'lt'):
                mobiilid_lang = 'LIT'

        parameters = self.callMobileAuthenticate(httpService, phone_no, personal_number, mobiilid_lang, configs['serviceName'], configs['trustStorePath'], configs['trustStorePassword'], context, configs['endpointUrl'])
        if parameters == None:
            return False
            
        context.set("strongauth_mobiilid_sessCode", parameters['sessCode'])
        context.set("strongauth_mobiilid_userIDCode", parameters['userIDCode'])
        context.set("strongauth_mobiilid_userSurname", parameters['userSurname'])
        context.set("strongauth_mobiilid_userGivenname", parameters['userGivenname'])

        sessionContext.set("strongauth_mobiilid_challengeID", parameters['challengeID'])
            
        return True
    
    def handleDigiIDPostLogin(self, sessionAttributes, userService):
    
        digiid_serialNumber = sessionAttributes.get("strongauth_digiid_serialNumber")
        digiid_surname = sessionAttributes.get("strongauth_digiid_surname")
        digiid_givenname = sessionAttributes.get("strongauth_digiid_givenname")
        passed_step2 = StringHelper.isNotEmptyString(digiid_serialNumber)
        if (not passed_step2):
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", digiid_serialNumber)
            
        if (foundUser == None):
            print "StrongAuth. DigiID Authenticate for step 3. There is no user in LDAP. Adding user to local LDAP"
            newUser = User()
            newUser.setAttribute("sn", digiid_surname)
            if digiid_givenname != None:
                newUser.setAttribute("givenName", digiid_givenname)
                newUser.setAttribute("cn", digiid_givenname + ' ' + digiid_surname)
            else:
                newUser.setAttribute("cn", digiid_surname)
            newUser.setAttribute("oxExternalUid", digiid_serialNumber)
            newUser.setAttribute("uid", UUID.randomUUID().toString())
            foundUser = userService.addUser(newUser, True)
            print "StrongAuth. DigiID Authenticate for step 3. Added new user with UID", foundUser.getUserId()
            foundUserName = foundUser.getUserId()
            print "StrongAuth. DigiID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. DigiID Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            return True
    
    def handleDigiIDAuth(self, sessionContext, userService, context):
        print "StrongAuth. DigiID. Authenticate for step 2"
            
        surname = sessionContext.get('strongauth_digiid_surname')
        givenname = sessionContext.get('strongauth_digiid_givenname')
        serialNumber = sessionContext.get('strongauth_digiid_serialNumber')
            
        foundUser = userService.getUserByAttribute("oxExternalUid", serialNumber)
            
        if (foundUser == None):
            print "StrongAuth. DigiID. Authenticate for step 2. There is no user in LDAP."

            context.set("strongauth_digiid_serialNumber", serialNumber)
            context.set("strongauth_digiid_surname", surname)
            context.set("strongauth_digiid_givenname", givenname)

            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. DigiID Authenticate for step 2. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
                
            context.set("strongauth_count_login_steps", 2)
                
            return True
       
    
    def handleDigiIDLogin(self, configurationAttributes, sessionContext):
        print "StrongAuth. DigiID. Authenticate for step 1"
            
        configLocation = configurationAttributes.get("digiid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. DigiID. Authenticate for step 1. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False
        
        sessionContext.set("digiid_login_enabled", "true")
        return True
    
    def handleTupasPostLogin(self, sessionAttributes, userService):
        
        tupasUserUid = sessionAttributes.get("strongauth_tupas_user_id")
        tupasUserName = sessionAttributes.get("strongauth_tupas_user_name")
        tupasGivenname = sessionAttributes.get("strongauth_tupas_givenname")
        tupasSurname = sessionAttributes.get("strongauth_tupas_surname")
        passed_step1 = StringHelper.isNotEmptyString(tupasUserUid)
        if (not passed_step1):
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", tupasUserUid)
            
        if (foundUser == None):
            print "StrongAuth. Tupas Authenticate for step 3. There is no user in LDAP. Adding user to local LDAP"
            newUser = User()
            newUser.setAttribute("sn", tupasSurname)
            newUser.setAttribute("givenName", tupasGivenname)
            newUser.setAttribute("cn", tupasUserName)
            newUser.setAttribute("oxExternalUid", tupasUserUid)
            newUser.setAttribute("uid", UUID.randomUUID().toString())
            foundUser = userService.addUser(newUser, True)
            print "StrongAuth. Tupas Authenticate for step 3. Added new user with UID", foundUser.getUserId()
            foundUserName = foundUser.getUserId()
            print "StrongAuth. Tupas Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            
            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. Tupas Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            
            return True

    def handleTupasAuth(self, sessionAttributes, userService, context):
        print "StrongAuth. Tupas. Authenticate for step 2"
            
        name = sessionAttributes.get('strongauth_tupas_user_name')
        givenname = sessionAttributes.get('strongauth_tupas_givenname')
        surname = sessionAttributes.get('strongauth_tupas_surname')
        userid = sessionAttributes.get('strongauth_tupas_user_id')
        
        foundUser = userService.getUserByAttribute("oxExternalUid", userid)
            
        if (foundUser == None):
            print "StrongAuth. Tupas. Authenticate for step 2. There is no user in LDAP."

            context.set("strongauth_tupas_user_name", name)
            context.set("strongauth_tupas_givenname", givenname)
            context.set("strongauth_tupas_surname", surname)
            context.set("strongauth_tupas_user_id", userid)

            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. Tupas. Authenticate for step 2. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
                
            context.set("strongauth_count_login_steps", 2)
                
            return True
            
    def handleTupasLogin(self, requestParameters, sessionContext, configurationAttributes, userService, context):
        
        tupas_op_array = requestParameters.get('tupas_op')
        if ArrayHelper.isEmpty(tupas_op_array) == False:
            tupas_op = tupas_op_array[0]
            if tupas_op != None and tupas_op == 'cancel':
                print "StrongAuth. Tupas. User canceled operation"
                context.set("faultstring", 'tupas_error_user_canceled')
                return False
            elif tupas_op != None and tupas_op == 'reject':
                print "StrongAuth. Tupas. Operation was rejected."
                context.set("faultstring", 'tupas_error_rejected')
                return False
            
        parameter_map = self.parseResponse(requestParameters)
            
        if parameter_map == None:
            return False
        
        verification_result = self.verifyResponse(parameter_map, sessionContext, configurationAttributes)
        if verification_result == False:
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", parameter_map['B02K_CUSTID'])
        if (foundUser == None):
            print "StrongAuth. Tupas. Authenticate for step 1. Failed to find user"
            context.set("strongauth_tupas_user_id", parameter_map['B02K_CUSTID'])
            context.set("strongauth_tupas_user_name", parameter_map['B02K_CUSTNAME'])
            
            print "StrongAuth. Tupas. Parameter values are %s" % (str(parameter_map))
            print "StrongAuth. Tupas. Name is %s" % (parameter_map['B02K_CUSTNAME'].encode('iso-8859-1'))
            
            bankid = parameter_map['B02K_TIMESTMP'][:3]
            
            givenname = parameter_map['B02K_CUSTNAME'][parameter_map['B02K_CUSTNAME'].rfind(' ')+1:]
            surname = parameter_map['B02K_CUSTNAME'][0:parameter_map['B02K_CUSTNAME'].rfind(' ')]
                
            context.set("strongauth_tupas_givenname", givenname)
            context.set("strongauth_tupas_surname", surname)
            print "StrongAuth. Tupas. Givenname %s, surname %s" % (givenname.encode('iso-8859-1'), surname.encode('iso-8859-1'))
            
            return True
            
        found_user_name = foundUser.getUserId()
        print "StrongAuth. Tupas. Authenticate for step 1. found_user_name: " + found_user_name

        credentials = Identity.instance().getCredentials()
        credentials.setUsername(found_user_name)
        credentials.setUser(foundUser)

        print "StrongAuth. Tupas. Authenticate for step 1. Setting count steps to 1"
        context.set("strongauth_count_login_steps", 1)
                
        return True

    def handleIPasasPostLogin(self, sessionAttributes, userService):
        
        iPasasPersonCode = sessionAttributes.get("strongauth_ipasas_person_code")
        iPasasFirstName = sessionAttributes.get("strongauth_ipasas_first_name")
        iPasasLastName = sessionAttributes.get("strongauth_ipasas_last_name")
        passed_step1 = StringHelper.isNotEmptyString(iPasasPersonCode)
        if (not passed_step1):
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", iPasasPersonCode)
            
        if (foundUser == None):
            print "StrongAuth. iPasas Authenticate for step 3. There is no user in LDAP. Adding user to local LDAP"
            newUser = User()
            newUser.setAttribute("sn", iPasasLastName)
            if iPasasFirstName != None:
                newUser.setAttribute("givenName", iPasasFirstName)
                newUser.setAttribute("cn", iPasasFirstName + ' ' + iPasasLastName)
            else:
                newUser.setAttribute("cn", iPasasLastName)
            newUser.setAttribute("oxExternalUid", iPasasPersonCode)
            newUser.setAttribute("uid", UUID.randomUUID().toString())
            foundUser = userService.addUser(newUser, True)
            print "StrongAuth. iPasas Authenticate for step 3. Added new user with UID", foundUser.getUserId()
            foundUserName = foundUser.getUserId()
            print "StrongAuth. iPasas Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            
            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. iPasas Authenticate for step 3. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
            
            return True

    def handleIPasasAuth(self, sessionAttributes, userService, context):
        print "StrongAuth. iPasas. Authenticate for step 2"
            
        first_name = sessionAttributes.get('strongauth_ipasas_first_name')
        last_name = sessionAttributes.get('strongauth_ipasas_last_name')
        person_code = sessionAttributes.get('strongauth_ipasas_person_code')
        
        foundUser = userService.getUserByAttribute("oxExternalUid", person_code)
            
        if (foundUser == None):
            print "StrongAuth. iPasas. Authenticate for step 2. There is no user in LDAP."

            context.set("strongauth_ipasas_first_name", first_name)
            context.set("strongauth_ipasas_last_name", last_name)
            context.set("strongauth_ipasas_person_code", person_code)

            return True
                
        else:
            foundUserName = foundUser.getUserId()
            print "StrongAuth. iPasas. Authenticate for step 2. foundUserName:", foundUserName
            credentials = Identity.instance().getCredentials()
            credentials.setUsername(foundUserName)
            credentials.setUser(foundUser)
                
            context.set("strongauth_count_login_steps", 2)
                
            return True
            
    def handleIPasasLogin(self, requestParameters, sessionContext, configurationAttributes, userService, context):
        
        parameter_map = self.parseIPasasResponse(requestParameters)
            
        if parameter_map == None:
            return False
        
        verification_result = self.verifyIPasasResponse(parameter_map, sessionContext, configurationAttributes)
        if verification_result == False:
            return False
            
        foundUser = userService.getUserByAttribute("oxExternalUid", parameter_map['PERSON_CODE'])
        if (foundUser == None):
            print "StrongAuth. iPasas. Authenticate for step 1. Failed to find user"
            context.set("strongauth_ipasas_person_code", parameter_map['PERSON_CODE'])
            
            print "StrongAuth. iPasas. Parameter values are %s" % (str(parameter_map))
            
            first_name = parameter_map['PERSON_FNAME']
            last_name = parameter_map['PERSON_LNAME']
                
            context.set("strongauth_ipasas_first_name", first_name)
            context.set("strongauth_ipasas_last_name", last_name)
            
            return True
            
        found_user_name = foundUser.getUserId()
        print "StrongAuth. iPasas. Authenticate for step 1. found_user_name: " + found_user_name

        credentials = Identity.instance().getCredentials()
        credentials.setUsername(found_user_name)
        credentials.setUser(foundUser)

        print "StrongAuth. iPasas. Authenticate for step 1. Setting count steps to 1"
        context.set("strongauth_count_login_steps", 1)
                
        return True

    def prepareForStep1(self, context, sessionContext, httpService, configurationAttributes):
            print "StrongAuth. Prepare for step 1"
     
            context.set("ui_header", "theme." + context.get("ui_template") + ".login.header")
     
            tupas_configs = []
            #tupas_stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")[:-3]
            sdf = SimpleDateFormat("yyyyMMddHHmmssSSS")
            sdf.setTimeZone(TimeZone.getTimeZone("Europe/Helsinki"))
            tupas_stamp = sdf.format(Date()) 
            
            sessionContext.set("strongauth_tupas_stamp", tupas_stamp)
            
            request = FacesContext.getCurrentInstance().getExternalContext().getRequest()
            base_url = httpService.constructServerUrl(request)
            
            context.set("digiid_forward_url", base_url + "/strongauthlanding?digiid_op=true")
            context.set("mobiilid_forward_url", base_url + "/strongauthlanding?mobiilid_op=true")
            context.set("bankid_forward_url", base_url + "/strongauthlanding?bankid_op=true")
            
            iPasasConfiguration = None
            if (configurationAttributes.containsKey("ipasas_config_location")):
                iPasasConfigLocation = configurationAttributes.get("ipasas_config_location").getValue2()
                iPasasConfiguration = self.loadConfiguration(iPasasConfigLocation)
                context.set("ipasas_forward_url", iPasasConfiguration["ipasas_forward_url"])
            
            authentications_config = configurationAttributes.get("enabled_authentications").getValue2()
            authentications_config_json = json.loads(authentications_config)
            
            context.set("tupas_enabled", authentications_config_json['tupas'])
            context.set("digiid_enabled", authentications_config_json['digiid'])
            context.set("mobiilid_enabled", authentications_config_json['mobiilid'])
            context.set("bankid_enabled", authentications_config_json['bankid'])
            context.set("ipasas_enabled", authentications_config_json['ipasas'])
            
            tupasConfiguration = None
            if (configurationAttributes.containsKey("tupas_config_location")):
                tupasConfigLocation = configurationAttributes.get("tupas_config_location").getValue2()
                tupasConfiguration = self.loadConfiguration(tupasConfigLocation)
            else:
                return True
        
            for config in tupasConfiguration:
                bank_config = dict()
                bank_config["tupas_url"] = config['tupas_url']
                bank_config["tupas_action_id"] = config['tupas_action_id']
                bank_config["tupas_vers"] = config['tupas_vers']
                bank_config["tupas_rcvid"] = config['tupas_rcvid']

                tupas_lang = "EN"
                if (sessionContext.get('org.jboss.seam.international.localeSelector') != None):
                    lang_code = sessionContext.get('org.jboss.seam.international.localeSelector').getLanguage()
                    if (lang_code == 'fi'):
                        tupas_lang = 'FI'
                    elif (lang_code == 'sv'):
                        tupas_lang = 'SV'
                
                bank_config["tupas_langcode"] = tupas_lang
                # TODO: Fix timezone handling
                bank_config["tupas_stamp"] = tupas_stamp
                bank_config["tupas_idtype"] = config['tupas_idtype']
                bank_config["tupas_retlink"] = base_url + "/strongauthlanding?tupas_op=return"
                bank_config["tupas_canlink"] = base_url + "/strongauthlanding?tupas_op=cancel"
                bank_config["tupas_rejlink"] = base_url + "/strongauthlanding?tupas_op=reject"
                bank_config["tupas_keyvers"] = config['tupas_keyvers']
                bank_config["tupas_alg"] = config['tupas_alg']
                bank_config["tupas_logo"] = config['tupas_logo']
                bank_config["tupas_bankname"] = config['tupas_bankname']
                mac = bank_config['tupas_action_id'] + '&' + bank_config['tupas_vers'] + '&' + bank_config['tupas_rcvid'] + '&' + bank_config['tupas_langcode'] + '&' + bank_config['tupas_stamp'] + '&' + bank_config['tupas_idtype'] + '&' + bank_config['tupas_retlink'] + '&' + bank_config['tupas_canlink'] + '&' + bank_config['tupas_rejlink'] + '&' + bank_config['tupas_keyvers'] + '&' + bank_config['tupas_alg'] + '&' + config['tupas_rcvkey'] + '&'
                bank_config["tupas_mac"] = hashlib.sha256(mac.encode('utf-8')).hexdigest().upper()
                tupas_configs.append(bank_config)
            
            context.set("tupas_configs", tupas_configs)
            
            print "StrongAuth. Prepare for step 1. Returning True."
            return True
        
    def prepareForStep(self, configurationAttributes, requestParameters, step):
        
        print "StrongAuth. Preparing for step"
        context = Contexts.getEventContext()
        sessionContext = Contexts.getSessionContext()
        httpService = HttpService.instance();

        if (configurationAttributes.containsKey("ui_template")):
            context.set("ui_template", configurationAttributes.get("ui_template").getValue2())
        else:
            context.set("ui_template", "tilaajavastuu")
        
        if (step == 1):
            return self.prepareForStep1(context, sessionContext, httpService, configurationAttributes)
        elif (step == 2):
            print "StrongAuth. Prepare for step 2."

            context.set("ui_header", "theme." + context.get("ui_template") + ".auth.header")
            
            request = FacesContext.getCurrentInstance().getExternalContext().getRequest()
            return_url = httpService.constructServerUrl(request) + "/strongauthlanding"
            
            context.set("strongauth_forward_url", return_url)
            
            certs = request.getAttribute("javax.servlet.request.X509Certificate")
            if certs != None and len(certs) > 0:
                return self.prepareForDigiIDAuth(httpService, request, context, configurationAttributes, certs, sessionContext)
            elif sessionContext.get("digiid_login_enabled") == "true":
                print "StrongAuth. DigiID. No certificates found from request."
                context.set("faultstring", 'digiid_error_login_failed')
                sessionAttributes = context.get('sessionAttributes')
                sessionAttributes.put('auth_step', '1')
                sessionAttributes.remove('auth_step_passed_1')
                context.set('sessionAttributes', sessionAttributes)
                sessionContext.set('digiid_login_enabled', None)
                        
                sessionStateService = SessionStateService.instance()
                sessionState = sessionStateService.getSessionState()
                sessionState.setSessionAttributes(sessionAttributes)
                sessionStateService.updateSessionState(sessionState, True, True)
                        
                print "StrongAuth. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                return self.prepareForStep1(context, sessionContext, httpService, configurationAttributes)

            mobiilid_challengeID = sessionContext.get("strongauth_mobiilid_challengeID")
            if mobiilid_challengeID != None:
                context.set("strongauth_mobiilid_challengeID", mobiilid_challengeID)
            
            bankid_auto_start_token = sessionContext.get("strongauth_bankid_auto_start_token")
            if bankid_auto_start_token != None:
                context.set("strongauth_bankid_auto_start_token", bankid_auto_start_token)
            
            return True
        elif (step == 3):
            print "StrongAuth. Prepare for step 2. Returning True."

            context.set("ui_header", "theme." + context.get("ui_template") + ".terms.header")
            context.set("theme_terms", context.get("ui_template") + "_terms")
            
            sessionAttributes = context.get("sessionAttributes")
            
            if sessionAttributes != None and sessionAttributes.containsKey("strongauth_tupas_user_id") and sessionAttributes.containsKey("strongauth_tupas_user_name") and sessionAttributes.get("strongauth_tupas_user_id") != None and sessionAttributes.get("strongauth_tupas_user_name") != None:
                context.set("strongauth_name", sessionAttributes.get("strongauth_tupas_user_name"))
                context.set("strongauth_personal_number", sessionAttributes.get("strongauth_tupas_user_id"))
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_digiid_serialNumber") and sessionAttributes.get("strongauth_digiid_serialNumber") != None:
                context.set("strongauth_name", sessionAttributes.get("strongauth_digiid_givenname") + " " + sessionAttributes.get("strongauth_digiid_surname"))
                context.set("strongauth_personal_number", sessionAttributes.get("strongauth_digiid_serialNumber"))
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_mobiilid_userIDCode") and sessionAttributes.get("strongauth_mobiilid_userIDCode") != None:
                mobiilid_userIDCode = sessionAttributes.get("strongauth_mobiilid_userIDCode")
                mobiilid_userSurname = sessionAttributes.get("strongauth_mobiilid_userSurname")
                mobiilid_userGivenname = sessionAttributes.get("strongauth_mobiilid_userGivenname")
                context.set("strongauth_name", mobiilid_userGivenname + " " + mobiilid_userSurname)
                context.set("strongauth_personal_number", mobiilid_userIDCode)
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_bankid_personalNumber") and sessionAttributes.get("strongauth_bankid_personalNumber") != None:
                context.set("strongauth_name", sessionAttributes.get("strongauth_bankid_name"))
                context.set("strongauth_personal_number", sessionAttributes.get("strongauth_bankid_personalNumber"))
            elif sessionAttributes != None and sessionAttributes.containsKey("strongauth_ipasas_person_code") and sessionAttributes.get("strongauth_ipasas_person_code") != None:
                context.set("strongauth_name", sessionAttributes.get("strongauth_ipasas_first_name") + " " + sessionAttributes.get("strongauth_ipasas_last_name"))
                context.set("strongauth_personal_number", sessionAttributes.get("strongauth_ipasas_person_code"))
            else:
                print "StrongAuth. Invalid authentication method requested."
                return False
                
            return True
        else:
            return False

    def prepareForDigiIDAuth(self, httpService, request, context, configurationAttributes, certs, sessionContext):
        
        configLocation = configurationAttributes.get("digiid_config_location").getValue2()
        if (configLocation == None):
            print "StrongAuth. DigiID. Prepare for step 2. No configuration location set."
            return False

        configs = self.loadConfiguration(configLocation)
        if (configs == None):
            return False

        certificateFactory = CertificateFactory.getInstance("X.509")
        issuerCertificate = certificateFactory.generateCertificate(FileInputStream(configs['issuerCertificatePath']))
        responderCertificate = certificateFactory.generateCertificate(FileInputStream(configs["responderCertificatePath"]))
                
        status = OCSP.check(certs[0], issuerCertificate, URI(configs["responderURI"]), responderCertificate, None)
            
        if (status == None or status.getCertStatus().toString() != 'GOOD'):
            print "StrongAuth. DigiID. Prepare for step 2. Certificate status was not GOOD %s" % (status.getCertStatus())
            
        surname = None
        givenname = None
        serialNumber = None
            
        for ava in certs[0].getSubjectDN().allAvas():
            if ava.toString().encode('utf-8').startswith('SURNAME='):
                surname = ava.getValueString()
            elif ava.toString().encode('utf-8').startswith('GIVENNAME='):
                givenname = ava.getValueString()
            elif ava.toString().encode('utf-8').startswith('SERIALNUMBER='):
                serialNumber = ava.getValueString()

        if serialNumber == None:
            print "StrongAuth. DigiID. Prepare for step 2. No serialNumber found."
            return False

        sessionContext.set('strongauth_digiid_surname', surname)
        sessionContext.set('strongauth_digiid_givenname', givenname)
        sessionContext.set('strongauth_digiid_serialNumber', serialNumber)
                                    
        print "StrongAuth. DigiID. Prepare for step 2. Returning True."
        return True
            
    def getExtraParametersForStep(self, configurationAttributes, step):
    
        if (step == 2):
            return Arrays.asList("strongauth_tupas_user_id", "strongauth_tupas_user_name", "strongauth_tupas_givenname", "strongauth_tupas_surname", "strongauth_digiid_serialNumber", "strongauth_digiid_surname", "strongauth_digiid_givenname", "strongauth_mobiilid_sessCode", "strongauth_mobiilid_userIDCode", "strongauth_mobiilid_userSurname", "strongauth_mobiilid_userGivenname", "strongauth_bankid_orderRef", "strongauth_bankid_surname", "strongauth_bankid_name", "strongauth_bankid_givenName", "strongauth_bankid_personalNumber", "strongauth_ipasas_person_code", "strongauth_ipasas_first_name", "strongauth_ipasas_last_name")
        elif (step == 3):
            return Arrays.asList("strongauth_tupas_user_id", "strongauth_tupas_user_name", "strongauth_tupas_givenname", "strongauth_tupas_surname", "strongauth_digiid_serialNumber", "strongauth_digiid_surname", "strongauth_digiid_givenname", "strongauth_mobiilid_sessCode", "strongauth_mobiilid_userIDCode", "strongauth_mobiilid_userSurname", "strongauth_mobiilid_userGivenname", "strongauth_bankid_surname", "strongauth_bankid_name", "strongauth_bankid_givenName", "strongauth_bankid_personalNumber", "strongauth_ipasas_person_code", "strongauth_ipasas_first_name", "strongauth_ipasas_last_name")
    
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        context = Contexts.getEventContext()
        if (context.isSet("strongauth_count_login_steps")):
            return context.get("strongauth_count_login_steps")        
        return 3

    def getPageForStep(self, configurationAttributes, step):
        if (step == 1):
            print "StrongAuth. Returning page for step 1."
            return "/auth/strongauth/strongauthlogin.xhtml"
        elif (step == 2):
            print "StrongAuth. Returning page for step 2."
            sessionContext = Contexts.getSessionContext()
            if sessionContext.get("digiid_login_enabled") != None:
                return "/auth/strongauth/strongauthauth.xhtml"
            else:
                return "/auth/strongauth/strongauthpass.xhtml"
        elif (step == 3):
            print "StrongAuth. Returning page for step 3."
            return "/auth/strongauth/strongauthpostlogin.xhtml"       
        else:
            print "StrongAuth. Invalid page requested."
            return None

    def logout(self, configurationAttributes, requestParameters):
        return True

    def parseIPasasResponse(self, requestParameters):
    
        response_map = dict()
        parameters = ['SRC', 'TIME', 'PERSON_CODE', 'PERSON_FNAME', 'PERSON_LNAME', 'SIGNATURE', 'TYPE']
        for param in parameters:
            param_array = requestParameters.get(param)
            if ArrayHelper.isEmpty(param_array):
                print "StrongAuth. iPasas. Authenticate for step 1. %s is empty." % param
                return None
            param_val = param_array[0]
            if StringHelper.isEmpty(param_val):
                print "StrongAuth. iPasas. Authenticate for step 1. %s value is empty." % param
                return None
            response_map[param] = param_val
            
        return response_map
        
    def parseResponse(self, requestParameters):
    
        response_map = dict()
        parameters = ['tupas_op', 'B02K_VERS', 'B02K_TIMESTMP', 'B02K_IDNBR', 'B02K_STAMP', 'B02K_CUSTNAME', 'B02K_KEYVERS', 'B02K_ALG', 'B02K_CUSTID', 'B02K_CUSTTYPE', 'B02K_MAC']
        for param in parameters:
            param_array = requestParameters.get(param)
            if ArrayHelper.isEmpty(param_array):
                print "StrongAuth. Tupas. Authenticate for step 1. %s is empty." % param
                return None
            param_val = param_array[0]
            if StringHelper.isEmpty(param_val):
                print "StrongAuth. Tupas. Authenticate for step 1. %s is empty." % param
                return None
            response_map[param] = param_val
            
        return response_map
    
    def verifyIPasasResponse(self, parameter_map, sessionContext, configurationAttributes):
    
        iPasasConfiguration = None
        if (configurationAttributes.containsKey("ipasas_config_location")):
            iPasasConfigLocation = configurationAttributes.get("ipasas_config_location").getValue2()
            iPasasConfiguration = self.loadConfiguration(iPasasConfigLocation)
        else:
            print "StrongAuth. iPasas. Authenticate for step 1. Failed to read ipasas_configuration."
            return False
        
        base_str = "%s%s%s%s%s" % (parameter_map['SRC'], parameter_map['TIME'], parameter_map['PERSON_CODE'], parameter_map['PERSON_FNAME'], parameter_map['PERSON_LNAME'])
        keyBytes = Base64.decode(iPasasConfiguration["ipasas_public_key"])
        spec = X509EncodedKeySpec(keyBytes)
        kf = KeyFactory.getInstance("RSA")
        pubKey = kf.generatePublic(spec)
        sig = Signature.getInstance("SHA1withRSA")
        sig.initVerify(pubKey)
        sig.update(bytes(base_str.encode('utf-8')))
        
        sig_verified = sig.verify(Base64.decode(parameter_map['SIGNATURE']))
        print "StrongAuth. iPasas. Signature verification result %s" % (str(sig_verified))
        if sig_verified == False:
            return False

        sdf = SimpleDateFormat("yyyy'.'MM'.'dd' 'HH':'mm':'ss")
        sdf.setTimeZone(TimeZone.getTimeZone("Europe/Vilnius"))
        timestamp = sdf.parse(parameter_map['TIME']).getTime()
        timestamp_now = Date().getTime()
        time_difference = timestamp_now - timestamp
        print ('Time difference: ' + str(time_difference) + ' milliseconds')
        if time_difference > 60000:
            print "StrongAuth. iPasas. Authenticate for step 1. Invalid Timestamp difference received. Expecting below %s seconds, got %s seconds." % ('60', str(time_difference.seconds))
            return False
            
        return True
    
    def verifyResponse(self, parameter_map, sessionContext, configurationAttributes):
    
        tupasConfiguration = None
        if (configurationAttributes.containsKey("tupas_config_location")):
            tupasConfigLocation = configurationAttributes.get("tupas_config_location").getValue2()
            tupasConfiguration = self.loadConfiguration(tupasConfigLocation)
        else:
            print "StrongAuth. Tupas. Authenticate for step 1. Failed to read tupas_configuration."
            return False

        bankid = parameter_map['B02K_TIMESTMP'][:3]
        
        bankConfiguration = None
        for config in tupasConfiguration:
            if config['tupas_bankid'] == bankid:
                bankConfiguration = config
                break

        if bankConfiguration == None:
            print "StrongAuth. Tupas. Authenticate for step 1. Failed to find bank configuration for %s" % bankid
                
        if bankConfiguration['tupas_vers'] != parameter_map['B02K_VERS']:
            print "StrongAuth. Tupas. Authenticate for step 1. Invalid TUPAS version received. Expecting %s, got %s." % (bankConfiguration['tupas_vers'], parameter_map['B02K_VERS'])
            return False
            
        sdf = SimpleDateFormat("yyyyMMddHHmmssSSS")
        sdf.setTimeZone(TimeZone.getTimeZone("Europe/Helsinki"))
        timestamp = sdf.parse(parameter_map['B02K_TIMESTMP'][3:20]).getTime()
        timestamp_now = Date().getTime()
        time_difference = timestamp_now - timestamp
        #timestamp = datetime.strptime(parameter_map['B02K_TIMESTMP'][3:], "%Y%m%d%H%M%S%f")
        #timestamp_now = datetime.utcnow()
        #time_difference = timestamp_now - timestamp
        print ('Time difference: ' + str(time_difference) + ' milliseconds')
        if time_difference > 60000:
            print "Tupas. Authenticate for step 1. Invalid Timestamp difference received. Expecting below %s seconds, got %s seconds." % ('60', str(time_difference.seconds))
            return False
        
        tupas_stamp = sessionContext.get("strongauth_tupas_stamp")
        if tupas_stamp == None:
            print "StrongAuth. Tupas. Authenticate for step 1. tupas_stamp not found from session."
            return False
            
        if tupas_stamp != parameter_map['B02K_STAMP']:
            print "StrongAuth. Tupas. Authenticate for step 1. Invalid TUPAS stamp received. Expecting %s, got %s." % (tupas_stamp, parameter_map['B02K_STAMP'])
            return False
            
        if bankConfiguration['tupas_keyvers'] != parameter_map['B02K_KEYVERS']:
            print "StrongAuth. Tupas. Authenticate for step 1. Invalid TUPAS key version received. Expecting %s, got %s." % (bankConfiguration['tupas_keyvers'], parameter_map['B02K_KEYVERS'])
            return False
            
        if bankConfiguration['tupas_alg'] != parameter_map['B02K_ALG']:
            print "StrongAuth. Tupas. Authenticate for step 1. Invalid TUPAS algorithm received. Expecting %s, got %s." % (bankConfiguration['tupas_alg'], parameter_map['B02K_ALG'])
            return False

        mac = unicode(parameter_map['B02K_VERS'] + '&' + parameter_map['B02K_TIMESTMP'] + '&' + parameter_map['B02K_IDNBR'] + '&' + parameter_map['B02K_STAMP'] + '&' + parameter_map['B02K_CUSTNAME'] + '&' + parameter_map['B02K_KEYVERS'] + '&' + parameter_map['B02K_ALG'] + '&' + parameter_map['B02K_CUSTID'] + '&' + parameter_map['B02K_CUSTTYPE'] + '&' + bankConfiguration['tupas_rcvkey'] + '&')
        
        expected_mac = hashlib.sha256(mac.encode('iso-8859-1')).hexdigest().upper()
        
        if expected_mac != parameter_map['B02K_MAC']:
            print "StrongAuth. Tupas. Authenticate for step 1. Invalid TUPAS mac received. Expecting %s, got %s." % (expected_mac, parameter_map['B02K_MAC'])
            return False
             
        return True
        
    def loadConfiguration(self, configPath):
        configs = None

        f = open(configPath, 'r')
        try:
            configs = json.loads(f.read())
        except:
            print "StrongAuth. Failed to load configurations from file:", configPath
            return None
        finally:
            f.close()
        
        return configs
        
    def callMobileAuthenticate(self, httpService, phoneNo, personalNumber, lang, serviceName, trustStorePath, trustStorePassword, context, endpointUrl):

        print 'StrongAuth. MobiilID. Sending Call to MobileAuthenticate'
    
        spChallenge = ''.join(random.choice(string.digits) for _ in range(20))
    
        personalNumberStr = '<IDCode xsi:type=\"xsd:string\" xsi:nil=\"true\"/>'
        if personalNumber != None:
            personalNumberStr = '<IDCode xsi:type=\"xsd:string\">%s</IDCode>' % (personalNumber)
    
        postData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Body><ns1:MobileAuthenticate soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\">%s<CountryCode xsi:type=\"xsd:string\" xsi:nil=\"true\"/><PhoneNo xsi:type=\"xsd:string\">%s</PhoneNo><Language xsi:type=\"xsd:string\">%s</Language><ServiceName xsi:type=\"xsd:string\">%s</ServiceName><MessageToDisplay xsi:type=\"xsd:string\"></MessageToDisplay><SPChallenge xsi:type=\"xsd:string\">%s</SPChallenge><MessagingMode xsi:type=\"xsd:string\">asynchClientServer</MessagingMode><AsyncConfiguration xsi:type=\"xsd:int\">0</AsyncConfiguration><ReturnCertData xsi:type=\"xsd:boolean\">true</ReturnCertData><ReturnRevocationData xsi:type=\"xsd:boolean\">true</ReturnRevocationData></ns1:MobileAuthenticate></soapenv:Body></soapenv:Envelope>" % (personalNumberStr, phoneNo, lang, serviceName, spChallenge)
        
        print 'StrongAuth. MobiilID. Sending Content to MobileAuthenticate ' + postData

        client = httpService.getHttpsClient("JKS", trustStorePath, trustStorePassword)
        response = httpService.executePost(client, endpointUrl, None, {}, postData, ContentType.TEXT_XML)
    
        status = response.getHttpResponse().getStatusLine().getStatusCode()
        print "StrongAuth. MobiilID. Received response for mobileAuthenticate call: ", status
        if status == 200:
            body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
            print "Received: " + body.encode('utf-8')
            doc = ET.fromstring(body.encode('utf-8'))

            if (len(doc) < 2 or len(doc[1]) == 0 or doc[1][0].find('Status') == None or doc[1][0].find('Status').text != 'OK'):
                print "StrongAuth. MobiilID. Status is not OK."
                if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('Status') != None):
                    print "Status is %s" % (doc[1][0].find('Status').text)
                return None
            
            sessCode = None
            if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('Sesscode') != None):
                sessCode = doc[1][0].find('Sesscode').text
            if StringHelper.isEmpty(sessCode):
                print "StrongAuth. MobiilID. Received empty sessCode from mobileAuthenticate call."
                return None
                
            challengeID = None
            if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('ChallengeID') != None):
                challengeID = doc[1][0].find('ChallengeID').text
            if StringHelper.isEmpty(challengeID):
                print "StrongAuth. MobiilID. Received empty challengeID from mobileAuthenticate call."
                return None

            userIDCode = None
            if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('UserIDCode') != None):
                userIDCode = doc[1][0].find('UserIDCode').text
            if StringHelper.isEmpty(challengeID):
                print "StrongAuth. MobiilID. Received empty userIDCode from mobileAuthenticate call."
                return None

            userSurname = None
            if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('UserSurname') != None):
                userSurname = doc[1][0].find('UserSurname').text
            if StringHelper.isEmpty(challengeID):
                print "StrongAuth. MobiilID. Received empty userSurname from mobileAuthenticate call."
                return None

            userGivenname = None
            if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('UserGivenname') != None):
                userGivenname = doc[1][0].find('UserGivenname').text
                
            return {'sessCode':sessCode, 'challengeID':challengeID, 'userIDCode':userIDCode, 'userSurname':userSurname, 'userGivenname':userGivenname}
            
        else:
            print "StrongAuth. MobiilID. MobileAuthenticate call failed."
            body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
            print "StrongAuth. Received: " + body.encode('utf-8')
            doc = ET.fromstring(body.encode('utf-8'))
            
            print "Doc len %s" % (len(doc))
            if (len(doc) > 1 and len(doc[1]) > 0 and len(doc[1][0]) > 0 and doc[1][0].find('faultstring') != None):
                faultString = doc[1][0].find('faultstring').text
                context.set("faultstring", 'mobiilid_error_' + faultString)
                print "StrongAuth. Fault string was %s" % faultString
            
            return None
 
    def callMobileAuthenticateStatus(self, httpService, sessCode, trustStorePath, trustStorePassword, context, sessionContext, endpointUrl):

        timeout = 60
        curTime = java.lang.System.currentTimeMillis()
        endTime = curTime + timeout * 1000
        while (endTime >= curTime):
            # TODO validate signature
            postData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><soapenv:Body><ns1:GetMobileAuthenticateStatus soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\"><Sesscode xsi:type=\"xsd:int\">%s</Sesscode><WaitSignature xsi:type=\"xsd:boolean\">false</WaitSignature></ns1:GetMobileAuthenticateStatus></soapenv:Body></soapenv:Envelope>" % (sessCode)
            client = httpService.getHttpsClient("JKS", trustStorePath, trustStorePassword)
            response = httpService.executePost(client, endpointUrl, None, {}, postData, ContentType.TEXT_XML)
    
            status = response.getHttpResponse().getStatusLine().getStatusCode()
            print "StrongAuth. MobiilID. Received response for MobileAuthenticateStatus call: ", status
            if status == 200:
                body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
                print "StrongAuth. Received: ", body.encode('utf-8')
                doc = ET.fromstring(body.encode('utf-8'))
            
                status = None
                if (len(doc) > 1 and len(doc[1]) > 0 and doc[1][0].find('Status') != None):
                    status = doc[1][0].find('Status').text
                if StringHelper.isEmpty(status) or status != 'USER_AUTHENTICATED':
                    if status == 'OUTSTANDING_TRANSACTION':
                        print "StrongAuth. MobiilID. Status is not USER_AUTHENTICATED %s. Waiting." % (status)
                    else:
                        print "StrongAuth. MobiilID. Status is not USER_AUTHENTICATED %s" % (status)
                        context.set("faultstring", 'mobiilid_error_' + status)
                        sessionAttributes = context.get('sessionAttributes')
                        sessionAttributes.put('auth_step', '1')
                        sessionAttributes.remove('auth_step_passed_1')
                        sessionAttributes.remove('strongauth_mobiilid_sessCode')
                        sessionAttributes.remove('strongauth_mobiilid_userIDCode')
                        sessionAttributes.remove('strongauth_mobiilid_userSurname')
                        sessionAttributes.remove('strongauth_mobiilid_userGivenname')
                        context.set('sessionAttributes', sessionAttributes)
                        sessionContext.set('strongauth_mobiilid_challengeID', None)
                        
                        sessionStateService = SessionStateService.instance()
                        sessionState = sessionStateService.getSessionState()
                        sessionState.setSessionAttributes(sessionAttributes)
                        sessionStateService.updateSessionState(sessionState, True, True)
                        
                        print "StrongAuth. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                        return False
                else:
                    return True
            
            else:
                print "StrongAuth. MobiilID. MobileAuthenticateStatus call failed."
                body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
                print "StrongAuth. Received: ", body.encode('utf-8')
                doc = ET.fromstring(body.encode('utf-8'))
                if (len(doc) > 1 and len(doc[1]) > 0 and len(doc[1][0]) > 0 and doc[1][0].find('faultstring') != None):
                    faultString = doc[1][0].find('faultstring').text
                    context.set("faultstring", 'mobiilid_error_' + faultString)
                    print "StrongAuth. Fault string was %s" % faultString
                sessionAttributes = context.get('sessionAttributes')
                sessionAttributes.put('auth_step', '1')
                sessionAttributes.remove('auth_step_passed_1')
                sessionAttributes.remove('strongauth_mobiilid_sessCode')
                sessionAttributes.remove('strongauth_mobiilid_userIDCode')
                sessionAttributes.remove('strongauth_mobiilid_userSurname')
                sessionAttributes.remove('strongauth_mobiilid_userGivenname')
                context.set('sessionAttributes', sessionAttributes)
                sessionContext.set('strongauth_mobiilid_challengeID', None)
                
                sessionStateService = SessionStateService.instance()
                sessionState = sessionStateService.getSessionState()
                sessionState.setSessionAttributes(sessionAttributes)
                sessionStateService.updateSessionState(sessionState, True, True)

                print "StrongAuth. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                return False

            Thread.sleep(5000)
            curTime = java.lang.System.currentTimeMillis()
        return False

    def callAuthenticate(self, httpService, trustStorePath, trustStorePassword, keystorePath, keystorePassword, personal_number, context, bankidEndpoint):
    
        personal_number_str = ''
        requirementAlternatives = ''
        if personal_number != None:
            personal_number_str = '<personalNumber>%s</personalNumber>' % (personal_number)
            requirementAlternatives = '<requirementAlternatives><requirement><condition><key>CertificatePolicies</key><value>1.2.752.78.1.5</value><value>1.2.3.4.25</value></condition></requirement></requirementAlternatives>'
    
        postData = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:rp=\"http://bankid.com/RpService/v4.0.0/types/\" xmlns:ts=\"http://bankid.com/RpService/v4.0.0/\"><SOAP-ENV:Header/><SOAP-ENV:Body><rp:AuthenticateRequest>%s%s</rp:AuthenticateRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>" % (personal_number_str, requirementAlternatives)
        print 'StrongAuth. BankID. Sending: %s' % (postData)
        client = httpService.getHttpsClient("JKS", trustStorePath, trustStorePassword, "JKS", keystorePath, keystorePassword)
        response = httpService.executePost(client, bankidEndpoint, None, {}, postData, ContentType.APPLICATION_XML)
    
        status = response.getHttpResponse().getStatusLine().getStatusCode()
        print "StrongAuth. BankID. Received response for authenticate call: ", status
        if status == 200:
            body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
            print "StrongAuth. Received: " + body
            doc = ET.fromstring(body)
            
            orderRef = None
            if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('orderRef') != None):
                orderRef = doc[0][0].find('orderRef').text
            if StringHelper.isEmpty(orderRef):
                print "StrongAuth. BankID. Received empty orderRef from authenticate call."
                return None
                
            autoStartToken = None
            if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('autoStartToken') != None):
                autoStartToken = doc[0][0].find('autoStartToken').text
            if StringHelper.isEmpty(autoStartToken):
                print "StrongAuth. BankID. Received empty autoStartToken from authenticate call."
                return None
            
            return {'orderRef':orderRef, 'autoStartToken':autoStartToken}
            
        else:
            print "StrongAuth. BankID. Authenticate call failed."
            body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
            print "StrongAuth. Received: " + body
            doc = ET.fromstring(body.encode('utf-8'))
            
            if (len(doc) > 0 and len(doc[0]) > 0 and len(doc[0][0]) > 0 and doc[0][0].find('faultstring') != None):
                faultstring = doc[0][0].find('faultstring').text
                context.set("faultstring", 'bankid_error_' + faultstring)
                print "StrongAuth. Fault string was %s" % faultstring            
            else:
                print "StrongAuth. No error information found"
            return None

    def callCollect(self, httpService, trustStorePath, trustStorePassword, keystorePath, keystorePassword, orderRef, context, sessionContext, bankidEndpoint):
    
        timeout = 60
        curTime = java.lang.System.currentTimeMillis()
        endTime = curTime + timeout * 1000
    
        while (endTime >= curTime):
            postData = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:rp=\"http://bankid.com/RpService/v4.0.0/types/\" xmlns:ts=\"http://bankid.com/RpService/v4.0.0/\"><SOAP-ENV:Header/><SOAP-ENV:Body><rp:orderRef>%s</rp:orderRef></SOAP-ENV:Body></SOAP-ENV:Envelope>" % (orderRef)
            client = httpService.getHttpsClient("JKS", trustStorePath, trustStorePassword, "JKS", keystorePath, keystorePassword)
            response = httpService.executePost(client, bankidEndpoint, None, {}, postData, ContentType.APPLICATION_XML)
    
            status = response.getHttpResponse().getStatusLine().getStatusCode()
            print "StrongAuth. BankID. Received response for collect call: ", status
            if status == 200:
                body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
                print "StrongAuth. Received: ", body.encode('utf-8')
                doc = ET.fromstring(body.encode('utf-8'))
            
                progressStatus = None
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('progressStatus') != None):
                    progressStatus = doc[0][0].find('progressStatus').text
                if StringHelper.isEmpty(progressStatus) or progressStatus != 'COMPLETE':
                    if progressStatus == 'OUTSTANDING_TRANSACTION' or progressStatus == 'NO_CLIENT' or progressStatus == 'STARTED' or progressStatus == 'USER_SIGN':
                        print "StrongAuth. BankID. Progress status is not complete %s" % (progressStatus)
                        Thread.sleep(2000)
                        curTime = java.lang.System.currentTimeMillis()
                        continue
                    else:
                        print "StrongAuth. BankID. Progress status is not complete %s" % (progressStatus)
                        context.set("faultstring", 'bankid_error_' + progressStatus)
                        sessionAttributes = context.get('sessionAttributes')
                        sessionAttributes.put('auth_step', '1')
                        sessionAttributes.remove('auth_step_passed_1')
                        sessionAttributes.remove('strongauth_bankid_orderRef')
                        sessionAttributes.remove('strongauth_bankid_surname')
                        sessionAttributes.remove('strongauth_bankid_name')
                        sessionAttributes.remove('strongauth_bankid_givenName')
                        sessionAttributes.remove('strongauth_bankid_personalNumber')
                        context.set('sessionAttributes', sessionAttributes)
                        sessionContext.set('strongauth_bankid_auto_start_token', None)
                        sessionContext.set('strongauth_bankid_show_iframe', None)
                        
                        sessionStateService = SessionStateService.instance()
                        sessionState = sessionStateService.getSessionState()
                        sessionState.setSessionAttributes(sessionAttributes)
                        sessionStateService.updateSessionState(sessionState, True, True)
                        
                        print "StrongAuth. BankID. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                        return None
            
                name = None
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('userInfo') != None and doc[0][0].find('userInfo').find('name') != None):
                    name = doc[0][0].find('userInfo').find('name').text
                if StringHelper.isEmpty(name):
                    print "StrongAuth. BankID. Received empty name from collect call."
                    Thread.sleep(2000)
                    curTime = java.lang.System.currentTimeMillis()
                    continue

                personalNumber = None
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('userInfo') != None and doc[0][0].find('userInfo').find('personalNumber') != None):
                    personalNumber = doc[0][0].find('userInfo').find('personalNumber').text
                if StringHelper.isEmpty(personalNumber):
                    print "StrongAuth. BankID. Received empty personalNumber from collect call."
                    Thread.sleep(2000)
                    curTime = java.lang.System.currentTimeMillis()
                    continue
                
                givenName = None
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('userInfo') != None and doc[0][0].find('userInfo').find('givenName') != None):
                    givenName = doc[0][0].find('userInfo').find('givenName').text
            
                surname = None
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('userInfo') != None and doc[0][0].find('userInfo').find('surname') != None):
                    surname = doc[0][0].find('userInfo').find('surname').text
                if StringHelper.isEmpty(surname):
                    surname = name
            
                signature_verified = False
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('signature') != None):
                    signature = doc[0][0].find('signature').text
                    signature_verified = self.validateSignature(signature)
                
                ocsp_verified = False
                if (len(doc) > 0 and len(doc[0]) > 0 and doc[0][0].find('ocspResponse') != None):
                    ocspResponse = doc[0][0].find('ocspResponse').text
                    ocsp_verified = self.validateOcspResponse(ocspResponse)
                
                if signature_verified == False or ocsp_verified == False:
                    print "StrongAuth. BankID. Signature or OCSP response verification failed."
                    context.set("faultstring", 'bankid_error_INVALID_SIGNATURE')
                    sessionAttributes = context.get('sessionAttributes')
                    sessionAttributes.put('auth_step', '1')
                    sessionAttributes.remove('auth_step_passed_1')
                    sessionAttributes.remove('strongauth_bankid_orderRef')
                    sessionAttributes.remove('strongauth_bankid_surname')
                    sessionAttributes.remove('strongauth_bankid_name')
                    sessionAttributes.remove('strongauth_bankid_givenName')
                    sessionAttributes.remove('strongauth_bankid_personalNumber')
                    context.set('sessionAttributes', sessionAttributes)
                    sessionContext.set('strongauth_bankid_auto_start_token', None)
                    sessionContext.set('strongauth_bankid_show_iframe', None)
                        
                    sessionStateService = SessionStateService.instance()
                    sessionState = sessionStateService.getSessionState()
                    sessionState.setSessionAttributes(sessionAttributes)
                    sessionStateService.updateSessionState(sessionState, True, True)
                        
                    print "StrongAuth. BankID. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                    return None

                return {'name':name, 'personalNumber':personalNumber, 'givenName':givenName, 'surname':surname}
            
            else:
                print "StrongAuth. BankID. Collect call failed."
                body = EntityUtils.toString(response.getHttpResponse().getEntity(), Charset.forName('UTF-8'))
                print "StrongAuth. BankID. Received: ", body.encode('utf-8')
                doc = ET.fromstring(body.encode('utf-8'))
                if (len(doc) > 0 and len(doc[0]) > 0 and len(doc[0][0]) > 0 and doc[0][0].find('faultstring') != None):
                    faultString = doc[0][0].find('faultstring').text
                    context.set("faultstring", 'bankid_error_' + faultString)
                    print "StrongAuth. Fault string was %s" % faultString
                sessionAttributes = context.get('sessionAttributes')
                sessionAttributes.put('auth_step', '1')
                sessionAttributes.remove('auth_step_passed_1')
                sessionAttributes.remove('strongauth_bankid_orderRef')
                sessionAttributes.remove('strongauth_bankid_surname')
                sessionAttributes.remove('strongauth_bankid_name')
                sessionAttributes.remove('strongauth_bankid_givenName')
                sessionAttributes.remove('strongauth_bankid_personalNumber')
                context.set('sessionAttributes', sessionAttributes)
                sessionContext.set('strongauth_bankid_auto_start_token', None)
                sessionContext.set('strongauth_bankid_show_iframe', None)

                sessionStateService = SessionStateService.instance()
                sessionState = sessionStateService.getSessionState()
                sessionState.setSessionAttributes(sessionAttributes)
                sessionStateService.updateSessionState(sessionState, True, True)

                print "StrongAuth. BankID. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
                return None

        print "StrongAuth. BankID. Collect call failed."
        context.set("faultstring", 'bankid_error_EXPIRED_TRANSACTION')
        sessionAttributes = context.get('sessionAttributes')
        sessionAttributes.put('auth_step', '1')
        sessionAttributes.remove('auth_step_passed_1')
        sessionAttributes.remove('strongauth_bankid_orderRef')
        sessionAttributes.remove('strongauth_bankid_surname')
        sessionAttributes.remove('strongauth_bankid_name')
        sessionAttributes.remove('strongauth_bankid_givenName')
        sessionAttributes.remove('strongauth_bankid_personalNumber')
        context.set('sessionAttributes', sessionAttributes)
        sessionContext.set('strongauth_bankid_auto_start_token', None)
        sessionContext.set('strongauth_bankid_show_iframe', None)

        sessionStateService = SessionStateService.instance()
        sessionState = sessionStateService.getSessionState()
        sessionState.setSessionAttributes(sessionAttributes)
        sessionStateService.updateSessionState(sessionState, True, True)

        print "StrongAuth. BankID. Context is %s" % str(context.get('sessionAttributes').get('auth_step'))
            
        return None

    def validateOcspResponse(self, ocspResponse):
    
        aIn = ASN1InputStream(Base64InputStream(ByteArrayInputStream(bytes(ocspResponse))))
        resp = OCSPResponse.getInstance(aIn.readObject())
        
        return resp.getResponseStatus().getValue() == 0
    
        
    def validateSignature(self, signature):
    
        dbf = DocumentBuilderFactory.newInstance()
        dbf.setNamespaceAware(True)
        doc = dbf.newDocumentBuilder().parse(Base64InputStream(ByteArrayInputStream(bytes(signature))))
        nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature")
        if nl.getLength() == 0:
            print "StrongAuth. BankID. Cannot find Signature Element."
            return False
            
        fac = XMLSignatureFactory.getInstance("DOM")
        valContext = DOMValidateContext(X509KeySelector(), nl.item(0))
        
        m = doc.getElementsByTagName("bankIdSignedData")
        if m.getLength() > 0:
            n = m.item(0)
            idAttr = n.getAttributeNode("Id")
            n.setIdAttributeNode(idAttr, True)
    
        signature = fac.unmarshalXMLSignature(valContext)
        
        return signature.validate(valContext)

class SimpleKeySelectorResult(KeySelectorResult):
    def __init__(self, pk):
        self.pk = pk
        
    def getKey(self):
        return self.pk
        
class X509KeySelector(KeySelector):
        
    def select(self, keyInfo, purpose, method, context):
        ki = keyInfo.getContent().iterator()
        while ki.hasNext():
            info = ki.next()
            if not isinstance(info, X509Data):
                continue
            xi = info.getContent().iterator()
            while xi.hasNext():
                o = xi.next()
                if not isinstance(o, X509Certificate):
                    continue
                key = o.getPublicKey()
                if key.getAlgorithm() == "RSA" and method.getAlgorithm() == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                    return SimpleKeySelectorResult(key)
        
        raise KeySelectorException("StrongAuth. BankID. No key found for signature validation.")