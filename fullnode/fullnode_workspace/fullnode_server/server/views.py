from django.http import JsonResponse
from . import web3Util, pkcs7Util
import os, base64, json
from . import func, sm2, models

# Create your views here.

def issueid(request):
    """
    Issue identity certificates to light nodes
    Method:POST
    Params:(address,pubkey)
    """
    if request.method != 'POST':
        return JsonResponse({'msg':'HTTP method error',"usage": 'POST', "success": False})
    else:
        
        address = request.POST.get('address') #Account address:
        pubkey = request.POST.get('pubkey') #SM2 public key
        info = json.loads(request.POST.get('info')) #Individual information

        ca_info = func.get_ca_info()
        ca_address = ca_info['CA_ACCOUNT_ADDRESS']
        ca_password = ca_info['CA_ACCOUNT_PASSWORD']
        height = web3Util.web3.eth.blockNumber + 1

        #Create identity certificate
        data = pkcs7Util.issue_cert(pubkey, info, height, ca_address, address)

        #Chain up the hash value of the identity certificate
        b64cert = base64.b64encode(data)
        
        hash = web3Util.Hashsc.functions.hash(b64cert).call()
        hash_str = hex(int.from_bytes(hash,'big'))

        try:
            tx = web3Util.Idca.functions.store(address, hash_str).buildTransaction( #Create transaction
                {
                    'from': ca_address,
                    'nonce': web3Util.web3.eth.getTransactionCount(ca_address),
                }
            )

            tx_create = web3Util.web3.eth.account.signTransaction(tx, web3Util.getPrivateKey_CA(ca_password)) #Sign the transaction with the account private key
            # tx_create = web3Util.web3.eth.account.signTransaction(tx, '406cf18cbd47212a1d1306d7652a64fe2ac1d450c1522a12cc392ab5fbe96f4d')
            
            tx_hash = web3Util.web3.eth.sendRawTransaction(tx_create.rawTransaction) #Send original transaction
            tx_receipt = web3Util.web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
            print(tx_receipt)
        except Exception as e:
            print(e)
            return JsonResponse({"msg": "Certificate on chain failed", 'success': False})
        
        #The identity certificate is encrypted and stored in the database
        sm2_obj = sm2.CryptSM2(public_key=ca_info['CA_PUBLICATE_KEY'])
        encdata = sm2_obj.encrypt(b64cert)
        b64_encdata = base64.b64encode(encdata).decode()

        new_cert = models.Cert()
        new_cert.hash = hash_str
        new_cert.data = b64_encdata
        new_cert.save()

        return JsonResponse({"cert": b64cert.decode(), "height": height, 'success': True})


def auth(request):
    """
    Verify the validity of the certificate
    Method:POST
    Params:(address,height)
    """
    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP method error',"usage": 'GET', 'success': False})
    else:

        address = request.GET.get('address') # Account address to verify identity certificate
        height = request.GET.get('height') # Block height to verify identity certificate

        ca_info = func.get_ca_info()

        # Query the hash value of the identity certificate on the chain
        try:
            hash = web3Util.Idca.functions.query(address).call() 
        except Exception as e:
            print(e)
            return JsonResponse({'msg': "Identity certificate query failed", 'success': False})
        
        #Get the certificate data from the database
        b64_encdata = models.Cert.objects.get(hash = hash).data
        encdata = base64.b64decode(b64_encdata)
        sm2_obj = sm2.CryptSM2(private_key=ca_info['CA_PRIVATE_KEY'])
        data = base64.b64decode(sm2_obj.decrypt(encdata))

        #View the valid values of certificates in the database
        success = pkcs7Util.is_vaild(data)

        print(success)

        return JsonResponse({'success':success})


def issueau(request):
    """
    Chain the hash value of the authorization certificate and store the encrypted certificate in the database
    Method:POST
    Params:(address,height)
    """
    if request.method != 'POST':
        return JsonResponse({'msg':'HTTP method error',"usage": 'POST', "success": False})
    else:

        name = request.POST.get('name') #Certificate name:
        b64cert = request.POST.get('cert').encode() #Authorization certificate

        ca_info = func.get_ca_info()
        ca_address = ca_info['CA_ACCOUNT_ADDRESS']
        ca_password = ca_info['CA_ACCOUNT_PASSWORD']

        #Authorization certificate hash value uplink
        hash = web3Util.Hashsc.functions.hash(b64cert).call()
        hash_str = hex(int.from_bytes(hash,'big'))

        try:
            tx = web3Util.Auca.functions.store(name, hash_str).buildTransaction( #Create transaction
                {
                    'from': ca_address,
                    'nonce': web3Util.web3.eth.getTransactionCount(ca_address),
                }
            )
            
            tx_create = web3Util.web3.eth.account.signTransaction(tx, web3Util.getPrivateKey_CA(ca_password)) #Sign the transaction with the account private key
            # tx_create = web3Util.web3.eth.account.sign_transaction(tx, '406cf18cbd47212a1d1306d7652a64fe2ac1d450c1522a12cc392ab5fbe96f4d')
            
            tx_hash = web3Util.web3.eth.sendRawTransaction(tx_create.rawTransaction) #Send original transaction
            tx_receipt = web3Util.web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
            print(tx_receipt)
        except Exception as e:
            print(e)
            return JsonResponse({"msg": "Certificate on chain failed", 'success': False})
        
        #The authorization certificate is encrypted and stored in the database
        sm2_obj = sm2.CryptSM2(public_key=ca_info['CA_PUBLICATE_KEY'])
        encdata = sm2_obj.encrypt(b64cert)
        b64_encdata = base64.b64encode(encdata).decode()

        new_cert = models.Cert()
        new_cert.hash = hash_str
        new_cert.data = b64_encdata
        new_cert.save()

        return JsonResponse({'success': True})


def revoke(request):
    """
    Revocation of certificate
    Method:POST
    Params:(name,cert,type)
    """
    if request.method != 'POST':
        return JsonResponse({'msg':'HTTP method error',"usage": 'POST', "success": False})
    else:

        cert_name = request.POST.get('name') #Certificate name:
        b64cert = request.POST.get('cert') #Certificate data
        cert_type = request.POST.get('type') #Certificate type:

        ca_info = func.get_ca_info()
        ca_address = ca_info['CA_ACCOUNT_ADDRESS']
        ca_password = ca_info['CA_ACCOUNT_PASSWORD']

        cert = base64.b64decode(b64cert)
        if not pkcs7Util.overdue(cert):
            return JsonResponse({'msg':'证书未过期', "success": False})
        else:
            new_cert = pkcs7Util.change_validity(cert)
            b64newcert = base64.b64encode(new_cert)

            #Chain the modified certificate
            hash = web3Util.Hashsc.functions.hash(b64newcert).call()
            hash_str = hex(int.from_bytes(hash,'big'))
            height = web3Util.web3.eth.blockNumber + 1

            try:
                if cert_type == 'id':
                    tx = web3Util.Idca.functions.revoke(cert_name, hash_str).buildTransaction( #Create transaction
                        {
                            'from': ca_address,
                            'nonce': web3Util.web3.eth.getTransactionCount(ca_address),
                        }
                    )
                else:
                    tx = web3Util.Auca.functions.revoke(cert_name, hash_str).buildTransaction(
                        {
                            'from': ca_address,
                            'nonce': web3Util.web3.eth.getTransactionCount(ca_address),
                        }
                    )
                
                tx_create = web3Util.web3.eth.account.signTransaction(tx, web3Util.getPrivateKey_CA(ca_password)) #Sign the transaction with the account private key
                # tx_create = web3Util.web3.eth.account.sign_transaction(tx, '406cf18cbd47212a1d1306d7652a64fe2ac1d450c1522a12cc392ab5fbe96f4d')
                
                tx_hash = web3Util.web3.eth.sendRawTransaction(tx_create.rawTransaction) #发送原始交易
                tx_receipt = web3Util.web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
                print(tx_receipt)
            except Exception as e:
                print(e)
                return JsonResponse({"msg": "Certificate uplink failed", 'success': False})
            
            #The modified certificate is encrypted and stored in the database
            sm2_obj = sm2.CryptSM2(public_key=ca_info['CA_PUBLICATE_KEY'])
            encdata = sm2_obj.encrypt(b64newcert)
            b64_encdata = base64.b64encode(encdata).decode()

            new_cert = models.Cert()
            new_cert.hash = hash_str
            new_cert.data = b64_encdata
            new_cert.save()

            return JsonResponse({'success': True, 'height': height})


def queryinfo(request):
    """
    Query information
    Method:POST
    Params:(idcert,aucert,height)
    """
    if request.method != 'POST':
        return JsonResponse({'msg':'HTTP method error',"usage": 'POST', "success": False})
    else:

        b64idcert = request.POST.get('idcert') #Identity certificate
        b64aucert = request.POST.get('aucert') #Authorization certificate
        height = request.POST.get('height') #block height

        idcert = base64.b64decode(b64idcert)
        aucert = base64.b64decode(b64aucert)

        ca_info = func.get_ca_info()

        #Verification of identity certificate
        if not pkcs7Util.verify(idcert):
            return JsonResponse({'msg':'Identity certificate verification failed', "success": False})
        
        #Verification of authorization certificate
        from_address, to_address = pkcs7Util.get_address(aucert)

        if pkcs7Util.get_address(idcert)[1] != to_address: #Determine whether the account corresponding to the identity certificate is authorized
            return JsonResponse({'msg':'Permission Denied', "success": False})

        try:
            hash = web3Util.Idca.functions.query(from_address.decode()).call()  #Get the hash value of the authorizer identity certificate
        except Exception as e:
            print(e)
            return JsonResponse({'msg': "Authorizer identity certificate query failed", 'success': False})
        
        b64_encdata = models.Cert.objects.get(hash = hash).data  #Obtain the identity certificate of the authorizer
        encdata = base64.b64decode(b64_encdata)
        sm2_obj = sm2.CryptSM2(private_key=ca_info['CA_PRIVATE_KEY'])
        issuer_idcert = base64.b64decode(sm2_obj.decrypt(encdata))

        if not pkcs7Util.verifyau(issuer_idcert, aucert):
            return JsonResponse({'msg':'Authorization certificate verification failed', "success": False})

        #Use blockchain to verify the validity of certificates
        idres = auth_cert(idcert, 'id')
        aures = auth_cert(aucert, 'au')
        if not idres[0]:
            return JsonResponse({'msg':'Authorization certificate verification failed：'+idres[1], "success": False})
        if not aures[0]:
            return JsonResponse({'msg':'Authorization certificate verification failed：'+aures[1], "success": False})

        return JsonResponse({'success':True})


def auth_cert(cert, type):

    b64cert = base64.b64encode(cert)

    #Calculate certificate hash value
    hash = web3Util.Hashsc.functions.hash(b64cert).call()
    hash_str = hex(int.from_bytes(hash,'big'))

    ca_info = func.get_ca_info()

    #Get the certificate hash value on the chain
    from_address,to_address = pkcs7Util.get_address(cert)

    try:
        if type == 'id':
            hash = web3Util.Idca.functions.query(to_address.decode()).call()
        else:
            hash = web3Util.Auca.functions.query((from_address+to_address).decode()).call()
    except Exception as e:
        print(e)
        return False,'Certificate query failed'
    
    if hash_str != hash:
        return False,'Certificate integrity verification failed'

    #Get the certificate data from the database
    b64_encdata = models.Cert.objects.get(hash = hash).data 
    encdata = base64.b64decode(b64_encdata)
    sm2_obj = sm2.CryptSM2(private_key=ca_info['CA_PRIVATE_KEY'])
    data = base64.b64decode(sm2_obj.decrypt(encdata))

    #View the valid values of certificates in the database
    if not pkcs7Util.is_vaild(data):
        return False,'证书已失效'
    else:
        return True,'证书验证成功'


def issue_cacert(request):
    """
    Used for initialization, issuing self signed CA certificates, chaining hash values, and storing encrypted data in the database
    """

    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP method error',"usage": 'GET', 'success': False})
    else:

        height = web3Util.web3.eth.blockNumber + 1

        cacert = pkcs7Util.ca_cert(height)
        ca_info = func.get_ca_info()

        #Chain up the hash value of the identity certificate
        b64cert = base64.b64encode(cacert)
        
        hash = web3Util.Hashsc.functions.hash(b64cert).call()
        hash_str = hex(int.from_bytes(hash,'big'))

        try:
            tx = web3Util.Idca.functions.store(ca_info['CA_ACCOUNT_ADDRESS'], hash_str).buildTransaction( #Create transaction
                {
                    'from': ca_info['CA_ACCOUNT_ADDRESS'],
                    'nonce': web3Util.web3.eth.getTransactionCount(ca_info['CA_ACCOUNT_ADDRESS']),
                }
            )

            tx_create = web3Util.web3.eth.account.signTransaction(tx, web3Util.getPrivateKey_CA(ca_info['CA_ACCOUNT_PASSWORD'])) #Sign the transaction with the account private key
            # tx_create = web3Util.web3.eth.account.signTransaction(tx, '406cf18cbd47212a1d1306d7652a64fe2ac1d450c1522a12cc392ab5fbe96f4d')
            
            tx_hash = web3Util.web3.eth.sendRawTransaction(tx_create.rawTransaction) #Send original transaction
            tx_receipt = web3Util.web3.eth.waitForTransactionReceipt(tx_hash, timeout=120)
            print(tx_receipt)
        except Exception as e:
            print(e)
            return JsonResponse({"msg": "Certificate on chain failed", 'success': False})
        
        #The identity certificate is encrypted and stored in the database
        sm2_obj = sm2.CryptSM2(public_key=ca_info['CA_PUBLICATE_KEY'])
        encdata = sm2_obj.encrypt(b64cert)
        b64_encdata = base64.b64encode(encdata).decode()

        new_cert = models.Cert()
        new_cert.hash = hash_str
        new_cert.data = b64_encdata
        new_cert.save()

        return JsonResponse({"msg": "CA certificate created successfully", "height": height, 'success': True})
