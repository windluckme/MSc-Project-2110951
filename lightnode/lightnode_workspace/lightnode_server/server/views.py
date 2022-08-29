from django.http import JsonResponse
import json, os
import requests, base64
from . import web3Util, pkcs7Util, func

# Create your views here.
def applyid(request):
    """
    The light node accesses the interface to apply for an identity certificate
    This interface will create an Ethereum account and automatically write the obtained account address and password in user_ info. S in JSON file_ ACCOUNT_ Address and S_ ACCOUNT_ At password
    If you need to create a new SM2 key pair, you can https://const.net.cn/tool/sm2/genkey/ Create in, and then write user_ info. S in JSON file_ PRIVATE_ Key and S_ PUBLICATE_ Key

    Method:GET
    Params:(ip,password)
    """
    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP method error',"usage": 'GET', 'success': False})
    else:

        fullnode_ip = request.GET.get('ip') # Full node IP
        password = request.GET.get('password') # Password for new account

        if password == None or fullnode_ip == None:
            return JsonResponse({'msg':'Parameter error',"parameter": 'ip,password', 'success': False})

        user_info = func.get_user_info()

        #Create an Ethereum account
        new_account = web3Util.web3.eth.account.create()
        address = new_account.address

        with open(os.path.join(func.tests_root, 'keystore/' + new_account.address + '.keystore'), 'w+') as f:
            f.write(json.dumps(new_account.encrypt(password)))

        #Request identity certificate
        data = {
            'address':address,
            'pubkey':user_info['S_PUBLICATE_KEY'],
            'info':json.dumps(user_info['SUBJECT_NAME'])
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', 
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2', 
            'Accept-Encoding': 'gzip, deflate'
        }

        res = requests.post(url='http://'+fullnode_ip+':8000/issueid/',data=data, headers=headers).text
        if json.loads(res)['success'] == False:
            reason = json.loads(res)['msg']
            return JsonResponse({"msg": "Failed to apply for identity certificate", 'reason':reason, 'success': False})
        else:
            b64cert = json.loads(res)['cert']
            cert = base64.b64decode(b64cert)

            height = json.loads(res)['height']

            with open(os.path.join(func.tests_root, 'idcert/' + address + '.der'), 'wb+') as f:
                f.write(cert)
            with open(os.path.join(func.tests_root, 'idcert/height.txt'), 'w+') as f:
                f.write(str(height))

            #Save the account address and password into the JSON file
            with open(os.path.join(func.tests_root, 'userinfo/user_info.json'), 'r', encoding='utf-8') as f:
                js = json.load(f)

            js['S_ACCOUNT_ADDRESS'] = address
            js['S_ACCOUNT_PASSWORD'] = password

            with open(os.path.join(func.tests_root, 'userinfo/user_info.json'), 'w', encoding='utf-8') as f:
                json.dump(js, f, ensure_ascii=False)

            return JsonResponse({"msg": "Application for identity certificate succeeded", "address": address, 'success': True})


def applyau(request):
    """
    The light node accesses the interface to apply for an authorization certificate
    Method:GET
    Params:(fullnodeip,issuerip)
    """
    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP方法错误',"usage": 'GET', 'success': False})
    else:

        fullnode_ip = request.GET.get('fullnodeip') #Full node IP
        issuer_ip = request.GET.get('issuerip') #Authorizer IP

        if issuer_ip == None or fullnode_ip == None:
            return JsonResponse({'msg':'Parameter error',"Parameter": 'fullnodeip,issuerip', 'success': False})

        user_info = func.get_user_info()

        local_address = user_info['S_ACCOUNT_ADDRESS']

        with open(os.path.join(func.tests_root,'idcert/height.txt'), 'r') as f:
            height = f.read()

        data = {
            'fullnodeip':fullnode_ip,
            'address':local_address,
            'height':height,
            'pubkey':user_info['S_PUBLICATE_KEY'],
            'info':json.dumps(user_info['SUBJECT_NAME'])
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate'
        }

        res = requests.post(url='http://'+issuer_ip+':8000/issueau/',data=data, headers=headers).text
        # res = requests.post(url='http://'+issuer_ip+':8001/issueau/', data=data, headers=headers).text
        if json.loads(res)['success'] == False:
            reason = json.loads(res)['msg']
            return JsonResponse({"msg": "Failed to apply for authorization certificate", 'reason': reason, 'success': False})
        else:
            name = json.loads(res)['name']
            b64cert = json.loads(res)['cert']
            cert = base64.b64decode(b64cert)

            with open(os.path.join(func.tests_root,'aucert/' + name + '.der'), 'wb+') as f:
                f.write(cert)

            return JsonResponse({"msg": "Application for authorization certificate succeeded", 'name': name, 'success': True})


def issueau(request):
    """
    Issue authorization certificate to the authorized person
    Method:POST
    Params:(fullnodeip,address,height,pubkey,info)
    """
    if request.method != 'POST':
        return JsonResponse({'msg':'HTTP method error',"usage": 'POST', 'success': False})
    else:
        
        fullnode_ip = request.POST.get('fullnodeip') #Full node IP
        address = request.POST.get('address') #Account address of the authorized person
        height = request.POST.get('height') #Block height of the authorized person's identity certificate
        pubkey = request.POST.get('pubkey') #Authorized person's SM2 public key
        info = json.loads(request.POST.get('info')) #Individual information of the authorized person

        user_info = func.get_user_info()
        local_address = user_info['S_ACCOUNT_ADDRESS']

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate'
        }

        #Pass the account address and block height of the authorized person to the whole node to verify the identity of the authorized person
        res = requests.get(url='http://'+fullnode_ip+':8000/auth/?address='+address+'&height='+height, headers=headers).text
        auth_success = json.loads(res)['success']
        if auth_success == False:
            reason = json.loads(res)['msg']
            return JsonResponse({'msg':'被授权者身份验证失败：'+reason, 'success': False})
        else:
            
            #Create authorization certificate
            cert = pkcs7Util.issue_cert(pubkey, info, height, local_address, address)
            b64cert = base64.b64encode(cert)

            data = {
                'name': local_address+address,
                'cert': b64cert
            }

            #Send to full nodes, chain up the hash value of the certificate, and store the certificate in the database after encryption
            res = requests.post(url='http://'+fullnode_ip+':8000/issueau/', data=data, headers=headers).text

            if json.loads(res)['success']:
                return JsonResponse({'success':True, 'name':local_address+address, 'cert':b64cert.decode()})
            else:
                reason = json.loads(res)['msg']
                return JsonResponse({'success':False, 'msg': reason})


def applyrevoke(request):
    """
    The light node accesses the interface to revoke the certificate
    Method:GET
    Params:(ip, name,type)
    """
    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP方法错误',"usage": 'GET', 'success': False})
    else:

        fullnode_ip = request.GET.get('ip') #Full node IP
        cert_name = request.GET.get('name') #The name of the certificate to be revoked, the identity certificate is the account address, and the authorization certificate is the concatenated string of the account address of the authorizer and the authorized person
        cert_type = request.GET.get('type') #Certificate type, ID indicates identity certificate, Au indicates authorization certificate

        if cert_name == None or cert_type == None or fullnode_ip == None:
            return JsonResponse({'msg':'参数错误',"参数": 'ip,name,type', 'success': False})

        try:
            if cert_type == 'id':
                with open(os.path.join(func.tests_root, 'idcert/'+cert_name+'.der'), 'rb') as f:
                    cert = f.read()
            else:
                with open(os.path.join(func.tests_root, 'derfile/'+cert_name+'.der'), 'rb') as f:
                    cert = f.read()
        except Exception as e:
            print(e)
            return JsonResponse({"msg": "证书文件未找到", 'success': False})

        b64cert = base64.b64encode(cert)

        data = {
            'name':cert_name,
            'cert':b64cert,
            'type':cert_type
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate'
        }

        #Send the certificate name to all nodes and revoke the certificate
        res = requests.post(url='http://'+fullnode_ip+':8000/revoke/', data=data, headers=headers).text
        revoke_success = json.loads(res)['success']
        if revoke_success == False:
            reason = json.loads(res)['msg']
            return JsonResponse({'msg':'Certificate revocation failed', 'reason':reason, 'success': False})
        else:
            height = json.loads(res)['height']
            return JsonResponse({'msg':'Certificate revocation succeeded', 'height': height, 'success': True})


def applyinfo(request):
    """
    The light node accesses the interface to obtain the authorizer information
    Method:GET
    Params:(ip,address)
    """
    if request.method != 'GET':
        return JsonResponse({'msg':'HTTP method error',"usage": 'GET', 'success': False})
    else:

        fullnode_ip = request.GET.get('ip') #Full node IP
        address = request.GET.get('address') #Account address of the authorizer to view the information

        if address == None or fullnode_ip == None:
            return JsonResponse({'msg':'Parameter error',"parameter": 'ip,address', 'success': False})
        
        user_info = func.get_user_info()
        local_address = user_info['S_ACCOUNT_ADDRESS']

        #Obtain local identity certificate and authorization certificate
        try:
            with open(os.path.join(func.tests_root, 'idcert/'+local_address+'.der'), 'rb') as f:
                idcert = f.read()
            with open(os.path.join(func.tests_root, 'aucert/'+local_address+address+'.der'), 'rb') as f:
                aucert = f.read()
            with open(os.path.join(func.tests_root, 'idcert/height.txt'), 'r') as f:
                height = f.read()
        except Exception as e:
            print(e)
            return JsonResponse({"msg": "Local certificate acquisition failed", 'success': False})
        
        b64idcert = base64.b64encode(idcert)
        b64aucert = base64.b64encode(aucert)

        data = {
            'idcert':b64idcert,
            'aucert':b64aucert,
            'height':height
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate'
        }

        #Send identity certificate, authorization certificate and block height to all nodes to obtain information
        res = requests.post(url='http://'+fullnode_ip+':8000/queryinfo/', data=data, headers=headers).text
        revoke_success = json.loads(res)['success']
        if revoke_success == False:
            reason = json.loads(res)['msg']
            return JsonResponse({'msg':'getting information failure', 'reason':reason, 'success': False})
        else:
            return JsonResponse({'msg':'Information obtained successfully', 'success': True})

        home - api
        link - handle - gateways
        base - info
        help - admin
        link - snapshot
        link - dataquery
        link - control - record
        link - route