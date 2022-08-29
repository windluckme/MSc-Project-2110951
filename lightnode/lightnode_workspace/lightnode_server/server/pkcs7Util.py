from asn1crypto import x509,util,keys,cms,core
from dateutil.relativedelta import relativedelta
from . import sm2,sm3,func
import datetime
import os,sys
import hashlib

au_validity = 5 #The validity period of the authorization certificate is 5 minutes, which is convenient for test revocation

def issue_cert(publickey, info, number, issueraddr, accepteraddr):
    #Tbscertificate certificate subject
    tbscert = x509.TbsCertificate()
    tbscert['version'] = 'v3'
    tbscert['serial_number'] = int(func.random_int(20))
    tbscert['signature'] = util.OrderedDict([('algorithm', '1.2.156.10197.1.501'),('parameters', None)])
    user_info = func.get_user_info()
    issuer = x509.Name().build(name_dict=user_info['SUBJECT_NAME'])
    subject = x509.Name().build(name_dict=info)
    tbscert['issuer'] = issuer
    tbscert['subject'] = subject
    not_before = x509.Time(name='utc_time', value=datetime.datetime.now(tz=datetime.timezone.utc))
    not_after = x509.Time(name='utc_time', value=datetime.datetime.now(tz=datetime.timezone.utc)+relativedelta(minutes=au_validity))
    validity = x509.Validity()
    validity['not_before'] = not_before
    validity['not_after'] = not_after
    tbscert['validity'] = validity

    #subjectPublicKeyInfo Public key information in the certificate body
    pubkey = x509.PublicKeyInfo()
    sm2_domain = keys.ECDomainParameters(name='named', value="1.2.156.10197.1.301")
    pubkey['algorithm'] = util.OrderedDict([('algorithm', '1.2.840.10045.2.1'), ('parameters', sm2_domain)])
    subject_pub_point = func.hex_to_point(publickey, 64)
    pub_bitstring = keys.ECPointBitString.from_coords(subject_pub_point[0], subject_pub_point[1])
    pubkey['public_key'] = pub_bitstring
    tbscert['subject_public_key_info'] = pubkey

    #extensions Extension information in the certificate body
    ext_ca = x509.Extension()
    ext_ca['extn_id'] = 'basic_constraints'
    ext_ca['extn_value'] = util.OrderedDict([('ca',False),('path_len_constraint',None)])
    ext_skid = x509.Extension()
    ext_skid['extn_id'] = 'key_identifier'
    pub_sha1 = hashlib.sha1(pub_bitstring.native).hexdigest() #Kid is the SHA1 value of the public key
    ext_skid['extn_value'] = int(pub_sha1,16).to_bytes(20,'big') #Hexadecimal string to bytecode
    ext_akid = x509.Extension()
    ext_akid['extn_id'] = 'authority_key_identifier'
    iss_pub_point = func.hex_to_point(user_info['S_PUBLICATE_KEY'], 64)
    iss_pub_bitstring = keys.ECPointBitString.from_coords(iss_pub_point[0], iss_pub_point[1])
    iss_pub_sha1 = hashlib.sha1(iss_pub_bitstring.native).hexdigest()  #Akid is the public key SHA1 value of the issuer
    ext_akid['extn_value'] = util.OrderedDict([('key_identifier', int(iss_pub_sha1,16).to_bytes(20,'big')),
                                            ('authority_cert_issuer', None),
                                            ('authority_cert_serial_number', None)])

    cert_type = x509.ExtensionId()
    cert_type._map['1.2.3.4.5.6.7.8.1'] = 'cert_type' #Certificate type. To add custom extension content, you need to set some non-existent oid numbers
    cert_type.set('1.2.3.4.5.6.7.8.1')
    ext_type = x509.Extension()
    ext_type['extn_id'] = cert_type
    ext_type['extn_value'] = b'authorization certificate'

    hash_algorithm = x509.ExtensionId()
    hash_algorithm._map['1.2.3.4.5.6.7.8.2'] = 'hash_algorithm' #Hash algorithm used in the uplink
    hash_algorithm.set('1.2.3.4.5.6.7.8.2')
    ext_hashalgo = x509.Extension()
    ext_hashalgo['extn_id'] = hash_algorithm
    ext_hashalgo['extn_value'] = b'keccak256'

    Vaild = x509.ExtensionId()
    Vaild._map['1.2.3.4.5.6.7.8.3'] = 'Vaild' #Is the certificate valid
    Vaild.set('1.2.3.4.5.6.7.8.3')
    ext_vaild = x509.Extension()
    ext_vaild['extn_id'] = Vaild
    ext_vaild['extn_value'] = b'True'

    blockchain_name = x509.ExtensionId()
    blockchain_name._map['1.2.3.4.5.6.7.8.4'] = 'blockchain_name' #Blockchain name
    blockchain_name.set('1.2.3.4.5.6.7.8.4')
    ext_blockchain = x509.Extension()
    ext_blockchain['extn_id'] = blockchain_name
    ext_blockchain['extn_value'] = b'test'

    block_height = x509.ExtensionId()
    block_height._map['1.2.3.4.5.6.7.8.5'] = 'block_height' #Block height
    block_height.set('1.2.3.4.5.6.7.8.5')
    ext_number = x509.Extension()
    ext_number._oid_specs['block_height'] = x509.Integer
    ext_number['extn_id'] = block_height
    ext_number['extn_value'] = int(number)

    access_scope = x509.ExtensionId()
    access_scope._map['1.2.3.4.5.6.7.8.6'] = 'access_scope' #Access scope:
    access_scope.set('1.2.3.4.5.6.7.8.6')
    ext_access = x509.Extension()
    ext_access['extn_id'] = access_scope
    ext_access['extn_value'] = b'test'

    issuer_address = x509.ExtensionId()
    issuer_address._map['1.2.3.4.5.6.7.8.7'] = 'issuer_address' #Issuer address
    issuer_address.set('1.2.3.4.5.6.7.8.7')
    ext_issuer = x509.Extension()
    ext_issuer['extn_id'] = issuer_address
    ext_issuer['extn_value'] = issueraddr.encode()

    accepter_address = x509.ExtensionId()
    accepter_address._map['1.2.3.4.5.6.7.8.8'] = 'accepter_address' #Recipient address
    accepter_address.set('1.2.3.4.5.6.7.8.8')
    ext_accepter = x509.Extension()
    ext_accepter['extn_id'] = accepter_address
    ext_accepter['extn_value'] = accepteraddr.encode()

    tbscert['extensions'] = [ext_ca, ext_skid, ext_akid, ext_type, ext_hashalgo, ext_vaild, 
        ext_blockchain, ext_number, ext_access, ext_issuer, ext_accepter]

    #certificate
    scert = x509.Certificate()
    scert['tbs_certificate'] = tbscert
    scert['signature_algorithm'] = util.OrderedDict([('algorithm', '1.2.156.10197.1.501'),('parameters', None)])

    #Calculate SM2 signature value
    tbs_serialized = tbscert.dump()
    sm3_digest = sm3.sm3_hash(func.bytes_to_list(tbs_serialized))

    sm2_obj = sm2.CryptSM2(public_key=user_info['S_PUBLICATE_KEY'], private_key=user_info['S_PRIVATE_KEY'])
    random_hex_str = func.random_hex(sm2_obj.para_len)
    sign = sm2_obj.sign(sm3_digest.encode(), random_hex_str)

    scert['signature_value'] = int(sign,16).to_bytes(64,'big')

    """
    构造pkcs7结构
    """

    #SignedData structure
    sd = cms.SignedData()
    sd['version'] = 'v1'
    sd['digest_algorithms'] = [util.OrderedDict([('algorithm', '1.2.156.10197.1.401'),('parameters', None)])]
    sm_data_type = cms.ContentType()
    sm_data_type._map['1.2.156.10197.6.1.4.2.1'] = 'data' #Add a mapping to the _map Dictionary of the ContentType object
    sm_data_type.set("1.2.156.10197.6.1.4.2.1") #Set the value of the ContentType object
    contentinfo = cms.ContentInfo()
    contentinfo['content_type'] = sm_data_type
    contentinfo['content'] = core.OctetString(accepteraddr.encode()) #The signature content is the account address of the authorized certificate recipient
    sd['encap_content_info'] = contentinfo

    sd['certificates'] = [scert]

    #Signer information
    signer_info = cms.SignerInfo()
    signer_info['version'] = 'v1'
    ias = cms.IssuerAndSerialNumber()
    ias['issuer'] = x509.Name().build(name_dict=user_info['SUBJECT_NAME'])
    ias['serial_number'] = scert['tbs_certificate']['serial_number'].native
    sid = cms.SignerIdentifier(name='issuer_and_serial_number', value=ias)
    signer_info['sid'] = sid
    signer_info['digest_algorithm'] = util.OrderedDict([('algorithm', '1.2.156.10197.1.401'),('parameters', None)])
    signer_info['signature_algorithm'] = util.OrderedDict([('algorithm', '1.2.156.10197.1.501'),('parameters', None)])

    #Signature properties
    attr1 = cms.CMSAttribute()
    attr1['type'] = 'content_type'
    attr1['values'] = ['1.2.156.10197.6.1.4.2.1']
    attr2 = cms.CMSAttribute()
    attr2['type'] = 'signing_time'
    timeins = core.UTCTime()
    timeins.set(datetime.datetime.now(tz=datetime.timezone.utc))
    attr2['values'] = [timeins]
    attr3 = cms.CMSAttribute()
    sm3_digest = sm3.sm3_hash(func.bytes_to_list(accepteraddr.encode()))
    sm3_digest_bytes = int(sm3_digest,16).to_bytes(32,'big')
    attr3['type'] = 'message_digest'
    attr3['values'] = [sm3_digest_bytes]
    signer_info['signed_attrs'] = [attr1, attr2, attr3]

    #Sign data
    sm2_obj = sm2.CryptSM2(private_key=user_info['S_PRIVATE_KEY']) #Sign with local SM2 private key
    random_hex_str = func.random_hex(sm2_obj.para_len)
    sign = sm2_obj.sign(sm3_digest_bytes, random_hex_str)

    signer_info['signature'] = int(sign,16).to_bytes(64,'big')
    sd['signer_infos'] = [signer_info]

    #PKCS7
    sm_signed_data_type = cms.ContentType()
    sm_signed_data_type._map['1.2.156.10197.6.1.4.2.2'] = 'signed_data'
    sm_signed_data_type.set("1.2.156.10197.6.1.4.2.2")
    pkcs7 = cms.ContentInfo()
    pkcs7['content_type'] = sm_signed_data_type
    pkcs7['content'] = sd

    with open(os.path.join(func.derfile_dir,issueraddr+accepteraddr+'.der'),'wb+') as f:
        f.write(pkcs7.dump())
    
    return pkcs7.dump()


def verify():

    #Get the CA public key, as well as the signature value of the CA certificate and the serialized value of tbs_certificate
    with open(os.path.join(func.derfile_dir, 'CAcert.der'),'rb') as inf:
        ca_cert = x509.Certificate.load(inf.read())
    ca_pubkey = ca_cert['tbs_certificate']['subject_public_key_info']['public_key'].to_coords()
    ca_pubkey_hex = func.point_to_hex(ca_pubkey)
    tbs_serialized_ca = ca_cert['tbs_certificate'].dump()
    ca_cert_sign = ca_cert['signature_value'].native
    ca_cert_sign_hex = hex(int.from_bytes(ca_cert_sign,'big'))[2:]

    #Self signature verification of CA certificate
    sm3_ca_tbs_digest = sm3.sm3_hash(func.bytes_to_list(tbs_serialized_ca))
    sm2_ca_obj = sm2.CryptSM2(public_key=ca_pubkey_hex)
    ca_self_verify = sm2_ca_obj.verify(ca_cert_sign_hex, sm3_ca_tbs_digest.encode())
    if(ca_self_verify == False):
        print("Verification failed: Incorrect CA certificate")
        sys.exit()

    #Obtain pkcs7 and its user certificate
    with open(os.path.join(func.derfile_dir, 'signed_data.der'),'rb') as inf:
        pkcs7 = cms.ContentInfo.load(inf.read())
    cms.ContentType()._map['1.2.156.10197.6.1.4.2.2'] = 'signed_data' #修改类属性
    cms.ContentType()._map['1.2.156.10197.6.1.4.2.1'] = 'data'
    del cms.ContentType()._map['1.2.840.113549.1.7.1']
    del cms.ContentType()._map['1.2.840.113549.1.7.2']
    subject_cert_bytes = pkcs7['content']['certificates'][0].dump()
    subject_cert = x509.Certificate.load(subject_cert_bytes)

    #Verify the user certificate in pkcs7 through CA public key
    s_cert_sign = subject_cert['signature_value'].native
    s_cert_sign_hex = hex(int.from_bytes(s_cert_sign,'big'))[2:]
    tbs_serialized = subject_cert['tbs_certificate'].dump()
    sm3_tbs_digest = sm3.sm3_hash(func.bytes_to_list(tbs_serialized))

    ca_verify = sm2_ca_obj.verify(s_cert_sign_hex, sm3_tbs_digest.encode())
    if(ca_verify == False):
        print("Verification failed: Incorrect signer certificate")
        sys.exit()

    #Verify user signature through certificate in pkcs7
    s_pubkey = subject_cert['tbs_certificate']['subject_public_key_info']['public_key'].to_coords()
    s_pubkey_hex = func.point_to_hex(s_pubkey)
    signature = pkcs7['content']['signer_infos'][0]['signature'].native
    signature_hex = hex(int.from_bytes(signature,'big'))[2:]
    data = pkcs7['content']['encap_content_info']['content'].native
    sm3_data_digest = sm3.sm3_hash(func.bytes_to_list(data))
    digest_bytes = int(sm3_data_digest,16).to_bytes(32,'big')

    sm2_s_obj = sm2.CryptSM2(public_key=s_pubkey_hex)
    s_verify = sm2_s_obj.verify(signature_hex, digest_bytes)
    if(s_verify == False):
        print("Verification failed")
        sys.exit()

    print("Verification successful")