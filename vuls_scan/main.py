from __future__ import print_function
import boto3, commands, os, shutil
from base64 import b64decode
from os.path import basename

bucket = os.environ['S3_BUCKET']
encrypted_sshkey = os.environ['ENCRYPTED_SSHKEY']
encrypted_dbpwd = os.environ['ENCRYPTED_DBPWD']
dbhost = os.environ['DBHOST']
dbuser = os.environ['DBUSER']
dbname = os.environ['DBNAME']
dbport = os.environ['DBPORT']
region = os.environ['AWS_REGION']

id_rsa_path = "/tmp/id_rsa"
kms = boto3.client("kms", region_name=region)

def lambda_handler(event, context):

    # create id_rsa
    id_rsa = kms.decrypt(CiphertextBlob=b64decode(encrypted_sshkey))['Plaintext']
    f = open(id_rsa_path, "w")
    f.write(id_rsa)
    f.close()

    # exec ec2-vuls-config
    check = commands.getoutput('export AWS_REGION=%s ; ./ec2-vuls-config --config ./config.toml --out /tmp/config.toml' % region)
    print(check)

    # configtest
    check = commands.getoutput('./vuls configtest -config=/tmp/config.toml -log-dir=/tmp/vuls -ssh-native-insecure')
    print(check)

    # scan
    check = commands.getoutput('./vuls scan -config=/tmp/config.toml -results-dir=/tmp/results -log-dir=/tmp/vuls -ssh-native-insecure')
    print(check)

    # report
    dbpwd = kms.decrypt(CiphertextBlob=b64decode(encrypted_dbpwd))['Plaintext']
    cvedb_url = "%s:%s@tcp(%s:%s)/%s?parseTime=true" %(dbuser, dbpwd, dbhost, dbport, dbname)
    check = commands.getoutput('./vuls report -lang=ja -config=/tmp/config.toml -results-dir=/tmp/results -log-dir=/tmp/vuls -format-one-line-text -cvedb-type=mysql -cvedb-url="%s" -refresh-cve' % cvedb_url)
    print(check)

    # S3 report
    check = commands.getoutput('./vuls report -lang=ja -config=/tmp/config.toml -results-dir=/tmp/results -log-dir=/tmp/vuls -to-localfile -format-json -to-s3 -aws-region=%s -aws-s3-bucket=%s -cvedb-type=mysql -cvedb-url="%s" -refresh-cve' % (region, bucket, cvedb_url))
    print(check)

    # delete files
    os.remove(id_rsa_path)
    os.remove('/tmp/config.toml')
    shutil.rmtree('/tmp/results')
    shutil.rmtree('/tmp/vuls')

    return True
