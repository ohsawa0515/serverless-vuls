from __future__ import print_function
import commands, os, datetime, boto3
from base64 import b64decode

init_year = os.environ['INIT_YEAR']
encrypted_dbpwd = os.environ['ENCRYPTED_DBPWD']
dbhost = os.environ['DBHOST']
dbuser = os.environ['DBUSER']
dbname = os.environ['DBNAME']
dbport = os.environ['DBPORT']
region = os.environ['AWS_REGION']

kms = boto3.client("kms", region_name=region)

def lambda_handler(event, context):

    d = datetime.datetime.today()
    if not event.has_key('year'):
        year = int(init_year)
    elif int(event['year']) < 1998 or int(event['year']) > d.year:
        year = int(init_year)
    else:
        year = int(event['year'])

    dbpwd = kms.decrypt(CiphertextBlob=b64decode(encrypted_dbpwd))['Plaintext']
    db_path = "%s:%s@tcp(%s:%s)/%s" %(dbuser, dbpwd, dbhost, dbport, dbname)

    # fetch
    check = commands.getoutput('./go-cve-dictionary fetchjvn -dbtype=mysql -dbpath="%s" -log-dir=/tmp/vuls -years %d' % (db_path, year))
    print(check)

    year += 1
    return {u'year': year}
