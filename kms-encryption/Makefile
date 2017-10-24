.PHONY: upload build

S3_BUCKET := serverless-vuls
S3_KEY    := lambda-backed-cloud-formation-kms-encryption.zip

build:
	if [ -a $(GOPATH)/src/github.com/ohsawa0515/lambda-backed-cloud-formation-kms-encryption ] ; \
	then \
		cd  $(GOPATH)/src/github.com/ohsawa0515/lambda-backed-cloud-formation-kms-encryption; git pull -r ; \
	else \
		mkdir -p $GOPATH/src/github.com/ohsawa0515 ; \
		cd $(GOPATH)/src/github.com/ohsawa0515; git clone https://github.com/ohsawa0515/lambda-backed-cloud-formation-kms-encryption.git ; \
	fi;
	cd $(GOPATH)/src/github.com/ohsawa0515/lambda-backed-cloud-formation-kms-encryption; cp -a lambda_function.py $(PWD)/main.py

upload:
	if [ -a $(S3_KEY) ] ; \
	then \
		rm -rf $(S3_KEY); \
	fi;
	zip -r $(S3_KEY) ./*
	aws s3 cp $(S3_KEY) s3://$(S3_BUCKET)/
	rm -f $(S3_KEY)
