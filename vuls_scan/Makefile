.PHONY: upload build

S3_BUCKET := serverless-vuls
S3_KEY    := vuls_scan.zip
EC2_VULS_CONFIG_VERSION := v0.1.0

build:
	  # Vuls
		if [ -a $(GOPATH)/src/github.com/future-architect/vuls ] ; \
		then \
    		cd  $(GOPATH)/src/github.com/future-architect/vuls; git pull -r ; \
		else \
				mkdir -p $GOPATH/src/github.com/future-architect ; \
				cd $(GOPATH)/src/github.com/future-architect; git clone https://github.com/future-architect/vuls.git ; \
		fi;
		cd $(GOPATH)/src/github.com/future-architect/vuls; make install
		cd $(GOPATH)/src/github.com/future-architect/vuls; go build -o $(PWD)/vuls
		chmod +x $(PWD)/vuls
    # ec2-vuls-config
		wget "https://github.com/ohsawa0515/ec2-vuls-config/releases/download/$(EC2_VULS_CONFIG_VERSION)/ec2-vuls-config_linux_amd64.tar.gz"
		tar zxf ec2-vuls-config_linux_amd64.tar.gz
		rm -f ec2-vuls-config_linux_amd64.tar.gz

upload:
		if [ -a $(S3_KEY) ] ; \
		then \
     rm -rf $(S3_KEY); \
		fi;
		zip -r $(S3_KEY) ./*
		aws s3 cp $(S3_KEY) s3://$(S3_BUCKET)/
		rm -f $(S3_KEY)
