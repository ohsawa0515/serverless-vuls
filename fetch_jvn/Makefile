.PHONY: upload build

S3_BUCKET := serverless-vuls
S3_KEY    := fetch_nvd.zip

build:
		if [ -a $(GOPATH)/src/github.com/kotakanbe/go-cve-dictionary ] ; \
		then \
    		cd  $(GOPATH)/src/github.com/kotakanbe/go-cve-dictionary; git pull -r ; \
		else \
				mkdir -p $(GOPATH)/src/github.com/kotakanbe ; \
				cd $(GOPATH)/src/github.com/kotakanbe; git clone https://github.com/kotakanbe/go-cve-dictionary.git ; \
		fi;
		cd $(GOPATH)/src/github.com/kotakanbe/go-cve-dictionary; make install
		cd $(GOPATH)/src/github.com/kotakanbe/go-cve-dictionary; go build -o $(PWD)/go-cve-dictionary
		chmod +x $(PWD)/go-cve-dictionary

upload:
		if [ -a $(S3_KEY) ] ; \
		then \
     rm -rf $(S3_KEY); \
		fi;
		zip -r $(S3_KEY) ./*
		aws s3 cp $(S3_KEY) s3://$(S3_BUCKET)/
		rm -f $(S3_KEY)
