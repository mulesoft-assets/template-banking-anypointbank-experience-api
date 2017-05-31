# Template Banking AnypointBank Experience API

+ [License Agreement](#licenseagreement)
+ [Use Case](#usecase)
+ [Considerations](#considerations)
	* [APIs security considerations](#apissecurityconsiderations)
+ [Run it!](#runit)
	* [Running on premise](#runonopremise)
	* [Running on Studio](#runonstudio)
	* [Running on Mule ESB stand alone](#runonmuleesbstandalone)
	* [Running on CloudHub](#runoncloudhub)
	* [Deploying your Anypoint Template on CloudHub](#deployingyouranypointtemplateoncloudhub)
	* [Properties to be configured (With examples)](#propertiestobeconfigured)

# License Agreement <a name="licenseagreement"/>
Note that using this template is subject to the conditions of this [License Agreement](AnypointTemplateLicense.pdf).
Please review the terms of the license before downloading and using this template. In short, you are allowed to use the template for free with Mule ESB Enterprise Edition, CloudHub, or as a trial in Anypoint Studio.

# Use Case <a name="usecase"/>

As a Portal User I want a service to request Banking information about my Accounts and Transactions. 

# Considerations <a name="considerations"/>

To make this Anypoint Template run, there are certain preconditions that must be considered. **Failling to do so could lead to unexpected behavior of the template.**

## APIs security considerations <a name="apissecurityconsiderations"/>
This Experience API is meant to be deployed to CloudHub and managed using the API Platform Manager.

### Exposing external endpoints with HTTPS and basic authentication
+ It is triggered by Anypoint Banking Portal using HTTPS. You can follow the [Building an HTTPS Service Tutorial](https://docs.mulesoft.com/runtime-manager/building-an-https-service) to properly configure the HTTPS listener.  
Requests to the AnypointBank Experience API must contains the Authorization header with bearer JWT session token. The token is generated after successful login is performed by an User on AnypointBank Experience API.    

# Run it! <a name="runit"/>
Simple steps to get Banking AnypointBank Experience API running.
See below.

## Running on premise <a name="runonopremise"/>
In this section we detail the way you should run your Anypoint Template on your computer.


### Where to Download Mule Studio and Mule ESB
First thing to know if you are a newcomer to Mule is where to get the tools.

+ You can download Mule Studio from this [Location](http://www.mulesoft.com/platform/mule-studio)
+ You can download Mule ESB from this [Location](http://www.mulesoft.com/platform/soa/mule-esb-open-source-esb)

### Importing an Anypoint Template into Studio
Mule Studio offers several ways to import a project into the workspace, for instance: 

+ Anypoint Studio generated Deployable Archive (.zip)
+ Anypoint Studio Project from External Location
+ Maven-based Mule Project from pom.xml
+ Mule ESB Configuration XML from External Location

You can find a detailed description on how to do so in this [Documentation Page](http://www.mulesoft.org/documentation/display/current/Importing+and+Exporting+in+Studio).

### Running on Studio <a name="runonstudio"/>
Once you have imported you Anypoint Template into Anypoint Studio you need to follow these steps to run it:

+ Generate keystore and truststore (You can find a detailed description on how to do so in this [Documentation Page](https://docs.mulesoft.com/mule-user-guide/v/3.7/tls-configuration#generating-keystores-and-truststores))
+ Locate the properties file `mule-<env>.properties`, in src/main/app/resources
+ Complete all the properties required as per the examples in the section [Properties to be configured](#propertiestobeconfigured)
+ Once that is done, right click on you Anypoint Template project folder 
+ Hover you mouse over `"Run as"`
+ Click on  `"Mule Application"`

### Running on Mule ESB stand alone <a name="runonmuleesbstandalone"/>
Complete all properties in one of the property files, for example in [mule.prod.properties](../master/src/main/resources/mule.prod.properties) and run your app with the corresponding environment variable to use it. To follow the example, this will be `mule.env=prod`. 

## Running on CloudHub <a name="runoncloudhub"/>
While [creating your application on CloudHub](http://www.mulesoft.org/documentation/display/current/Hello+World+on+CloudHub) (Or you can do it later as a next step), you need to go to `"Manage Application"` > `"Properties"` to set all environment variables detailed in **Properties to be configured**.
Follow other steps defined [here](#runonpremise) and once your app is all set and started, there is no need to do anything else.

### Deploying your Anypoint Template on CloudHub <a name="deployingyouranypointtemplateoncloudhub"/>
Mule Studio provides you with really easy way to deploy your Template directly to CloudHub, for the specific steps to do so please check this [link](http://www.mulesoft.org/documentation/display/current/Deploying+Mule+Applications#DeployingMuleApplications-DeploytoCloudHub)

## Properties to be configured (With examples) <a name="propertiestobeconfigured"/>
In order to use this Mule Anypoint Template you need to configure properties (Credentials, configurations, etc.) either in properties file or in CloudHub as Environment Variables. It's necessary to register your Banking Experience API to desired Bank to obtain client_id, client_secret and endpoind URIs.    
Detailed list with examples:
### Application properties

####HTTPS configuration
+ https.port `8082` 
+ keystore.location `keystore.jks` 
+ keystore.password `pass123!`
+ key.password `pass123!`
+ key.alias `1`
+ truststore.location `truestore` 
+ truststore.password `true123`

####API auto-discovery
+ api.id `123`
+ api.name `example-api`
+ api.version `v1` 

####API Platform Organization
+ anypoint.platform.client_id `cloudhub_client_id` 
+ anypoint.platform.client_secret `cloudhub_client_secret` 

####User identity service
+ identity_service.host `identity.example.com`
+ identity_service.port `443`
+ identity_service.basePath `/api`

+ identity_service_ex.host `identity-ex.example.com`
+ identity_service_ex.port `443`
+ identity_service_ex.basePath `/api`

####JWT session token details
+ access_token.issuer `https://anypoint-bank.example.com`
+ access_token.validity.minutes `30`
+ access_token.encryption_key.path `aes-key.jwk`

####Accounts process API
+ api.banking.accounts.host `http://account-process-api.com`
+ api.banking.accounts.port `80`
+ api.banking.accounts.basePath `/api`

####Anypoint Bank
+ anypoint.bank.name `Anypoint Bank`
+ anypoint.bank.id `1`

####API calls configuration
```
registered.banks 	{\
	"2":\
		{\
			"name": "Chase",\
			"clienId": "client_id",\
			"clientSecret": "client_secret",\
			"asBaseURL" : "https://host:port/basePath", \
			"redirectUri" : "https://host:port/redirectPath", \
			"aispBaseURL" : "https://host:port/basePath" \
		},\
	"3":\
		{\
			"name": "Union Bank",\
			"clienId": "client_id",\
			"clientSecret": "client_secret",\
			"asBaseURL" : "https://host:port/basePath", \
			"redirectUri" : "https://host:port/redirectPath", \
			"aispBaseURL" : "https://host:port/basePath" \
		}\
}
```

