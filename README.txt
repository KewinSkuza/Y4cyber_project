Rec-encrypt.io

Encryption Recommendation for Small to Medium EnterprisesApplication that views your database data and classifies which fields contain sensitive information and should be encrypted and which fields are not safe to store in plaintext.

Note:
	- At the moment only PHPMyAdmin database export is supported, other administration tools will not work.
	
	- This application does not perform any encryption. It simply recommends which fields within your database should be encrypted

	- The Amazon service used is NOT FREE. You can find out more about the pricing at: https://aws.amazon.com/macie/pricing/

	- Required Files:
		- rec-encrypt.pyw
		- AWS.py 
		- scripts.py
		- green.png
		- red.png
		- requirenments.txt

	- Prerequisites:
		- Python 3.9 or higher
		- pip
		- AWS account
		- Windows operating system

Installation:

	- Open command prompt in directory where the files are located

	- Make sure that python is installed on your device
		= This can be done using the command py --version or python --version
		= Version Python 3.9 is confirmed to work

	- Make sure that pip is installed on your machine
		= Can be done using pip --version command

	- Download dependencies by issuing:
		= pip install -r requirenments.txt

	- Now you are ready to launch the application

AWS account:

	- This application requires an AWS account to work

	- The services used are sts, macie, s3, and iam

	- To create an AWS account visit: https://aws.amazon.com/

	- Create your account and sign in

	- You will require to input access keys to log into the application. This can be done by:

		= Signing into your AWS account; you will be inside the AWS console

		= On the top right of your screen you will see an option menu with your username on it. Press it.

		= A drop down menu will appear. Press on "Security Credentials".

		= This will take you to another page. This page will display a lot of different options. DO not be alarmed; we only require one thing from here.

		= Look for a dropdown button titled "Access keys (access key ID and secret access key)". Press it.

		= You will be able to see a blue button named "Create New Access Key". This will generate an access key ID and secret access key.

		= Press "Show Access Key" to view your access keys

		= REMEMBER, YOU WILL NOT BE ABLE TO VIEW THE SECRET ACCESS KEY AGAIN, MEMORIZE IT OR SAVE IT IN A SAFE LOCATION

		= These access keys can now be used in the application

Use:

	The application is equipped with a how-to-use page which you can refer to at any moment.
	
Results:
	
	- Top of screen the application will display the approximate time it would take to encrypt the supplied data
	
	- A table will be displayed with a colored strip on top. The strip will be either red or green above each column:
		- Green means that the data is safe and there is no urgent need to encrypt it 
		- Red means that the data is sensitive and should be encrypted
	
	- The table itself will display the data supplied in a neat manner