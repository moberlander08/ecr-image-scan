# ecr-image-scan
Script to repot image vulnerabilities and/or tag image for workflow approval

#Disclaimer: 
This script is as is.  Meaning I provide no support and if you wish to use feel free, but you do so at your own risk.

---
##Orginal ask: 
I wrote this script to provide a means for our compliance team to review the vulnerabilities in our docker containers that were stored in our AWS environment.  

##Why is this script important:
This was my first python script I wrote that solved a real problem I had, and overtime it was a script that I continuted to imporve and refine as I got more confident in my ability to code.

##Design:
Ideas was to have the ECR Image Scan provide the vulnerability data, and then I decided that being able to provide the data in a CSV that our complance team could download at their convience was the best way to start.  As the script evolved and my coding skills got better.  The script evolved in to a workflow tool that could not only provide a vulnerability repot it could be used to approve images programatically for deployment process to leverage.

##What would I do differently:
For one:  I would have use argparse to handle user input
Secound: Not use ecr repo tags to store the approve/adminoveride iamges.  Something like Dnyamodb would have been a better option.
