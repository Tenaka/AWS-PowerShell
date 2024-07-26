# AWS-PowerShell

This is in Dev and may not work as intended.

The script will deploy a VPC with a private and public subnet.
Create all the necessary security groups, S3 bucket, IAM etc
Deploy a public ec2 instance secured to your public ip as an RDP jump box
Deploy private ec2 instance that can only be accessed via the public RDP server
The private ec2 instance will auto deploy a Domain Controller based on my AD and OU deployment script
https://www.tenaka.net/post/deploy-domain-with-powershell-and-json-part-1

