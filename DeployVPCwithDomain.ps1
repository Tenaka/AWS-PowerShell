
<#
    READ ME
    Security Credentials are required

    Go to IAM and create a user
    Add 
        AmazonEC2FullAccess,   
        AmazonS3FullAccess, 
        AWSKeyManagementServicePowerUser, 
        AmazonSSMReadOnlyAccess, 
        AWSKeyManagementServicePowerUser, 
        IAMFullAccess, 
        AmazonSSMManagedInstanceCore,

And the following 2 custom policies 

KMS to grant enabling encrypted volumes - needs refining - without this volumes cant be encrypted and instances will fail to deploy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateRandom",
                "kms:ListRetirableGrants",
                "kms:CreateCustomKeyStore",
                "kms:DescribeCustomKeyStores",
                "kms:ListKeys",
                "kms:DeleteCustomKeyStore",
                "kms:UpdateCustomKeyStore",
                "kms:Encrypt",
                "kms:ListAliases",
                "kms:GenerateDataKey",
                "kms:DisconnectCustomKeyStore",
                "kms:CreateKey",
                "kms:DescribeKey",
                "kms:ConnectCustomKeyStore",
                "kms:CreateGrant"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "kms:*",
            "Resource": "*"
        }
    ]
}

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:SendCommand",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:CreateControlChannel"
            ],
            "Resource": "*"
        }
    ]
}


    If all else fails add the 'AdministratorAccess' Role

    Click into the new user account and select the Security Credential tab

    Create an Access Key and record output - the script will prompt if aws credentials are missing.

    Dont hardcode the access key and secret into the script


    This has limited error handling, its not production and is in dev

    Requires Powershell version 7 or Visual Studio Code

    https://docs.aws.amazon.com/powershell/latest/reference/items/EC2_cmdlets.html
    https://docs.aws.amazon.com/powershell/latest/userguide/powershell_ec2_code_examples.html

    https://docs.aws.amazon.com/powershell/latest/reference/items/S3_cmdlets.html

    https://docs.aws.amazon.com/powershell/latest/reference/items/KeyManagementService_cmdlets.html

    https://docs.aws.amazon.com/powershell/latest/reference/items/SimpleSystemsManagement_cmdlets.html

    version 0.1

#>
#Install required PowerShell Modules 
#Remove-Item "C:\Users\Admin\Documents\PowerShell\Modules" -Recurse -Force | where {$_.name -like "AWS."}

$awsModules = "AWSLambdaPSCore",
"AWS.tools.autoscaling",
"AWS.tools.common",
"AWS.tools.ec2",
"AWS.Tools.KeyManagementService",
"AWS.Tools.S3",
"AWS.Tools.IdentityManagement",
"AWS.Tools.SimpleSystemsManagement"
$awsModCount = $awsModules.Count

foreach ($awsModule in $awsModules)
    {
        install-module $awsModule -Force
            write-host "Installed $awsModule" -ForegroundColor Green
    }

<#
    Highlight any problems importing moduels, this is a Visual Code Studio feature locking\in-use .dll's preventing modules importing
    The fix is to close down the application (vsc or powershell) and try to import the modules again
    Last resort is to close application, delete the directories containing the modules
    The following tries to check that all the modules are loaded correctly
#>
$i=0
foreach ($awsModule in $awsModules)
    {
        try {
                import-module $awsModule -Force -ErrorAction Stop
                    write-host "Importing $awsModule" -ForegroundColor Green             
            }
        catch 
            {
                $gtModulePath =  (get-module -ListAvailable $awsModule).Path
                foreach ($ModulePath in $gtModulePath)
                    {
                        $spPathModule = Split-Path $ModulePath -Parent                   
                        #Remove-Item $spPathModule -Force -Recurse -Confirm:$false
                            #Write-Host "Removed $ModulePath" -ForegroundColor Cyan
                            Write-Host "Close down app executing this script as the Modules are in use and retry" -ForegroundColor red
                            Write-Host "Failing that, close down app and remove the following directory $spPathModule and then try again" -ForegroundColor Red
                }
               #If this equals more than zero there's problems with importing modules
                $i++                
            }
    }
if ($i -gt 0)
    {
        write-host "Fix issues with importing modules" -ForegroundColor Red
        pause
        exit;
    }
    
    #Update-AWSToolsModule -Confirm:$false
<#    
    Quick test to see if the aws.tools modules have been imported
#>
$gtModules = (Get-Module  | where {$_.name -like "AWS*"}).name  
$awsImportedCount = $gtModules.Count
    if($awsModCount -eq $awsImportedCount)
        {
            write-host "The number of listed modules matches the number of imported modules" -ForegroundColor Green
        }
    else
        {
            write-host "The number listed modules does not match the imported modules" -ForegroundColor Red
            pause
            exit;
        }    

<#    
    Set-AWSCredential -AccessKey -SecretKey
#>    
try
    {
        $gtAWSCreds = Get-AWSCredentials
        $accessKey = $gtAWSCreds.GetCredentials().AccessKey
        $secretKey = $gtAWSCreds.GetCredentials().SecretKey
        Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey 
    }
catch
    {
        $accessKey = Read-Host "Enter Access Key"
        $secretKey = Read-Host "Enter Secret Key"
        Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey 
    }

<#    
    Set Region
#>     
$region1 = "us-east-1"   #this is hardcoded in the ec2 userdata script as well
Set-defaultAWSRegion -Region $region1

#Download Domain and OU deployment scripts
$pwdPath = "C:\AWS-Domain\"
try
    {Get-ChildItem $pwdPath -erroraction Stop}  
catch
    {New-Item $pwdPath -ItemType Directory -Force}

#Logging
Start-Transcript -Path "$($pwdPath)\AWS-Logging.log" -Force
    write-host "Logs are written to $($pwdPath)\AWS-Logging.log" -ForegroundColor Green
#Download the Domain and OU scripts
try {
        $domainZip = "https://github.com/Tenaka/AWS-PowerShell/raw/main/AD-AWS.zip" 
        Invoke-WebRequest -Uri $domainZip -OutFile "$($pwdPath)\AD-AWS.zip" -errorAction Stop
        #Expand-Archive -Path "$($pwdPath)\AD-AWS.zip" -DestinationPath $pwdPath -Force
        $pwdZip = "$($pwdPath)\AD-AWS.zip"
        $domainScript = "$($pwdPath)\AD-AWS\"
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
        exit;
    }    

<#    
    Declare Variables for VPC
#> 
$cidr = "10.1.1"      # Dont use "10.1.250.0/24" as this is assigned to Transit Gateway and another VPC
$cidrFull = "$($cidr).0/24"

#Check that the CIDR is unique - If its found EXIT.
$gtVpcCidr = Get-EC2Vpc
    if ($gtVpcCidr.CidrBlock -match $cidrFull)
        {
            Write-Host "The VPC has the CIDR already, change the CIDR and try again" -ForegroundColor Red
            pause
            exit;    
        }

#Get the Public IP of the Router - Require to set RDP access via Public Security Group
$whatsMyIP = (Invoke-WebRequest ifconfig.me/ip).Content.Trim()    #Enter your IP home or business will be used for allowing RDP traffic into Server
    if ([string]::IsNullOrWhiteSpace($whatsMyIP) -eq $true){$whatsMyIP = "10.10.10.10"}
        Write-Host "Public facing IP is $whatsMyIP" -ForegroundColor Green

#Transit Gateway Route to another VPC - not required as TG sections is disabled
$transitRoute = "10.2.250.0/24"

#Declare Date
$dateToday = Get-Date -format "yyyy-MM-dd"
$dateTodayMinutes = Get-Date -format "yyyy-MM-dd-mm"
    write-host $dateToday -ForegroundColor Green
    write-host $dateTodayMinutes -ForegroundColor Green

<#    
   Create Key pair - keep PEM file safe for later use - for unencrypting local account passwords
#> 
try 
    {
        $newKeyPair = New-EC2KeyPair -KeyName "$($cidr)-$($dateToday)-KP" -KeyFormat pem -KeyType rsa -errorAction Stop
        $keyPairMaterial = $newKeyPair.KeyMaterial > "$($pwdPath)\$($cidr)-$($dateToday)-KP.pem"  
            try
                {
                    #test that the pen file exists
                    Get-ChildItem -Path "$($pwdPath)\$($cidr)-$($dateToday)-KP.pem" -ErrorAction Stop
                        write-host "$($pwdPath)\$($cidr)-$($dateToday)-KP.pem keypair file has been created" -ForegroundColor Green
                }
            catch
                {
                    $exceptionMessage = $_.Exception.message
                        Write-Host "Keypair file creation has failed" -ForegroundColor Red
                    Pause     
                    exit;            
                }
    }
catch
    {
        #During testing KeyPair would fail on re-runs due to the creation of duplicates - added minutes to name
        $newKeyPair = New-EC2KeyPair -KeyName "$($cidr)-$($dateTodayMinutes)-KP" -KeyFormat pem -KeyType rsa -errorAction Stop
        $keyPairMaterial = $newKeyPair.KeyMaterial > "$($pwdPath)\$($cidr)-$($dateToday)-KP.pem" 
            try
                {
                    #test that the pen file exists
                    Get-ChildItem -Path "$($pwdPath)\$($cidr)-$($dateToday)-KP.pem" -ErrorAction Stop
                        write-host "$($pwdPath)\$($cidr)-$($dateTodayMinutes)-KP.pem keypair file has been created" -ForegroundColor Green
                }
            catch
                {
                    $exceptionMessage = $_.Exception.message 
                         Write-Host "Keypair file creation has failed" -ForegroundColor Red
                    pause
                    exit;            
                }
    } 

<#
    New Key Management Service (KMS) value requires  AWS.Tools.KeyManagementService module
#>
try 
    {
        $newKMSKey = New-KMSKey -KeyUsage ENCRYPT_DECRYPT -Description "$($cidr).0/27 - KMS" -errorAction Stop
        $tag = New-Object Amazon.KeyManagementService.Model.Tag
        $tag.TagKey = "Name"
        $tag.TagValue = "$($cidr).0/27 - KMS"
        Add-KMSResourceTag -KeyId $newKMSKey.keyid -Tags $tag
        
        #no spaces allowed with Alias
        New-KMSAlias -TargetKeyId $newKMSKey.keyid -AliasName "alias/KMS-Encrypt-Volumes-$($dateToday)"
            Write-Host "New KmsKey is named $($cidr).0/27 - KMS with, id of $($newKMSKey.keyid) and an alias of alias/KMS-Encrypt-Volumes-$($dateToday)" -ForegroundColor Green        
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "The creation of a new KMS Key has failed" -ForegroundColor Red
    } 

<#
    New VPC
#>
try 
    {
        $newVPC = New-EC2vpc -CidrBlock "$cidrFull" -errorAction Stop
        $vpcID = $newVPC.VpcId
        $tagVPCValue = "VPCValue"
        $tag=@()
        $tags = New-Object Amazon.EC2.Model.Tag
        $tags = @( @{key="Name";value="VPC $cidrFull"}, `
                   @{key="VPCTag";value="Some Tag Example"} )
        New-EC2Tag -Resource $vpcID -Tag $tags 
            write-host "VPC with a CIDR of $cidrFull has been created" -ForegroundColor Green
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "A VPC has failed creation" -ForegroundColor Red
        Pause
        exit;
    } 

<#
    New Subnets

    New-EC2Subnet -VpcId vpc-12345678 -CidrBlock 10.0.0.0/24
    Get-EC2Subnet -SubnetId subnet-1a2b3c4d
#>

#PUBLIC SUBNET
try 
    {
        $Ec2subnetPub = New-EC2Subnet -CidrBlock "$($cidr).0/27"  -VpcId $vpcID -errorAction Stop
        $SubPubID = $ec2subnetPub.SubnetId
        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$($cidr).0/27 - Public Subnet"

        New-EC2Tag -Resource $Ec2subnetPub.SubnetId -Tag $tag
        Edit-EC2SubnetAttribute -SubnetId $ec2subnetPub.SubnetId -MapPublicIpOnLaunch $true 
            write-host "The new Public Subnet has been created with a CIDR of $($cidr).0/27" -ForegroundColor Green  
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "The new Public Subnet failed to create with a CIDR of $($cidr).0/27" -ForegroundColor Red
    } 

#PRIVATE SUBNET
try 
    {
        $Ec2subnetPriv = new-EC2Subnet -CidrBlock "$($cidr).32/27"  -VpcId $vpcID -errorAction Stop
        $SubPrivID = $Ec2subnetPriv.SubnetId
        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$($cidr).32/27 - Private Subnet"
        New-EC2Tag -Resource $Ec2subnetPriv.SubnetId -Tag $tag
            write-host "The new Private Subnet has been created with a CIDR of $($cidr).32/27" -ForegroundColor Green
        
    }
catch
    {
            $exceptionMessage = $_.Exception.message 
                Write-Host "The new Private Subnet failed to create with a CIDR of $($cidr).32/27" -ForegroundColor Red
    } 

<#
    Create Internet Gateway and attach it to the VPC
    New-EC2InternetGateway
#>
try 
    {
        $Ec2InternetGateway = New-EC2InternetGateway -errorAction Stop
        $InterGatewayID = $Ec2InternetGateway.InternetGatewayId
        Add-EC2InternetGateway -InternetGatewayId $InterGatewayID -VpcId $vpcID 
        
        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$cidr-InternetGateway"
        New-EC2Tag -Resource $InterGatewayID -Tag $tag 
            write-host "New Internet Gateway has been created with and id of $InterGatewayID" -ForegroundColor Green             
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "Creation of Intenret Gateway has failed" -ForegroundColor Red
    } 

<#
    Create custom route table with route to the internet and associate it with the subnet
    Get-EC2RouteTable -Filter @{ Name="vpc-id"; Values="vpc-1a2b3c4d" }
    New-EC2Route -RouteTableId rtb-1a2b3c4d -DestinationCidrBlock 0.0.0.0/0 -GatewayId igw-1a2b3c4d
#>
#PUBLIC Route Table
try 
    {
        $Ec2RouteTablePub = New-EC2RouteTable -VpcId $vpcID -errorAction Stop
        $Ec2RouteTablePubID = $Ec2RouteTablePub.RouteTableId

        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$($cidr).0/27 - Public Route"
        New-EC2Tag -Resource $Ec2RouteTablePubID -Tag $tag
        New-EC2Route -RouteTableId $Ec2RouteTablePub.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $InterGatewayID

        Register-EC2RouteTable -RouteTableId $Ec2RouteTablePubID -SubnetId $SubPubID   
            write-host "Created the Public Route Table" -ForegroundColor Green      
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "Failed to create the Public Route Table" -ForegroundColor red
    } 

#PRIVATE Route Table
try 
    {
        $Ec2RouteTablePriv = New-EC2RouteTable -VpcId $vpcID -errorAction Stop 
        $Ec2RouteTablePrivID = $Ec2RouteTablePriv.RouteTableId

        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$($cidr).32/27 - Private Route"
        New-EC2Tag -Resource $Ec2RouteTablePrivID -Tag $tag

        Register-EC2RouteTable -RouteTableId $Ec2RouteTablePrivID -SubnetId $SubPrivID
            write-host "Created the Private Route Table" -ForegroundColor Green          
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "Failed to create the Private Route Table" -ForegroundColor red    
    } 

<#
    Create Security groups

    Get-EC2SecurityGroup -GroupName my-security-group
    Get-EC2SecurityGroup -Filter @{Name="vpc-id";Values="vpc-0fc1ff23456b789eb"}
    New-EC2SecurityGroup -GroupName my-security-group -Description "my security group" -VpcId vpc-12345678

    $ip = @{ IpProtocol="tcp"; FromPort="80"; ToPort="80"; IpRanges="203.0.113.0/24" } 
    Grant-EC2SecurityGroupEgress -GroupId sg-12345678 -IpPermission $ip

    $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="203.0.113.25/32" }
    $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="203.0.113.25/32" }
    Grant-EC2SecurityGroupIngress -GroupId sg-12345678 -IpPermission @( $ip1, $ip2 )

    [Amazon.EC2.Model.IpPermission]::new() | Get-Member -MemberType Property
#>

#PUBLIC Security Group
try 
    {
        $SecurityGroupPub = New-EC2SecurityGroup -Description "Public Security Group" -GroupName "PublicSubnet" -VpcId $vpcID -Force -errorAction Stop

        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "PublicSubnet"
        New-EC2Tag -Resource $SecurityGroupPub -Tag $tag
            write-host "New Public Security Group has been created" -ForegroundColor Green
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "New Public Security Group has failed" -ForegroundColor Red
    } 

#PRIVATE Security Group
try 
    {
        $SecurityGroupPriv = New-EC2SecurityGroup -Description "Private Security Group" -GroupName "PrivateSubnet" -VpcId $vpcID -Force -errorAction Stop

        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "PrivateSubnet"
        New-EC2Tag -Resource $SecurityGroupPriv -Tag $tag 
            write-host "New Private Security Group has been created" -ForegroundColor Green       
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "New Private Security Group has failed" -ForegroundColor Red

    } 

#Inbound Rules
$InAllCidr = @{IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges=$cidrFull}
$InAllPrivCidr = @{IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="$($cidr).32/27"}
$InTCPWinRm = @{IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges=$cidrFull}
$InTCP3389 = @{IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges=$cidrFull}
$InTCPWhatmyIP3389 = @{IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$($whatsMyIP)/32"}
$InTCPWhatmyIPWinRM = @{IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="$($whatsMyIP)/32"}

#Outbound Rules
$EgAllCidr = @{IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges=$cidrFull}
$EgAllPrivCidr = @{IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="$($cidr).32/27"}
$EgTCPWinRM = @{IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges=$cidrFull}
$EgTCP3389 = @{IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges=$cidrFull}
$EgTCP443 = @{IpProtocol="tcp"; FromPort="443"; ToPort="443"; IpRanges="0.0.0.0/0"}

#PUBLIC - Inbound
try 
    {
        Grant-EC2SecurityGroupIngress -GroupId $SecurityGroupPub -IpPermission @($InTCPWhatmyIP3389) -errorAction Stop  
            write-host "Added Inbound rules to the Public Security Group" -ForegroundColor Green      
    }
catch
    {
        $exceptionMessage = $_.Exception.message
            write-host "Faield to add Inbound rules to the Public Security Group" -ForegroundColor Red 
    } 

#PUBLIC - Outbound
try 
    {
        Grant-EC2SecurityGroupEgress -GroupId $SecurityGroupPub -IpPermission @($EgTCPWinRM, $EgTCP3389) -errorAction Stop
            write-host "Added Outbound rules to the Public Security Group" -ForegroundColor Green        
    }
catch
    {
        $exceptionMessage = $_.Exception.message
            write-host "Failed to add Outbound rules to the Public Security Group" -ForegroundColor Red 
    } 

#PUBLIC - Remove the default any any outbound rule
try 
    {
        $InRvDefault = @{ IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="0.0.0.0/0"}
        Revoke-EC2SecurityGroupEgress -GroupId $SecurityGroupPub -IpPermission $InRvDefault -errorAction Stop    
            write-host "Removed the Any Any from the Outbound Public Security Group" -ForegroundColor Green    
    }
catch
    {
        $exceptionMessage = $_.Exception.message
            write-host "Failed to remove the Any Any Outbound rule from the Public Security Group" -ForegroundColor Red
    } 

#PRIVATE Inbound
try 
    {
        Grant-EC2SecurityGroupIngress -GroupId $SecurityGroupPriv -IpPermission @($InAllPrivCidr, $InTCP3389, $InTCPWinRm) -errorAction Stop        
            write-host "Added Inbound rules to the Private Security Group" -ForegroundColor Green
    }
catch
    {
        $exceptionMessage = $_.Exception.message
            write-host "Failed to Add Inbound rules to the Private Security Group" -ForegroundColor Red
    } 

#PRIVATE Outbound
try 
    {
        Grant-EC2SecurityGroupEgress -GroupId $SecurityGroupPriv -IpPermission @($EgAllPrivCidr,$EgAllCidr) -errorAction Stop        
            write-host "Added Outboudn rules to the Private Security Group" -ForegroundColor Green
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            write-host "Added Outbound rules to the Privvate Security Group" -ForegroundColor Red
    } 

#PRIVATE - Remove the default any any outbound rule - Do not enable as this will prevent access to S3 Bucket
#$InRvDefault = @{ IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="0.0.0.0/0" }
#Revoke-EC2SecurityGroupEgress -GroupId $SecurityGroupPriv -IpPermission $InRvDefault

<#
    S3 Buckets
    Write-S3Object -BucketName test-files -Folder .\Scripts -KeyPrefix SampleScripts\
    Write-S3Object -BucketName test-fi-les -Folder .\Scripts -KeyPrefix SampleScripts\ -SearchPattern *.ps1

    https://docs.aws.amazon.com/powershell/latest/reference/items/Get-S3Bucket.html

    no CAPS to be used in the name    
#>
try
    {
        $news3Bucket = New-S3Bucket -BucketName "auto-domain-create-$($dateTodayMinutes)" -Force -errorAction Stop
            Write-Host "New S3 Bucket with a name of auto-domain-create-$($dateTodayMinutes) has been created" -ForegroundColor Green
        $s3BucketName = $news3Bucket.BucketName
        $S3BucketARN = "arn:aws:s3:::$($s3BucketName)"

        $s3Url = "https://$($s3BucketName).s3.amazonaws.com/Domain/"
        Write-S3Object -BucketName $s3BucketName Domain -Folder $pwdPath -Force -errorAction
            Write-Host "The Domain zip file has been uploaded to auto-domain-create-$($dateTodayMinutes) S3 Bucket"        
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "Either the S3 Bucket failed to be created or the Zip file hasnt uploaded" -ForegroundColor Red
    } 

<#
    IAM S3 Bucket Read Account to allow DC to access S3 Bucket with user

    Dont require a user, alt is to assign the policy directly against the EC2 Instance, resulting in no hard coded and in clear pass keys

#> 
#create new IAM User
$s3User = "DomainCtrl-S3-READ"
$s3Group = 'S3-AWS-DC'
try 
    {
        $newIAMS3Read = New-IAMUser -UserName $s3User -errorAction Stop
            Write-Host "New IAM User account has been created, its named $s3User" -ForegroundColor Green       
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "Failed to create AIM User $s3User" -ForegroundColor red
    } 

#Create Access Key
try 
    {
        $newIAMAccKey = New-IAMAccessKey -UserName $newIAMS3Read.UserName -errorAction Stop
        $iamS3AccessID = $newIAMAccKey.AccessKeyId
        $iamS3AccessKey = $newIAMAccKey.SecretAccessKey
            write-host "The User Access Key and Secret have been created with the values set to the vars" -ForegroundColor Green
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "The Access key and Secret havent been created, this will prevent the DC from accessing the S3 Bucket" -ForegroundColor Red
    } 

#Create IAM Group
try 
    {
        New-IAMGroup -GroupName 'S3-AWS-DC' -errorAction Stop
        Add-IAMUserToGroup -GroupName $s3Group -UserName $s3User
            Write-Host "New IAM Group named $s3Group has been created" -ForegroundColor Green        
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "The IAM Group $s3Group has failed to be created" -ForegroundColor Red
    } 

#S3 Bucket Policy to allow READ access
$s3Policy = @'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
'@

#Import Policy
try 
    {
        $iamNewS3ReadPolicy = New-IAMPolicy -PolicyName 'S3-DC-Read' -Description 'Allows Read access to S3 from Domain Controller' -PolicyDocument $s3Policy -errorAction Stop
        Register-IAMGroupPolicy -GroupName $s3Group -PolicyArn $iamNewS3ReadPolicy.Arn
            Write-Host "A new IAM policy has been named S3-DC-Read has been created"-ForegroundColor Green     
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "Failed to import the AIM policy allowing access to the S3 Bucket" -ForegroundColor Red
    } 

<#
    Endpoints
    New-EC2VpcEndpoint -ServiceName c-om.amazonaws.eu-west-1.s3 -VpcId vpc-

    $newEnpointS3 = New-EC2VpcEndpoint -ServiceName "com.amazonaws.us-east-1.s3" -VpcEndpointType Interface -VpcId $vpcID -SecurityGroupId $SecurityGroupPriv -SubnetId $SubPrivID 

#> 
try 
    {
        $newEnpointS3 = New-EC2VpcEndpoint -ServiceName "com.amazonaws.us-east-1.s3" -VpcEndpointType Gateway -VpcId $vpcID -RouteTableId $Ec2RouteTablePubID,$Ec2RouteTablePrivID -errorAction Stop

        $newEnpointS3ID = $newEnpointS3.VpcEndpoint.VpcEndpointId
        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "S3-Bucket-Endpoint"

        New-EC2Tag -Resource $newEnpointS3ID -Tag $tag
            Write-Host "A new Endpoint so the Private Subnet can access the S3 Bucket has been created" -ForegroundColor Green        
    }
catch
    {
        $exceptionMessage = $_.Exception.message 
            Write-Host "The Endpoint allowing Private Servers to access S3 has failed to be created" -ForegroundColor Red
    } 

<#
    EC2 Instances
#>
#Enforce EC2 Volume Encryption - need to enable ebs encryption with KMS and not the AWS key
Enable-EC2EbsEncryptionByDefault -Region $region1

#Search for the latest Srv 2022 Base
$gtSrv2022AMI = Get-SSMLatestEC2Image -Path ami-windows-latest -Region $region1 | 
    where {$_.name -match "2022" -and `
    $_.name -match "full-base"-and    `
    $_.name -match "English" -and     `
    $_.name -notmatch "TPM-"}

    #declare volume mapping and encryption - still work in progress
    #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/image/block_device_mappings.html
    
    $ebsVolType = "io1"
    $ebsIops = 2000
    $ebsTrue = $true
    $ebsFalse = $false
    $ebskmsKeyArn = $newKMSKey.Arn
    $ebsVolSize = 50

    $blockDeviceMapping = New-Object Amazon.EC2.Model.BlockDeviceMapping
    $blockDeviceMapping.DeviceName = "/dev/sda1"
    $blockDeviceMapping.Ebs = New-Object Amazon.EC2.Model.EbsBlockDevice
    $blockDeviceMapping.Ebs.DeleteOnTermination = $enc
    $blockDeviceMapping.Ebs.Iops = $ebsIops
    $blockDeviceMapping.Ebs.KmsKeyId = $ebsKmsKeyArn
    $blockDeviceMapping.Ebs.Encrypted = $ebsTrue
    $blockDeviceMapping.Ebs.VolumeSize = $ebsVolSize
    $blockDeviceMapping.Ebs.VolumeType = $ebsVolType

    #    -BlockDeviceMapping $BlockDevMap ` add to instance

#Public UserData to rename computer and reset admin password
$RDPScript = 
'<powershell>
        Set-LocalUser -Name "administrator" -Password (ConvertTo-SecureString -AsPlainText ChangeMe1234 -Force)
        Rename-Computer -NewName "JUMPBOX1"    
        shutdown /r /t 10

</powershell>'
$RDPUserData = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($RDPScript))

#PUBLIC - Create an EC2 Instance - Public Instance Jump Box
$new2022InstancePub = New-EC2Instance `
    -ImageId $gtSrv2022AMI.value `
    -MinCount 1 -MaxCount 1 `
    -KeyName $newKeyPair.KeyName `
    -SecurityGroupId $SecurityGroupPub `
    -InstanceType t3.medium `
    -SubnetId $SubPubID `
    -UserData $RDPUserData `
    -BlockDeviceMapping $blockDeviceMapping

$new2022InstancePubID = $new2022InstancePub.Instances.InstanceId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Public RDP Jump Box to Private"
New-EC2Tag -Resource $new2022InstancePubID -Tag $tag    

#PRIVATE Userdate - dont add comments - makes this a Domain Controller
$domScript = 
'<powershell>

    import-module awspowershell ;

    Set-AWSCredential
    Set-defaultAWSRegion

    $pwdPath = "C:\AWS-Domain\" ;
    try
        {Get-ChildItem $pwdPath -erroraction Stop}  
    catch
        {New-Item $pwdPath -ItemType Directory -Force} ;

    $pwdDomain = "$($pwdPath)\Domain\"    ;
    Copy-S3Object auto-domain-create-2024-07-12-08 -key Domain/AD-AWS.zip -LocalFile "$($pwdDomain)\AD-AWS.zip" ;

    Expand-Archive -Path "$($pwdDomain)\AD-AWS.zip" -DestinationPath $pwdPath -Force ;
    $domainScript = "$($pwdPath)\AD-AWS\" ;   

    Set-LocalUser -Name "administrator" -Password (ConvertTo-SecureString -AsPlainText ChangeMe1234 -Force) ;

    $adminGet = gwmi win32_useraccount | where {$_.name -eq "administrator"} ;
    $sidGet = $adminGet.SID ;

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1 -Force ;
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "administrator" -Force ;
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "ChangeMe1234" -Force ;
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonSID -Value $sidGet -Force ;
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount -Value 0 -PropertyType string -Force ;

    $schTaskName = "AWSDCPromo" ;
    $trigger = New-ScheduledTaskTrigger -AtLogOn ;
    $battery = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries  ;
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-executionPolicy bypass -file C:\AWS-Domain\AD-AWS\dcPromo.ps1" ;
    Register-ScheduledTask -TaskName $schTaskName -Trigger $trigger -Settings $battery -User Administrator -Action $action -RunLevel Highest -Force ;

    Rename-Computer -NewName "AWSDC01"  ;
    start-sleep 10 ;
    shutdown /r /t 0

    </powershell>'

#Inject IAM User Creds to READ S3 Bucket then import as Base64   
$domScript | Out-File "$($pwdPath)\Base64.log"    
$gtDomScriptTxt = Get-Content "$($pwdPath)\Base64.log" 
$gtDomScriptTxt.Replace("Set-AWSCredential","Set-AWSCredential -AccessKey $($iamS3AccessID) -SecretKey $($iamS3AccessKey) ;").Replace("Set-defaultAWSRegion","Set-defaultAWSRegion -Region $region1 ;").replace("auto-domain-create-2024-07-12-08","auto-domain-create-$($dateTodayMinutes)") | Out-File "$($pwdPath)\Base64.log" -Force
$gtDomScriptTxt = Get-Content "$($pwdPath)\Base64.log" 

$UserData = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($gtDomScriptTxt))

#PRIVATE Instance
$new2022InstancePriv = New-EC2Instance `
    -ImageId $gtSrv2022AMI.value `
    -MinCount 1 -MaxCount 1 `
    -KeyName $newKeyPair.KeyName `
    -SecurityGroupId $SecurityGroupPriv  `
    -InstanceType t3.medium `
    -SubnetId $SubPrivID `
    -UserData $UserData `
    -BlockDeviceMapping $blockDeviceMapping   

$new2022InstancePrivID = $new2022InstancePriv.Instances.InstanceId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Private Domain Controller"
New-EC2Tag -Resource $new2022InstancePrivID  -Tag $tag    

Stop-Transcript
