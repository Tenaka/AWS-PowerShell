
<#
    READ ME
    Security Credentials are required

    Go to IAM and create a user
    Add AmazonEC2FullAccess, AmazonS3FullAccess, AWSKeyManagementServicePowerUser, AmazonSSMReadOnlyAccess Roles

    If all ele fails add the 'AdministratorAccess' Role

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
#Execution of script directory location
<#
if($psise -ne $null)
{
    $ISEPath = $psise.CurrentFile.FullPath
    $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
    $pwdPath = $ISEPath.TrimEnd("$ISEDisp")
}
else
{
    $pwdPath = split-path -parent $MyInvocation.MyCommand.Path
}
#>

#vsc path - set whilst in dev
$pwdPath = "C:\Users\Admin\Desktop\VPC"

#Install required PowerShell Modules 
install-module AWSLambdaPSCore -Force
install-module AWS.tools.autoscaling -Force
install-module AWS.tools.common -Force
install-module AWS.tools.ec2 -Force
Install-Module AWS.Tools.KeyManagementService -Force
Install-Module AWS.Tools.S3 -Force
Install-Module AWS.Tools.SimpleSystemsManagement -force

import-module AWSLambdaPSCore -Force
import-module AWS.tools.autoscaling -Force
import-module AWS.tools.common -Force
import-module AWS.tools.ec2 -Force
import-module AWS.Tools.KeyManagementService -Force
import-module AWS.Tools.S3 -force
import-module AWS.Tools.SimpleSystemsManagement -force

#List out imported modules
Get-Module

#####Set-AWSCredential -AccessKey -SecretKey
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

$region1 = "us-east-1"
Set-defaultAWSRegion -Region $region1

#Declare Subnet for VPV
$cidr = "10.1.99"      # Dont use "10.1.250.0/24" as this is assigned to Transit Gateway and another VPC
$cidrFull = "$($cidr).0/24"
$whatsMyIP = "123.123.123.124"    #Enter your IP home or business will be used for allowing RDP traffic into Server

#Transit Gateway Route to another VPC
$transitRoute = "10.1.250.0/24"

#Create Key pair - keep pen file safe for later use - for unencrypting local account passwords
$dateToday = get-date -format "yyyy-MM-dd"
$dateTodaySeconds = get-date -format "yyyy-MM-dd-ss"
$pwdpath = (get-location).path  
$newKeyPair = New-EC2KeyPair -KeyName "$($dateToday)-KP" -KeyFormat pem -KeyType rsa
$keyPairMaterial = $newKeyPair.KeyMaterial > "$($pwdPath)\$($dateToday)-KP.pem"


#New Key Management Service (KMS) value requires  AWS.Tools.KeyManagementService module
$newKMSKey = New-KMSKey -KeyUsage ENCRYPT_DECRYPT -Description "$($cidr).0/27 - KMS"
$tag = New-Object Amazon.KeyManagementService.Model.Tag
$tag.TagKey = "Name"
$tag.TagValue = "$($cidr).0/27 - KMS"
Add-KMSResourceTag -KeyId $newKMSKey.keyid -Tags $tag
#no spaces allowed with Alias
New-KMSAlias -TargetKeyId $newKMSKey.keyid -AliasName "alias/KMS-for-Encrypting-Volumes-$($dateToday)"

#VPC
<#
    Get-EC2Vpc -VpcId vpc-12345678
#>
$newVPC = new-ec2vpc -CidrBlock "$cidrFull"
$vpcID = $newVPC.VpcId
$tagVPCValue = "VPCValue"
$tag=@()
$tags = New-Object Amazon.EC2.Model.Tag
$tags = @( @{key="Name";value="VPC $cidrFull"}, `
           @{key="VPCTag";value="Some Tag Example"} )
New-EC2Tag -Resource $vpcID -Tag $tags 

#Subnets
<#
    New-EC2Subnet -VpcId vpc-12345678 -CidrBlock 10.0.0.0/24
    Get-EC2Subnet -SubnetId subnet-1a2b3c4d
#>
$Ec2subnetPub = New-EC2Subnet -CidrBlock "$($cidr).0/27"  -VpcId $vpcID 
$SubPubID = $ec2subnetPub.SubnetId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Public Subnet"
New-EC2Tag -Resource $Ec2subnetPub.SubnetId -Tag $tag
###Edit-EC2SubnetAttribute -SubnetId $ec2subnetPub.SubnetId -MapPublicIpOnLaunch $true

$Ec2subnetPriv = new-EC2Subnet -CidrBlock "$($cidr).32/27"  -VpcId $vpcID 
$SubPrivID = $Ec2subnetPriv.SubnetId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Private Subnet"
New-EC2Tag -Resource $Ec2subnetPriv.SubnetId -Tag $tag

#Create Internet Gateway and attach it to the VPC
<#
    New-EC2InternetGateway
#>
$Ec2InternetGateway = New-EC2InternetGateway
$InterGatewayID = $Ec2InternetGateway.InternetGatewayId
Add-EC2InternetGateway -InternetGatewayId $Ec2InternetGateway.InternetGatewayId -VpcId $vpcID 
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$cidr-InternetGateway"
New-EC2Tag -Resource $InterGatewayID -Tag $tag


#Create custom route table with route to the internet and associate it with the subnet
<#
    Get-EC2RouteTable -Filter @{ Name="vpc-id"; Values="vpc-1a2b3c4d" }
    New-EC2Route -RouteTableId rtb-1a2b3c4d -DestinationCidrBlock 0.0.0.0/0 -GatewayId igw-1a2b3c4d
#>
#Public Route Table
$Ec2RouteTablePub = New-EC2RouteTable -VpcId $vpcID 
$Ec2RouteTablePubID = $Ec2RouteTablePub.RouteTableId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Private Route"
New-EC2Tag -Resource $Ec2RouteTablePubID -Tag $tag
New-EC2Route -RouteTableId $Ec2RouteTablePub.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $InterGatewayID
Register-EC2RouteTable -RouteTableId $Ec2RouteTablePubID -SubnetId $SubPubID 


#Private Route Table
$Ec2RouteTablePriv = New-EC2RouteTable -VpcId $vpcID 
$Ec2RouteTablerivID = $Ec2RouteTablePriv.RouteTableId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Public Route"
New-EC2Tag -Resource $Ec2RouteTablerivID -Tag $tag
Register-EC2RouteTable -RouteTableId $Ec2RouteTablerivID -SubnetId $SubPrivID 


#Create Security group and firewall rule for RDP
<#
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
$SecurityGroupPub = New-EC2SecurityGroup -Description "Public Security Group" -GroupName "PublicSubnet" -VpcId $vpcID -Force
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "PublicSubnet"
New-EC2Tag -Resource $SecurityGroupPub -Tag $tag

$SecurityGroupPriv = New-EC2SecurityGroup -Description "Private Security Group" -GroupName "PrivateSubnet" -VpcId $vpcID -Force
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "PrivateSubnet"
New-EC2Tag -Resource $SecurityGroupPriv -Tag $tag

#Inbound Rules
$InTCPWinRm = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges=$cidrFull}
$InTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges=$cidrFull}
$InTCPWhatmyIP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$($whatsMyIP)/32"}
$InTCPWhatmyIPWinRM = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="$($whatsMyIP)/32"}

#Outbound Rules
$EgTCPWinRM = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges=$cidrFull }
$EgTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges=$cidrFull }
$EgTCP443 = @{ IpProtocol="tcp"; FromPort="443"; ToPort="443"; IpRanges="0.0.0.0/0" }

#PUBLIC
Grant-EC2SecurityGroupIngress -GroupId $SecurityGroupPub -IpPermission @( $InTCPWhatmyIP3389)

Grant-EC2SecurityGroupEgress -GroupId $SecurityGroupPub -IpPermission @( $EgTCPWinRM, $EgTCP3389 )

#Remove the default any any outbound rule
$InRvDefault = @{ IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="0.0.0.0/0" }
Revoke-EC2SecurityGroupEgress -GroupId $SecurityGroupPub -IpPermission $InRvDefault


#PRIVATE
Grant-EC2SecurityGroupIngress -GroupId $SecurityGroupPriv -IpPermission @( $InTCP3389, $InTCPWinRm )


#NACLs
<#
    New-EC2NetworkAcl -VpcId vpc-12345678
    New-EC2NetworkAclEntry -NetworkAclId acl-12345678 -Egress $false -RuleNumber 100 -Protocol 17 -PortRange_From 53 -PortRange_To 53 -CidrBlock 0.0.0.0/0 -RuleAction allow
    (Get-EC2NetworkAcl -NetworkAclId acl-12345678).Entries
    Remove-EC2NetworkAcl -NetworkAclId acl-12345678
    Remove-EC2NetworkAclEntry -NetworkAclId acl-12345678 -Egress $false -RuleNumber 100Set-EC2NetworkAclEntry -NetworkAclId acl-12345678 -Egress $false -RuleNumber 100 -Protocol 17 -PortRange_From 53 -PortRange_To 53 -CidrBlock 203.0.113.12/24 -RuleAction allow
    Set-EC2NetworkAclEntry -NetworkAclId acl-12345678 -Egress $false -RuleNumber 100 -Protocol 17 -PortRange_From 53 -PortRange_To 53 -CidrBlock 203.0.113.12/24 -RuleAction allow

    Set-EC2NetworkAclAssociation -NetworkAclId $naclNetID -AssociationId aclassoc-1a2b3c4d

#>
#Get-EC2NetworkAcl
$Nacl = New-EC2NetworkAcl -vpcid $vpcID 
$naclNetID = $Nacl.NetworkAclId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Public NACL"
New-EC2Tag -Resource $naclNetID -Tag $tag
New-EC2NetworkAclEntry -NetworkAclId $naclNetID -Egress $false -RuleNumber 100 -Protocol 17 -PortRange_From 53 -PortRange_To 53 -CidrBlock 0.0.0.0/0 -RuleAction allow 


#Transit Gateways - Transit Gateway to route VPN traffic to on-prem subnet of 192.168.2.0/24 (declared in route table)
$newTransitGateway = New-EC2TransitGateway
$transitGateID = $newTransitGateway.TransitGatewayId 
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Transit Gateway"
New-EC2Tag -Resource $transitGateID -Tag $tag
    while((Get-EC2TransitGateway -TransitGatewayId $transitGateID).state.Value -contains 'notavailable')
        {
                Write-Host $transitGateID is (Get-EC2TransitGateway -TransitGatewayId $transitGateID).state.Value
            Start-Sleep 10
        }
        Start-Sleep 30    #still working on this, but looks like it reports as available before it is able to attach  

#Transit Gateway attachments - VPC to TG

# during testing the previous attachment is picked up and is in a deleting a state - add filter to exclude


#disabled - not required for testing\dev

$TranGateAttVPC = New-EC2TransitGatewayVpcAttachment -VpcId $vpcID -TransitGatewayId $transitGateID -SubnetId $SubPrivID
$TranGateAttVPCID = $TranGateAttVPC.TransitGatewayAttachmentId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Transit Gateway VPC Attachment to Private Subnet"    #make this a var
New-EC2Tag -Resource $TranGateAttVPCID -Tag $tag
start-sleep 10
    while((Get-EC2TransitGatewayAttachment -TransitGatewayAttachmentId $TranGateAttVPCID).state.Value -Notcontains 'available')
        {
                Write-Host $TranGateAttVPCID is (Get-EC2TransitGatewayAttachment -TransitGatewayAttachmentId $TranGateAttVPCID).state.Value
            Start-Sleep 10
        }

        Start-Sleep -Seconds 10
New-EC2Route -RouteTableId $Ec2RouteTablePub.RouteTableId -DestinationCidrBlock $transitRoute -TransitGatewayId $transitGateID

#no caps allowed in name
$news3Bucket = New-S3Bucket -BucketName "auto-domain-create-$($dateTodaySeconds)" -Force
$s3BucketName = $news3Bucket.BucketName
<#
    S3
    Write-S3Object -BucketName test-files -Folder .\Scripts -KeyPrefix SampleScripts\
    Write-S3Object -BucketName test-fi-les -Folder .\Scripts -KeyPrefix SampleScripts\ -SearchPattern *.ps1
#>

#Use this when running from native powershell
Write-S3Object -BucketName $s3BucketName Domain -Folder "$($pwdPath)\Domain" -Force

#Endpoints
<#
    New-EC2VpcEndpoint -ServiceName c-om.amazonaws.eu-west-1.s3 -VpcId vpc-

        com.amazonaws.us-east-1.s3
#> 
$newEnpointS3 = New-EC2VpcEndpoint -ServiceName com.amazonaws.us-east-1.s3 -RouteTableId $Ec2RouteTablePriv -VpcEndpointType Gateway -VpcId $vpcID 
$newEnpointS3ID = $newEnpointS3.VpcEndpoint.VpcEndpointId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - S3 Bucket Endpoing"
New-EC2Tag -Resource $newEnpointS3ID -Tag $tag

<#
    EC2 Instances
#>
#Search for the latest Srv 2022 Base
$gtSrv2022AMI = Get-SSMLatestEC2Image -Path ami-windows-latest -Region $region1 | 
    where {$_.name -match "2022" -and `
    $_.name -match "full-base"-and    `
    $_.name -match "English" -and     `
    $_.name -notmatch "TPM-"}

#Create an EC2 Instance - Private Instance
$new2022InstancePub = New-EC2Instance `
    -ImageId $gtSrv2022AMI.value `
    -MinCount 1 -MaxCount 1 `
    -KeyName $newKeyPair.KeyName `
    -SecurityGroupId $SecurityGroupPub `
    -InstanceType t1.micro `
    -SubnetId $SubPubID

$new2022InstancePubID = $new2022InstancePriv.Instances.InstanceId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Public RDP Jump Box to Private"
New-EC2Tag -Resource $new2022InstancePubID -Tag $tag    

#check for instance state

#Create an EC2 Instance - Private Instance
<#
    <powershell>
    Rename-Computer -NewName "Server044"
    Restart-Computer
    </powershell>
#>

$new2022InstancePriv = New-EC2Instance `
    -ImageId $gtSrv2022AMI.value `
    -MinCount 1 -MaxCount 1 `
    -KeyName $newKeyPair.KeyName `
    -SecurityGroupId $SecurityGroupPriv  `
    -InstanceType t1.micro `
    -SubnetId $SubPrivID 

    <#
    -UserDataFile "Add DC Promo Script here"
    #>

    $new2022InstancePrivID = $new2022InstancePriv.Instances.InstanceId
    $tag = New-Object Amazon.EC2.Model.Tag
    $tag.Key = "Name"
    $tag.Value = "$($cidr).32/27 - Private Domain Controller"
    New-EC2Tag -Resource $new2022InstancePrivID  -Tag $tag    

    #check for instance state

