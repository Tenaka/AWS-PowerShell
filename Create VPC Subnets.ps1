$cidr = "10.99.1"

#VPC
<#
    Get-EC2Vpc -VpcId vpc-12345678
#>
$newVPC = new-ec2vpc -CidrBlock "$($cidr).0/24"
$vpdID = $newVPC.VpcId
$tagVPCValue = "VPCValue"
$tag=@()
$tags = New-Object Amazon.EC2.Model.Tag
$tags = @( @{key="Name";value="VPC $($cidr).0/24"}, `
           @{key="VPCTag";value="Some Tag Example"} )
New-EC2Tag -Resource $vpdID -Tag $tags 


#Subnets
<#
    New-EC2Subnet -VpcId vpc-12345678 -CidrBlock 10.0.0.0/24
    Get-EC2Subnet -SubnetId subnet-1a2b3c4d
#>
$Ec2subnetPub = New-EC2Subnet -CidrBlock "$($cidr).0/27"  -VpcId $vpdID
$SubPubID = $ec2subnetPub.SubnetId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Public Subnet"
New-EC2Tag -Resource $Ec2subnetPub.SubnetId -Tag $tag
###Edit-EC2SubnetAttribute -SubnetId $ec2subnetPub.SubnetId -MapPublicIpOnLaunch $true

$Ec2subnetPriv = new-EC2Subnet -CidrBlock "$($cidr).32/27"  -VpcId $vpdID
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
Add-EC2InternetGateway -InternetGatewayId $Ec2InternetGateway.InternetGatewayId -VpcId $vpdID
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$cidr-InternetGateway"
New-EC2Tag -Resource $InterGatewayID -Tag $tag


#Create custom route table with route to the internet and associate it with the subnet
<#
Get-EC2RouteTable -Filter @{ Name="vpc-id"; Values="vpc-1a2b3c4d" }
New-EC2Route -RouteTableId rtb-1a2b3c4d -DestinationCidrBlock 0.0.0.0/0 -GatewayId igw-1a2b3c4d
#>
#public Route
$Ec2RouteTable = New-EC2RouteTable -VpcId $vpdID -TagSpecification $tag
$Ec2RouteTableID = $Ec2RouteTable.RouteTableId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Public Route"
New-EC2Tag -Resource $Ec2RouteTableID -Tag $tag
New-EC2Route -RouteTableId $Ec2RouteTable.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $InterGatewayID
Register-EC2RouteTable -RouteTableId $Ec2RouteTable.RouteTableId -SubnetId $SubPubID 


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
$SecurityGroup = New-EC2SecurityGroup -Description "Rempote Mgmt Ports" -GroupName "RemoteMgmtPorts2" -VpcId $vpdID -Force
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "RemoteMgmtPorts"
New-EC2Tag -Resource $securityGroup -Tag $tag
#Inbound Rules
$InTCP22 = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="10.0.0.0/32"}
$InTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="10.0.0.0/32"}
Grant-EC2SecurityGroupIngress -GroupId $SecurityGroup -IpPermission @( $InTCP22, $InTCP3389 )
#Outbound Rules
$EgTCP22 = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="10.0.0.0/32" }
$EgTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="10.0.0.0/32" }
Grant-EC2SecurityGroupEgress -GroupId $SecurityGroup -IpPermission @( $EgTCP22, $EgTCP3389 )
#Remove the default any any outbound rule
$InRvDefault = @{ IpProtocol="-1"; FromPort="-1"; ToPort="-1"; IpRanges="0.0.0.0/0" }
Revoke-EC2SecurityGroupEgress -GroupId $SecurityGroup -IpPermission $InRvDefault



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
