$cidr = "10.94.0"
#VPC
$newVPC = new-ec2vpc -CidrBlock "$($cidr).0/24"
$vpdID = $newVPC.VpcId
$tagVPCValue = "VPCValue"
$tag=@()
$tags = New-Object Amazon.EC2.Model.Tag
$tags = @( @{key="Name";value="VPC $($cidr).0/24"}, `
           @{key="VPCTag";value="Some Tag Example"} )
New-EC2Tag -Resource $vpdID -Tag $tags 

#Subnets
$Ec2subnetPub = new-EC2Subnet -CidrBlock "$($cidr).0/27"  -VpcId $vpdID
$SubPubID = $ec2subnetPub.SubnetId
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).0/27 - Public Subnet"
New-EC2Tag -Resource $Ec2subnetPub.SubnetId -Tag $tag
Edit-EC2SubnetAttribute -SubnetId $ec2subnetPub.SubnetId -MapPublicIpOnLaunch $true

$Ec2subnetPriv = new-EC2Subnet -CidrBlock "$($cidr).32/27"  -VpcId $vpdID
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$($cidr).32/27 - Private Subnet"
New-EC2Tag -Resource $Ec2subnetPriv.SubnetId -Tag $tag

#Create Internet Gateway and attach it to the VPC
$Ec2InternetGateway = New-EC2InternetGateway
$InterGatewayID = $Ec2InternetGateway.InternetGatewayId
Add-EC2InternetGateway -InternetGatewayId $Ec2InternetGateway.InternetGatewayId -VpcId $vpdID
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "$cidr-InternetGateway"
New-EC2Tag -Resource $InterGatewayID -Tag $tag

#Create custom route table with route to the internet and associate it with the subnet
$Ec2RouteTable = New-EC2RouteTable -VpcId $vpdID
New-EC2Route -RouteTableId $Ec2RouteTable.RouteTableId -DestinationCidrBlock "0.0.0.0/0" -GatewayId $InterGatewayID
Register-EC2RouteTable -RouteTableId $Ec2RouteTable.RouteTableId -SubnetId $SubPubID 

#Create Security group and firewall rule for RDP
$SecurityGroup = New-EC2SecurityGroup -Description "Rempote Mgmt Ports" -GroupName "RemoteMgmtPorts" -VpcId $vpdID -Force
$tag = New-Object Amazon.EC2.Model.Tag
$tag.Key = "Name"
$tag.Value = "RemoteMgmtPorts"
New-EC2Tag -Resource $securityGroup -Tag $tag

#Inbound Rules
$InTCP22 = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="10.0.0.0/32" }
$InTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="10.0.0.0/32" }
#Outbound Rules
$EgTCP22 = @{ IpProtocol="tcp"; FromPort="5985"; ToPort="5986"; IpRanges="10.0.0.0/32" }
$EgTCP3389 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="10.0.0.0/32" }

Grant-EC2SecurityGroupIngress -GroupId $SecurityGroup -IpPermission @( $InTCP22, $InTCP3389 )
Grant-EC2SecurityGroupEgress -GroupId $SecurityGroup -IpPermission @( $EgTCP22, $EgTCP3389 )



#NACLs
