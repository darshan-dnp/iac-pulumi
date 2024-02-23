package myproject;

import com.pulumi.Pulumi;
import com.pulumi.asset.FileArchive;
import com.pulumi.aws.AwsFunctions;
import com.pulumi.aws.autoscaling.GroupArgs;
import com.pulumi.aws.autoscaling.PolicyArgs;
import com.pulumi.aws.autoscaling.inputs.GroupLaunchTemplateArgs;
import com.pulumi.aws.autoscaling.inputs.GroupTagArgs;
import com.pulumi.aws.cloudwatch.MetricAlarm;
import com.pulumi.aws.cloudwatch.MetricAlarmArgs;
import com.pulumi.aws.dynamodb.Table;
import com.pulumi.aws.dynamodb.TableArgs;
import com.pulumi.aws.dynamodb.inputs.TableAttributeArgs;
import com.pulumi.aws.ec2.*;
import com.pulumi.aws.ec2.inputs.*;
import com.pulumi.aws.ec2.outputs.GetAmiResult;
import com.pulumi.aws.iam.*;
import com.pulumi.aws.iam.inputs.GetPolicyArgs;
import com.pulumi.aws.iam.inputs.GetPolicyDocumentArgs;
import com.pulumi.aws.iam.inputs.GetPolicyDocumentStatementArgs;
import com.pulumi.aws.iam.inputs.GetPolicyDocumentStatementPrincipalArgs;
import com.pulumi.aws.iam.outputs.GetPolicyResult;
import com.pulumi.aws.inputs.GetAvailabilityZonesArgs;
import com.pulumi.aws.lambda.*;
import com.pulumi.aws.lambda.inputs.FunctionEnvironmentArgs;
import com.pulumi.aws.lb.*;
import com.pulumi.aws.lb.inputs.ListenerDefaultActionArgs;
import com.pulumi.aws.lb.inputs.TargetGroupHealthCheckArgs;
import com.pulumi.aws.macie2.MemberArgs;
import com.pulumi.aws.outputs.GetAvailabilityZonesResult;
import com.pulumi.aws.rds.ParameterGroupArgs;
import com.pulumi.aws.rds.SubnetGroup;
import com.pulumi.aws.rds.SubnetGroupArgs;
import com.pulumi.aws.rds.inputs.ParameterGroupParameterArgs;
import com.pulumi.aws.route53.Record;
import com.pulumi.aws.route53.RecordArgs;
import com.pulumi.aws.route53.Route53Functions;
import com.pulumi.aws.route53.inputs.GetZoneArgs;
import com.pulumi.aws.route53.inputs.RecordAliasArgs;
import com.pulumi.aws.route53.outputs.GetZoneResult;
import com.pulumi.aws.secretsmanager.Secret;
import com.pulumi.aws.secretsmanager.SecretArgs;
import com.pulumi.aws.secretsmanager.SecretVersion;
import com.pulumi.aws.secretsmanager.SecretVersionArgs;
import com.pulumi.aws.sns.*;
import com.pulumi.core.Output;
import com.pulumi.aws.rds.ParameterGroup;
import com.pulumi.aws.iam.outputs.GetPolicyDocumentResult;
import com.pulumi.gcp.serviceaccount.Account;
import com.pulumi.gcp.serviceaccount.AccountArgs;
import com.pulumi.gcp.serviceaccount.Key;
import com.pulumi.gcp.serviceaccount.KeyArgs;
import com.pulumi.gcp.storage.Bucket;
import com.pulumi.gcp.storage.BucketArgs;
import com.pulumi.gcp.storage.BucketIAMBinding;
import com.pulumi.gcp.storage.BucketIAMBindingArgs;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.pulumi.codegen.internal.Serialization.*;

public class App {
    public static void main(String[] args) {
        Pulumi.run(ctx -> {
            var config = ctx.config();
            var data = config.requireObject("data", Map.class);

            var name = data.get("name");
            if(name == null || name.toString().isEmpty()){
                name = UUID.randomUUID().toString().replace("-","");
            }

            String vpcName = name.toString();
            var cidrBlock = data.get("cidr-block");
            if(cidrBlock == null || cidrBlock.toString().isEmpty()){
                cidrBlock = "10.0.0.0/16";
            }

            String cidr = cidrBlock.toString();
            var vpc = new Vpc(vpcName,
                    VpcArgs.builder()
                            .cidrBlock(cidr)
                            .enableDnsHostnames(Boolean.TRUE)
                            .instanceTenancy("default")
                            .tags(Map.of("name", vpcName))
                            .build()
                    );

            var totalSubnets = data.get("num_of_subnets");
            int totalSubnetNumber;
            if(totalSubnets == null || Double.parseDouble(totalSubnets.toString()) <= 0){
                totalSubnetNumber = 3;
            } else {
                totalSubnetNumber = (int) Double.parseDouble(totalSubnets.toString());
            }

            var pubCidr = data.get("public-cidr");
            if(null == pubCidr || pubCidr.toString().isEmpty()){
                pubCidr = "0.0.0.0/0";
            }

            Output<GetAvailabilityZonesResult> availabilityZonesResultOutput =
                    AwsFunctions.getAvailabilityZones(GetAvailabilityZonesArgs.builder().state("available").build());

            Object finalCidr = pubCidr;
            availabilityZonesResultOutput.applyValue(
                    getAvailabilityZonesResult -> {
                        int totalZones = getAvailabilityZonesResult.names().size();
                        List<String> allSubnets = getAllSubnets(cidr, totalZones*2);

                        List<Subnet> publicSubnets = createPublicSubNets(totalSubnetNumber,vpcName,vpc,getAvailabilityZonesResult.names(),totalZones,allSubnets);
                        List<Subnet> privateSubNets =createPrivateSubnets(totalSubnetNumber,vpcName,vpc,getAvailabilityZonesResult.names(),totalZones,allSubnets);

                        var internetGateway = new InternetGateway("my-igw",
                                InternetGatewayArgs.builder().vpcId(vpc.id())
                                        .tags(Map.of("name", vpcName + "_igw"))
                                        .build());

                        var publicRouteTable = new RouteTable(vpcName + "_PublicRouteTable",
                                RouteTableArgs.builder()
                                        .tags(Map.of("name", vpcName + "_PublicRouteTable"))
                                        .vpcId(vpc.id())
                                        .routes(RouteTableRouteArgs.builder()
                                                .cidrBlock(finalCidr.toString())
                                                .gatewayId(internetGateway.id())
                                                .build()
                                        )
                                        .build()
                                );

                        var privateRouteTable = new RouteTable(vpcName + "_PrivateRouteTable",
                                RouteTableArgs.builder()
                                        .tags(Map.of("name", vpcName + "_PrivateRouteTable"))
                                        .vpcId(vpc.id())
                                        .build()
                                );

                        int smallerNum = Math.min(totalSubnetNumber, totalZones);
                        for(int i=0; i<smallerNum; i++){
                            new RouteTableAssociation("PublicRouteTableAssociation_" + i,
                                    RouteTableAssociationArgs.builder()
                                            .subnetId(publicSubnets.get(i).id())
                                            .routeTableId(publicRouteTable.id())
                                            .build()
                                    );

                            new RouteTableAssociation("PrivateRouteTableAssociation_" + i,
                                    RouteTableAssociationArgs.builder()
                                            .subnetId(privateSubNets.get(i).id())
                                            .routeTableId(privateRouteTable.id())
                                            .build()
                                    );
                        }

                        List<String> publicSubnetIds = getSubnetIds(publicSubnets);
                        ctx.export("public-subnet-ids", Output.of(String.join(",", publicSubnetIds)));

                        List<String> privateSubnetIds = getSubnetIds(privateSubNets);
                        ctx.export("private-subnet-ids", Output.of(String.join(",", privateSubnetIds)));

                        SecurityGroup lbSecurityGroup = createLBSecGroup(vpc, data);

                        Output<String> secGroup = createSecGroup(vpc, data.get("public-cidr").toString());

                        SecurityGroup rdsSecGroup = createRDSSecGroup(vpc, secGroup);
                        ParameterGroup rdsParamGroup = createRDSParamGroup();

                        com.pulumi.aws.rds.Instance rdsDbInstance = createRDSInstance(privateSubNets, rdsSecGroup, rdsParamGroup, data);
                        ctx.export("rds-instance-id", rdsDbInstance.id());

                        Key key = createGCPResource(data);
                        Topic topic = createSNSTopic(data);
                        Table table = dynamoSetup(data);
                        setupLambda(topic, key, table, data);

                        LaunchTemplate launchTemplate = createLaunchTemplate(privateSubNets, rdsDbInstance, data, secGroup, topic);
                        TargetGroup targetGroup = createTargetGroup(vpc);
                        LoadBalancer loadBalancer = createLoadBalancer(vpc, data, targetGroup, publicSubnets, lbSecurityGroup);
                        createAutoScalingGroup(launchTemplate, vpc, targetGroup, publicSubnets, data);

//                        Instance instance = createEC2Instance(vpcName, secGroup, publicSubnets.get(0),data, rdsDbInstance);
//                        ctx.export("EC2-instance-id", instance.id());

//                        Eip ec2Eip = createEip(instance);
//                        Record aRecord = createARecord(ec2Eip, data);

                        createLBARecord(data, loadBalancer);


                        return null;
                    }
            );
            ctx.export("vpc-id", vpc.id());
        });
    }

    public static com.pulumi.aws.rds.Instance createRDSInstance(List<Subnet> privateSubnetIds, SecurityGroup rdsSecGroup, ParameterGroup rdsParamGroup, Map<String,Object> data){

        List<Output<String>> subnetIds = new ArrayList<>();
        for (Subnet subnet : privateSubnetIds) {
            subnetIds.add(subnet.id());
        }

        Output<List<String>> subnetIdsOutput = Output.all(subnetIds).applyValue(ids -> ids);
        SubnetGroup subnetGroup = new SubnetGroup("private-subnet-group",
                SubnetGroupArgs.builder()
                        .subnetIds(subnetIdsOutput)
                        .description("Subnet group to access db.")
                        .build());

        List<Output<String>> rdsSecGroupId = new ArrayList<>();
        rdsSecGroupId.add(rdsSecGroup.id());
        Output<List<String>> rdsSecGroupOutput = Output.all(rdsSecGroupId).applyValue(ids -> ids);

        Output<String> subnetGroupName = subnetGroup.name();

        return new com.pulumi.aws.rds.Instance("rds-instance", com.pulumi.aws.rds.InstanceArgs.builder()
                .engine("mariadb")
                .allocatedStorage(20)
                .engineVersion("10.5")
                .instanceClass("db.t2.micro")
                .storageType("gp2")
                .multiAz(false)
                .identifier("csye6225")
                .username(data.get("DB_USER").toString())
                .password(data.get("DB_PASS").toString())
                .dbSubnetGroupName(subnetGroupName)
                .publiclyAccessible(false)
                .dbName(data.get("DB_NAME").toString())
                .vpcSecurityGroupIds(rdsSecGroupOutput)
                .parameterGroupName(rdsParamGroup.name())
                .skipFinalSnapshot(true)
                .build());
    }

    public static ParameterGroup createRDSParamGroup(){
        return new ParameterGroup("rds-param-group", ParameterGroupArgs.builder()
                .description("RDS Parameter Group for MariaDB 10.5")
                .family("mariadb10.5")
                .parameters(
                        ParameterGroupParameterArgs.builder()
                                .name("max_connections")
                                .value("1000")
                                .build())
                .build());
    }

    public static Output<String> createSecGroup(Vpc vpc, String cidrBlock){
        List<SecurityGroupIngressArgs> securityGroupIngressArgs = new ArrayList<>();
        securityGroupIngressArgs.add(SecurityGroupIngressArgs.builder()
                .fromPort(22)
                .toPort(22)
                .protocol("tcp")
                .cidrBlocks(cidrBlock).build());
        securityGroupIngressArgs.add(SecurityGroupIngressArgs.builder()
                .fromPort(8080)
                .toPort(8080)
                .protocol("tcp")
                .cidrBlocks(cidrBlock).build());

        List<SecurityGroupEgressArgs> securityGroupEgressArgs = new ArrayList<>();
        securityGroupEgressArgs.add(SecurityGroupEgressArgs.builder()
                .fromPort(443)
                .toPort(443)
                .protocol("tcp")
                .cidrBlocks(cidrBlock)
                .build());

        var appSecGroup = new SecurityGroup("ApplicationSecurityGroup",
                SecurityGroupArgs.builder()
                        .description("EC2 Sec Group")
                        .vpcId(vpc.id())
                        .ingress(securityGroupIngressArgs)
                        .egress(securityGroupEgressArgs)
                .build());
        return appSecGroup.id();
    }

    public static SecurityGroup createRDSSecGroup(Vpc vpc, Output<String> id){
        var appSecGroup = new SecurityGroup("DatabaseSecurityGroup",
                SecurityGroupArgs.builder()
                        .description("RDS Sec Group")
                        .vpcId(vpc.id())
                        .build());

        new SecurityGroupRule("DatabaseSecurityGroupRule", new SecurityGroupRuleArgs.Builder()
                .securityGroupId(appSecGroup.id())
                .type("ingress")
                .sourceSecurityGroupId(id)
                .description("Allow traffic only from webapp sec group.")
                .fromPort(3306)
                .toPort(3306)
                .protocol("tcp")
                .build());

        new SecurityGroupRule("DatabaseSecurityGroupRuleEgress", new SecurityGroupRuleArgs.Builder()
                .securityGroupId(appSecGroup.id())
                .type("egress")
                .fromPort(3306)
                .toPort(3306)
                .protocol("tcp")
                .sourceSecurityGroupId(appSecGroup.id())
                .securityGroupId(id)
                .build());

        return appSecGroup;
    }

    public static Instance createEC2Instance(String vpcName,Output<String> appSecGroupID, Subnet subnet,Map<String,Object> data, com.pulumi.aws.rds.Instance rdsDbInstance) {
        Double volume = (Double) data.get("volume");

        Role cldWtchRole = new Role("CLD_WTCH_EC2_ROLE", new RoleArgs.Builder()
                .assumeRolePolicy(serializeJson(
                        jsonObject(
                                jsonProperty("Version", "2012-10-17"),
                                jsonProperty("Statement", jsonArray(jsonObject(
                                        jsonProperty("Action", "sts:AssumeRole"),
                                        jsonProperty("Effect", "Allow"),
                                        jsonProperty("Principal",
                                                jsonObject(
                                                        jsonProperty("Service", "ec2.amazonaws.com")
                                                )
                                        )))
                                )
                        )
                ))
                .build());

        new RolePolicyAttachment("CLD_WTCH_AGNT_PLCY", new RolePolicyAttachmentArgs.Builder()
                .policyArn("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")
                .role(cldWtchRole.id())
                .build()
        );

        new RolePolicyAttachment("CLD_WTCH_ADMN_PLCY", new RolePolicyAttachmentArgs.Builder()
                .policyArn("arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy")
                .role(cldWtchRole.id())
                .build()
        );

        InstanceProfile instanceProfile = new InstanceProfile("CLD_WTCH_INST_PRFL", new InstanceProfileArgs.Builder()
                .role(cldWtchRole.id())
                .build()
        );

        InstanceEbsBlockDeviceArgs instanceEbsBlockDeviceArgs = InstanceEbsBlockDeviceArgs.builder()
                .deviceName("/dev/xvda")
                .volumeType("gp2")
                .deleteOnTermination(true)
                .volumeSize(volume.intValue())
                .build();

        final var latestAMI = Ec2Functions.getAmi(
                GetAmiArgs.builder()
                        .mostRecent(true)
                        .owners(data.get("owner_id").toString())
                        .filters(GetAmiFilterArgs.builder()
                                .name("name")
                                .values("webapp*")
                                .build())
                        .build()
        );

        InstanceArgs.Builder insBuilder = InstanceArgs.builder();
        insBuilder.ami(latestAMI.applyValue(GetAmiResult::id));

        String port = data.get("DB_PORT").toString();
        String dbName = data.get("DB_NAME").toString();
        String username = data.get("DB_USER").toString();
        String password = data.get("DB_PASS").toString();


        Output<String> userData = rdsDbInstance.address().applyValue(v -> String.format(
                        "#!/bin/bash\n" +
                        "mkdir /opt/webapp\n" +
                        "touch /opt/webapp/.env\n" +
                        "echo \"DB_HOST=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_USER=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_NAME=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_PASS=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_PORT=%s\" >> /opt/webapp/.env\n" +
                        "chown admin /opt/webapp/.env\n",
                v,
                username,
                dbName,
                password,
                port
        ));

        return new Instance(vpcName+"_Instance",
                insBuilder.instanceType(data.get("instance_type").toString())
                        .subnetId(subnet.id())
                        .ebsBlockDevices(instanceEbsBlockDeviceArgs)
                        .keyName(data.get("key_name").toString())
                        .userData(userData)
                        .associatePublicIpAddress(true)
                        .disableApiTermination(false)
                        .vpcSecurityGroupIds(appSecGroupID.applyValue(Collections::singletonList))
                        .iamInstanceProfile(instanceProfile.name())
                        .build()
        );
    }

    public static Eip createEip(Instance ec2Instance){
        Eip elasticIp = new Eip("WEBAPP_EC2_EIP", new EipArgs.Builder()
                .domain("vpc")
                .build()
        );

        EipAssociation eipAssociation = new EipAssociation("WEBAPP_EC2_EIP_ASN", new EipAssociationArgs.Builder()
                .instanceId(ec2Instance.id())
                .publicIp(elasticIp.publicIp())
                .build()
        );
        return elasticIp;
    }

    public static Record createARecord(Eip eip, Map<String,Object> data){
        return new Record("EC2_ARECORD", RecordArgs.builder()
                .zoneId(data.get("hosted_zone").toString())
                .name(data.get("dns_name").toString())
                .records(eip.publicIp().applyValue(Collections::singletonList))
                .type("A")
                .ttl(60)
                .build()
        );
    }

    public static List<Subnet> createPublicSubNets(int totalSubnets,String vpcName,Vpc vpc,List<String> zones, int totalZones,List<String> subnets){
        List<Subnet> publicSubnets = new ArrayList<>();

        int smallerNum = Math.min(totalSubnets, totalZones);
        for(int i=0; i<smallerNum; i++){
            String subnetName = vpcName + "_public_" + i;
            var publicSubnet = new Subnet(subnetName,
                    SubnetArgs.builder()
                            .cidrBlock(subnets.get(i))
                            .vpcId(vpc.id())
                            .availabilityZone(zones.get(i))
                            .mapPublicIpOnLaunch(true)
                            .tags(Map.of("name", subnetName))
                            .tags(Map.of("type", "public"))
                            .build()
            );
            publicSubnets.add(publicSubnet);
        }
        return publicSubnets;
    }

    public static List<String> getSubnetIds(List<Subnet> subnets){
        List<String> subnetIds = new ArrayList<>();
        for(Subnet subnet : subnets){
            subnetIds.add(subnet.id().toString());
        }
        return subnetIds;
    }

    public static List<Subnet> createPrivateSubnets(int totalSubnets,String vpcName,Vpc vpc,List<String> zones, int totalZones,List<String> subnets){
        List<Subnet> privateSubnets = new ArrayList<>();
        int smallerNum = Math.min(totalSubnets, totalZones);

        for(int i=0; i<smallerNum; i++){
            String subnetName = vpcName + "_private_" + i;
            Subnet privateSubnet = new Subnet(subnetName,
                    SubnetArgs.builder()
                            .cidrBlock(subnets.get(i+smallerNum))
                            .vpcId(vpc.id())
                            .availabilityZone(zones.get(i))
                            .tags(Map.of("name", subnetName))
                            .tags(Map.of("type", "private"))
                            .build()
            );
            privateSubnets.add(privateSubnet);
        }
        return privateSubnets;
    }

    public static List<String> getAllSubnets(String cidr, int totalZones){
        try {
            InetAddress inetAddress = Inet4Address.getByName(cidr.split("/")[0]);
            int cidrPrefixLen = Integer.parseInt(cidr.split("/")[1]);
            int subnetPrefixLen = cidrPrefixLen + (int) Math.ceil(Math.log(totalZones)/Math.log(2));
            int availableAddress = 32 - subnetPrefixLen;

            List<String> allSubnets = new ArrayList<>();
            for(int i=0; i<totalZones; i++){
                int size = (int) Math.pow(2, availableAddress);
                allSubnets.add(inetAddress.getHostAddress() + "/" + subnetPrefixLen);
                inetAddress = InetAddress.getByName(setOffset(inetAddress.getHostAddress(), size));
            }
            return allSubnets;
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String setOffset(String ipAddress, int offset) throws UnknownHostException {
        InetAddress inetAddress = Inet4Address.getByName(ipAddress);
        byte[] bytes = inetAddress.getAddress();

        int offsetVal = 0;
        for (byte b : bytes) {
            offsetVal = (offsetVal << 8) | (b & 0xff);
        }

        offsetVal += offset;
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) ((offsetVal >> (24 - i * 8)) & 0xff);
        }
        return InetAddress.getByAddress(bytes).getHostAddress();
    }

    public static SecurityGroup createLBSecGroup(Vpc vpc, Map<String, Object> data){
        List<Double> lbPorts = (List<Double>) data.get("lb_ports");

        List<SecurityGroupIngressArgs> securityGroupIngressArgs = new ArrayList<>();
        for(Double port : lbPorts){
            securityGroupIngressArgs.add(SecurityGroupIngressArgs.builder()
                        .fromPort(port.intValue())
                        .toPort(port.intValue())
                        .protocol("tcp")
                        .cidrBlocks(data.get("public-cidr").toString())
                    .build());
        }

        List<SecurityGroupEgressArgs> securityGroupEgressArgs = new ArrayList<>();
        securityGroupEgressArgs.add(SecurityGroupEgressArgs.builder()
                        .fromPort(0)
                        .toPort(0)
                        .protocol("-1")
                        .cidrBlocks(data.get("public-cidr").toString())
                .build());

        return new SecurityGroup("LOAD_BALANCER_SEC_GRP",
                SecurityGroupArgs.builder()
                        .vpcId(vpc.id())
                        .ingress(securityGroupIngressArgs)
                        .egress(securityGroupEgressArgs)
                        .build());
    }

    public static LaunchTemplate createLaunchTemplate(List<Subnet> privateSubs, com.pulumi.aws.rds.Instance rdsInst, Map<String, Object> data, Output<String> secGroup, Topic topic){
        Double volumeSize = (Double) data.get("volume");
        var recentAMI = Ec2Functions.getAmi(
                GetAmiArgs.builder()
                        .mostRecent(true)
                        .owners(data.get("owner_id").toString())
                        .filters(GetAmiFilterArgs.builder()
                                .name("name")
                                .values("webapp*")
                                .build())
                        .build()
        );

        String port = data.get("DB_PORT").toString();
        String dbName = data.get("DB_NAME").toString();
        String username = data.get("DB_USER").toString();
        String password = data.get("DB_PASS").toString();
        String sysVal1 = System.getenv("AWS_ACCESS_KEY");
        String sysVal2 = System.getenv("AWS_SECRET_KEY");

        Output<String> userData = Output.all(rdsInst.address(), topic.arn()).applyValue(args -> String.format(
                "#!/bin/bash\n" +
                        "mkdir /opt/webapp\n" +
                        "touch /opt/webapp/.env\n" +
                        "echo \"DB_HOST=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_USER=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_NAME=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_PASS=%s\" >> /opt/webapp/.env\n" +
                        "echo \"DB_PORT=%s\" >> /opt/webapp/.env\n" +
                        "echo \"TOPIC_ARN=%s\" >> /opt/webapp/.env\n" +
                        "echo \"AWS_ACCESS_KEY=%s\" >> /opt/webapp/.env\n" +
                        "echo \"AWS_SECRET_KEY=%s\" >> /opt/webapp/.env\n" +
                        "chown admin /opt/webapp/.env\n",
                args.get(0),
                username,
                dbName,
                password,
                port,
                args.get(1),
                sysVal1,
                sysVal2

        ));

        LaunchTemplateArgs.Builder builder = LaunchTemplateArgs.builder();
        builder.imageId(recentAMI.applyValue(GetAmiResult::id));
        builder.keyName(data.get("key_name").toString());
        builder.instanceType(data.get("instance_type").toString());
        builder.vpcSecurityGroupIds(secGroup.applyValue(Collections::singletonList));

        Output<String> encodedUserData = userData.applyValue(s -> Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)));
        builder.userData(encodedUserData);

        Output<GetPolicyResult> cloudWatchAgentServerPolicy = IamFunctions.getPolicy(GetPolicyArgs.builder()
                .name("CloudWatchAgentServerPolicy")
                .build());

        Output<GetPolicyResult> amazonSSMManagedInstanceCore = IamFunctions.getPolicy(GetPolicyArgs.builder()
                .name("AmazonSSMManagedInstanceCore")
                .build());

        Output<GetPolicyResult> amazonEC2RoleforSSM = IamFunctions.getPolicy(GetPolicyArgs.builder()
                .name("AmazonEC2RoleforSSM")
                .build());

        var assumeRole = IamFunctions.getPolicyDocument(GetPolicyDocumentArgs.builder()
                .statements(GetPolicyDocumentStatementArgs.builder()
                        .effect("Allow")
                        .principals(GetPolicyDocumentStatementPrincipalArgs.builder()
                                .type("Service")
                                .identifiers("ec2.amazonaws.com")
                                .build())
                        .actions("sts:AssumeRole")
                        .build())
                .build());

        var cldWtchRole = new Role("CLD_WTCH_ROLE", RoleArgs.builder()
                .assumeRolePolicy(assumeRole.applyValue(GetPolicyDocumentResult::json))
                .tags(Map.of("name","CLD_WTCH_ROLE"))
                .build());

        RolePolicyAttachment rolePolicyAttachment1 = new RolePolicyAttachment("CLD_WTCH_PLCY_ATCH_1",
                RolePolicyAttachmentArgs.builder()
                        .role(cldWtchRole.name())
                        .policyArn(cloudWatchAgentServerPolicy.applyValue(GetPolicyResult::arn))
                        .build());

        RolePolicyAttachment rolePolicyAttachment2 = new RolePolicyAttachment("CLD_WTCH_PLCY_ATCH_2",
                RolePolicyAttachmentArgs.builder()
                        .role(cldWtchRole.name())
                        .policyArn(amazonSSMManagedInstanceCore.applyValue(GetPolicyResult::arn))
                        .build());

        RolePolicyAttachment rolePolicyAttachment3 = new RolePolicyAttachment("CLD_WTCH_PLCY_ATCH_3",
                RolePolicyAttachmentArgs.builder()
                        .role(cldWtchRole.name())
                        .policyArn(amazonEC2RoleforSSM.applyValue(GetPolicyResult::arn))
                        .build());

        InstanceProfile instanceProfile = new InstanceProfile("INSTANCE_PROFILE",
                InstanceProfileArgs.builder()
                        .role(cldWtchRole.id())
                        .build());

        builder.blockDeviceMappings(LaunchTemplateBlockDeviceMappingArgs.builder()
                        .deviceName("/dev/xvda")
                        .ebs(
                                LaunchTemplateBlockDeviceMappingEbsArgs.builder()
                                        .volumeSize(volumeSize.intValue())
                                        .volumeType("gp2")
                                        .deleteOnTermination(String.valueOf(true))
                                        .build())
                        .build());

        builder.iamInstanceProfile(LaunchTemplateIamInstanceProfileArgs.builder()
                        .arn(instanceProfile.arn())
                        .build());

        builder.disableApiTermination(false);

        builder.tagSpecifications(LaunchTemplateTagSpecificationArgs.builder()
                .resourceType("instance")
                .tags(Map.of("Name","LAUNCH_TEMPLATE"))
                .build());

        return new LaunchTemplate("LAUNCH_TEMPLATE", builder.build());
    }

    public static TargetGroup createTargetGroup(Vpc vpc){
        return new TargetGroup("TARGET-GROUP",TargetGroupArgs.builder()
                .port(8080)
                .protocol("HTTP")
                .vpcId(vpc.id())
                .healthCheck(TargetGroupHealthCheckArgs.builder()
                        .enabled(true)
                        .healthyThreshold(3)
                        .interval(30)
                        .matcher("200")
                        .path("/healthz")
                        .port("8080")
                        .protocol("HTTP")
                        .timeout(5)
                        .unhealthyThreshold(3)
                        .build())
                .build());
    }

    public static LoadBalancer createLoadBalancer(Vpc vpc, Map<String,Object> data, TargetGroup targetGroup, List<Subnet> publicSubNets, SecurityGroup lbSecurityGroup){
        List<Output<String>> subnetIds = new ArrayList<>();
        for (Subnet subnet : publicSubNets) {
            subnetIds.add(subnet.id());
        }
        Output<List<String>> subnetIdsOutput = Output.all(subnetIds).applyValue(ids -> ids);

        LoadBalancer loadBalancer = new LoadBalancer("LOAD-BALANCER",
                LoadBalancerArgs.builder()
                        .internal(false)
                        .ipAddressType("ipv4")
                        .loadBalancerType("application")
                        .tags(Map.of("name", "LOAD-BALANCER"))
                        .securityGroups(lbSecurityGroup.id().applyValue(Collections::singletonList))
                        .subnets(subnetIdsOutput)
                        .build());

        Listener listener = new Listener("HTTPS-LISTNER", ListenerArgs.builder()
                .loadBalancerArn(loadBalancer.arn())
                .port(443)
                .protocol("HTTPS")
                .certificateArn(data.get("CERTIFICATE_ARN").toString())
                .defaultActions(ListenerDefaultActionArgs.builder()
                        .type("forward")
                        .targetGroupArn(targetGroup.arn())
                        .build())
                .build());

        return loadBalancer;
    }

    public static void createAutoScalingGroup(LaunchTemplate launchTemplate, Vpc vpc, TargetGroup targetGroup, List<Subnet> publicSubnets, Map<String,Object> data){
        List<Output<String>> subnetIds = new ArrayList<>();
        for (Subnet subnet : publicSubnets) {
            subnetIds.add(subnet.id());
        }
        Output<List<String>> subnetIdsOutput = Output.all(subnetIds).applyValue(ids -> ids);

        com.pulumi.aws.autoscaling.Group group = new com.pulumi.aws.autoscaling.Group("AUTO_SCALING_GROUP",
                GroupArgs.builder()
                        .minSize(1)
                        .maxSize(3)
                        .healthCheckType("ELB")
                        .healthCheckGracePeriod(300)
                        .forceDelete(false)
                        .metricsGranularity("1Minute")
                        .terminationPolicies(Collections.singletonList("OldestInstance"))
                        .vpcZoneIdentifiers(subnetIdsOutput)
                        .targetGroupArns(targetGroup.arn().applyValue(Collections::singletonList))
                        .tags(GroupTagArgs.builder()
                                .propagateAtLaunch(true)
                                .key("name")
                                .value("AUTO_SCALING_GROUP")
                                .build(),
                                GroupTagArgs.builder()
                                        .propagateAtLaunch(true)
                                        .key("project")
                                        .value("webapp")
                                        .build()
                                )
                        .launchTemplate(GroupLaunchTemplateArgs.builder()
                                .id(launchTemplate.id())
                                .build())
                        .build()
                );

        com.pulumi.aws.autoscaling.Policy scaleUpPolicy = new com.pulumi.aws.autoscaling.Policy("SCL_UP_POLICY",
                PolicyArgs.builder()
                        .scalingAdjustment(1)
                        .adjustmentType("ChangeInCapacity")
                        .policyType("SimpleScaling")
                        .cooldown(300)
                        .autoscalingGroupName(group.name())
                        .build()
                );

        com.pulumi.aws.autoscaling.Policy scaleDownPolicy = new com.pulumi.aws.autoscaling.Policy("SCL_DWN_POLICY",
                PolicyArgs.builder()
                        .scalingAdjustment(-1)
                        .adjustmentType("ChangeInCapacity")
                        .policyType("SimpleScaling")
                        .cooldown(300)
                        .autoscalingGroupName(group.name())
                        .build()
                );

        MetricAlarm metricAlarmUp = new MetricAlarm("SCL_UP_ALARM", MetricAlarmArgs.builder()
                .alarmDescription("CPU High.")
                .comparisonOperator("GreaterThanOrEqualToThreshold")
                .evaluationPeriods(2)
                .metricName("CPUUtilization")
                .namespace("AWS/EC2")
                .period(60)
                .statistic("Average")
                .threshold(5.0)
                .alarmActions(scaleUpPolicy.arn().applyValue(Collections::singletonList))
                .dimensions(group.name().applyValue(name -> Map.of("GroupName", name)))
                .build());

        MetricAlarm metricAlarmDown = new MetricAlarm("SCL_DWN_ALARM", MetricAlarmArgs.builder()
                .alarmDescription("CPU Low.")
                .comparisonOperator("LessThanOrEqualToThreshold")
                .evaluationPeriods(2)
                .metricName("CPUUtilization")
                .namespace("AWS/EC2")
                .period(60)
                .statistic("Average")
                .threshold(3.0)
                .alarmActions(scaleDownPolicy.arn().applyValue(Collections::singletonList))
                .dimensions(group.name().applyValue(name -> Map.of("GroupName", name)))
                .build());
    }

    public static void createLBARecord(Map<String, Object> data, LoadBalancer loadBalancer){
        var zoneId = Route53Functions.getZone(GetZoneArgs.builder()
                        .name(data.get("dns_name").toString())
                        .privateZone(false)
                .build());

        var aliasLoadBalancer = new Record("ALIAS_LOAD_BALANCER", RecordArgs.builder()
                .zoneId(zoneId.applyValue(GetZoneResult::zoneId))
                .name(data.get("dns_name").toString())
                .type("A")
                .aliases(RecordAliasArgs.builder()
                        .name(loadBalancer.dnsName())
                        .zoneId(loadBalancer.zoneId())
                        .evaluateTargetHealth(true)
                        .build())
                .build());
    }

    public static Key createGCPResource(Map<String, Object> data){
        Bucket bucket = new Bucket("my-bucket", BucketArgs.builder()
                .project(data.get("gcp_project_id").toString())
                .forceDestroy(true)
                .location("US")
                .build());

        Account account = new Account("GCP_SERVICE_ACC", AccountArgs.builder()
                .accountId("my-service-account-id")
                .project(data.get("gcp_project_id").toString())
                .displayName("Service Account")
                .build());

        Key key = new Key("GCP_SERVICE_ACC_KEY", KeyArgs.builder()
                .serviceAccountId(account.name())
                .publicKeyType("TYPE_X509_PEM_FILE")
                .build());

        var bucketIAMBinding = new BucketIAMBinding("bucket-iam-binding", BucketIAMBindingArgs.builder()
                .bucket(bucket.name())
                .role("roles/storage.objectAdmin")
                .members("allUsers")
                .build());

        data.put("BUCKET_NAME", bucket.name());

        return key;
    }

    public static Topic createSNSTopic(Map<String, Object> data){
        Topic topic = new Topic("SNS_TOPIC", TopicArgs.builder()
                .build());

        var snsRole = new Role("SNS_ROLE", RoleArgs.builder()
                .assumeRolePolicy(serializeJson(
                        jsonObject(
                                jsonProperty("Version", "2012-10-17"),
                                jsonProperty("Statement", jsonArray(jsonObject(
                                        jsonProperty("Action", "sts:AssumeRole"),
                                        jsonProperty("Effect", "Allow"),
                                        jsonProperty("Sid", ""),
                                        jsonProperty("Principal", jsonObject(
                                                jsonProperty("Service", "ec2.amazonaws.com")
                                        ))
                                )))
                        )))
                .tags(Map.of("name", "SNS_ROLE"))
                .build());

        var topicPolicy = new TopicPolicy("SNS_POLICY", TopicPolicyArgs.builder()
                .arn(topic.arn())
                .policy(topic.arn().applyValue(v -> String.format(
                                "{%n" +
                                "    \"Version\":\"2012-10-17\",%n" +
                                "    \"Statement\":[{%n" +
                                "        \"Effect\":\"Allow\",%n" +
                                "        \"Principal\":{%n" +
                                "            \"AWS\":\"*\"%n" +
                                "        },%n" +
                                "        \"Action\":\"sns:Publish\",%n" +
                                "        \"Resource\":\"%s\"%n" +
                                "    }]%n" +
                                "}", v
                )))
                .build());

        return topic;
    }

    public static Table dynamoSetup(Map<String,Object> data){
        var table = new Table("EMAIL_TABLE", TableArgs.builder()
                .name("EMAIL_TABLE")
                .attributes(TableAttributeArgs.builder()
                        .name("ID")
                        .type("S")
                        .build())
                .hashKey("ID")
                .readCapacity(5)
                .writeCapacity(5)
                .tags(Map.ofEntries(
                        Map.entry("Name", "EMAIL_TABLE")
                ))
                .build());
        data.put("DYNAMODB_TABLE_NAME", table.name());
        return table;
    }

    public static void setupLambda(Topic topic, Key key, Table table, Map<String, Object> data){
        var lambdaRole = new Role("LAMBDA_ROLE", RoleArgs.builder()
                .assumeRolePolicy(serializeJson(
                        jsonObject(
                                jsonProperty("Version", "2012-10-17"),
                                jsonProperty("Statement", jsonArray(jsonObject(
                                        jsonProperty("Action", "sts:AssumeRole"),
                                        jsonProperty("Effect", "Allow"),
                                        jsonProperty("Principal", jsonObject(
                                                jsonProperty("Service", "lambda.amazonaws.com")
                                        ))
                                )))
                        )))
                .build());

        new RolePolicyAttachment("LAMBDA_ROLE_ATCHMENT", new RolePolicyAttachmentArgs.Builder()
                .policyArn("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
                .role(lambdaRole.id())
                .build());

        var dynamoBDPolicy = new Policy("DYNAMODB_POLICY", com.pulumi.aws.iam.PolicyArgs.builder()
                .policy(serializeJson(
                        jsonObject(
                                jsonProperty("Version", "2012-10-17"),
                                jsonProperty("Statement", jsonArray(jsonObject(
                                        jsonProperty("Action", jsonArray(
                                                "dynamodb:GetItem",
                                                        "dynamodb:PutItem",
                                                        "dynamodb:UpdateItem",
                                                        "dynamodb:DeleteItem")),
                                        jsonProperty("Effect", "Allow"),
                                        jsonProperty("Resource", "*")
                                )))
                        )))
                .build());

        new RolePolicyAttachment("DYNAMODB_ROLE_ATCHMENT", new RolePolicyAttachmentArgs.Builder()
                .policyArn(dynamoBDPolicy.arn())
                .role(lambdaRole.id())
                .build());

        var secret = new Secret("GCP_SA_SECRET_3", SecretArgs.builder()
                .name("GCP_SA_SECRET_3")
                .recoveryWindowInDays(0)
                .forceOverwriteReplicaSecret(true)
                .build());

        var policy = new Policy("SECRET_MANAGER_POLICY", com.pulumi.aws.iam.PolicyArgs.builder()
                .description("IAM policy for Lambda to access secrets.")
                .policy(secret.arn().applyValue(v -> String.format(
                        "{%n" +
                                "    \"Version\":\"2012-10-17\",%n" +
                                "    \"Statement\":[{%n" +
                                "        \"Effect\":\"Allow\",%n" +
                                "        \"Action\":\"secretsmanager:GetSecretValue\",%n" +
                                "        \"Resource\":\"%s\"%n" +
                                "    }]%n" +
                                "}", v
                )))
                .build());

        new RolePolicyAttachment("LAMBDAROLE_SECRET_ATCHMNT", new RolePolicyAttachmentArgs.Builder()
                .policyArn(policy.arn())
                .role(lambdaRole.id())
                .build());

        var secretVersion = new SecretVersion("SERVICE_ACC_SEC_VER", SecretVersionArgs.builder()
                .secretId(secret.id())
                .secretString(key.privateKey())
                .build());

        Output<String> bucketName = (Output<String>) data.get("BUCKET_NAME");
        Output<Map<String, String>> envvariables = Output.all(bucketName).applyValue(args -> {
            Map<String, String> tempEnv = new HashMap<>();
            tempEnv.put("PROJECT_ID", data.get("gcp_project_id").toString());
            tempEnv.put("GOOGLE_BUCKET_NAME", args.get(0));
            tempEnv.put("EMAIL_API", "061a0e27e36befb6a0a144522fcef59a-0a688b4a-63d239a9");
            tempEnv.put("MAIL_DOMAIN", data.get("dns_name").toString());
            tempEnv.put("TABLE_NAME", "EMAIL_TABLE");
            tempEnv.put("PATH", "Submissions/");
            tempEnv.put("EMAIL_LIST", data.get("EMAIL_LIST").toString());
            return tempEnv;
        });

        Function function = new Function("LAMBDA_FUNCTION", FunctionArgs.builder()
                .name("SNS")
                .runtime("python3.9")
                .handler("lambda_function.lambda_handler")
                .role(lambdaRole.arn())
                .code(new FileArchive("my_deployment_package.zip"))
                .timeout(300)
                .environment(FunctionEnvironmentArgs.builder()
                        .variables(envvariables)
                        .build())
                .build());

        Permission permission = new Permission("LAMBDA_FUNCTION_PERM", PermissionArgs.builder()
                .action("lambda:InvokeFunction")
                .function(function.name())
                .principal("sns.amazonaws.com")
                .sourceArn(topic.arn())
                .build());

        TopicSubscription topicSubscription = new TopicSubscription("WEBAPP_SUB", TopicSubscriptionArgs.builder()
                .topic(topic.arn())
                .protocol("lambda")
                .endpoint(function.arn())
                .build());
    }
}
