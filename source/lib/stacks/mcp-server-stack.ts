import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as ssm from "aws-cdk-lib/aws-ssm";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import { McpFargateServerConstruct } from "../constructs/mcp-fargate-server-construct";
import { McpAuthFargateServerConstruct } from "../constructs/mcp-auth-fargate-server-construct";
import { NagSuppressions } from "cdk-nag";
import { McpLambdaServerlessConstruct } from "../constructs/mcp-lambda-serverless-construct";
import { getAllowedCountries } from "../constants/geo-restrictions";

export interface MCPServerStackProps extends cdk.StackProps {
  /**
   * Suffix to append to resource names
   */
  resourceSuffix: string;
  vpc: ec2.IVpc;
  cognitoUserPool: cognito.UserPool;
  userPoolClientId: string;
  userPoolClientSecret: cdk.SecretValue;
}

/**
 * Combined stack for MCP platform and servers to avoid circular dependencies
 */
export class MCPServerStack extends cdk.Stack {
  public readonly albSecurityGroup: ec2.SecurityGroup;
  public readonly loadBalancer: elbv2.ApplicationLoadBalancer;
  public readonly cluster: ecs.Cluster;
  public readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props: MCPServerStackProps) {
    super(scope, id, props);

    // Get CloudFront WAF ARN from SSM (written by CloudFrontWafStack)
    const cloudFrontWafArnParam =
      ssm.StringParameter.fromStringParameterAttributes(
        this,
        "CloudFrontWafArnParam",
        {
          parameterName: `/mcp/cloudfront-waf-arn-${props.resourceSuffix}`,
        }
      );

    // Create shared ECS cluster for all MCP servers
    this.cluster = new ecs.Cluster(this, "MCPCluster", {
      vpc: props.vpc,
      containerInsightsV2: ecs.ContainerInsights.ENHANCED
    });

    // Add suppression for Container Insight (V1 - Deprecated) not being Enabled while Container Insight V2 is Enabled with Enhanced
    NagSuppressions.addResourceSuppressions(this.cluster, [
      {
        id: "AwsSolutions-ECS4",
        reason:
          "Container Insights V2 is Enabled with Enhanced capabilities, the Nag finding is about Container Insights (V1) which is deprecated",
      },
    ]);

    // Create context parameter for optional certificate ARN and custom domain
    const certificateArn = this.node.tryGetContext("certificateArn");
    const customDomain = this.node.tryGetContext("customDomain");

    // Validate that if certificate is provided, custom domain must also be provided
    if (certificateArn && !customDomain) {
      throw new Error(
        "Custom domain name must be provided when using a certificate. While CloudFront's default domain will support HTTPS, " +
          "the Application Load Balancer HTTPS listener and origin configuration require both a valid certificate and matching custom domain name."
      );
    }

    // Create DynamoDB table for token storage with encryption
    const tokenTable = new dynamodb.Table(this, "McpTokenTable", {
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // Use on-demand pricing
      removalPolicy: cdk.RemovalPolicy.DESTROY, // For dev environment (use RETAIN for prod)
      timeToLiveAttribute: "expiration", // Enable TTL for automatic token expiration
      encryption: dynamodb.TableEncryption.AWS_MANAGED, // Enable server-side encryption
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
    });

    // Create a Secrets Manager secret for the Cognito client secret
    const cognitoClientSecret = new secretsmanager.Secret(
      this,
      "CognitoClientSecret",
      {
        secretName: `mcp-cognito-client-secret-${props.resourceSuffix}`,
        description: "Cognito client secret for MCP server",
        secretStringValue: props.userPoolClientSecret,
      }
    );

    // Add suppression for the secret not having rotation
    NagSuppressions.addResourceSuppressions(cognitoClientSecret, [
      {
        id: "AwsSolutions-SMG4",
        reason:
          "Cognito client secret is managed by Cognito and rotated when the client is updated - manual rotation is not required",
      },
    ]);

    // Create HTTP and HTTPS security groups for the ALB
    const httpSecurityGroup = new ec2.SecurityGroup(
      this,
      `HttpSecurityGroup-${props.resourceSuffix}`,
      {
        vpc: props.vpc,
        allowAllOutbound: true,
        description: `HTTP Security group for MCP-Server Stack ALB`,
      }
    );

    const httpsSecurityGroup = new ec2.SecurityGroup(
      this,
      `HttpsSecurityGroup-${props.resourceSuffix}`,
      {
        vpc: props.vpc,
        allowAllOutbound: true,
        description: `HTTPS Security group for MCP-Server Stack ALB`,
      }
    );

    const cloudFrontPrefixList = ec2.PrefixList.fromLookup(
      this,
      "CloudFrontOriginFacing",
      {
        prefixListName: "com.amazonaws.global.cloudfront.origin-facing",
      }
    );

    // Add ingress rules to appropriate security group
    httpSecurityGroup.addIngressRule(
      ec2.Peer.prefixList(cloudFrontPrefixList.prefixListId),
      ec2.Port.tcp(80),
      "Allow HTTP traffic from CloudFront edge locations"
    );

    httpsSecurityGroup.addIngressRule(
      ec2.Peer.prefixList(cloudFrontPrefixList.prefixListId),
      ec2.Port.tcp(443),
      "Allow HTTPS traffic from CloudFront edge locations"
    );

    // Use the appropriate security group based on certificate presence
    this.albSecurityGroup = certificateArn
      ? httpsSecurityGroup
      : httpSecurityGroup;

    // Create S3 bucket for ALB and CloudFront access logs with proper encryption and lifecycle rules
    const accessLogsBucket = new cdk.aws_s3.Bucket(this, "AccessLogsBucket", {
      encryption: cdk.aws_s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      blockPublicAccess: cdk.aws_s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // For dev environment (use RETAIN for prod)
      autoDeleteObjects: true,
      lifecycleRules: [
        {
          expiration: cdk.Duration.days(30), // Retain logs for 30 days
        },
      ],
      serverAccessLogsPrefix: "server-access-logs/", // Separate prefix for server access logs
      objectOwnership: cdk.aws_s3.ObjectOwnership.BUCKET_OWNER_PREFERRED, // Required for CloudFront logging
    });

    // Create Application Load Balancer dedicated to this MCP server
    this.loadBalancer = new elbv2.ApplicationLoadBalancer(
      this,
      `ApplicationLoadBalancer`,
      {
        vpc: props.vpc,
        internetFacing: true,
        securityGroup: this.albSecurityGroup,
        http2Enabled: true,
      }
    );

    // Enable access logging to S3
    this.loadBalancer.logAccessLogs(accessLogsBucket);

    const paramName = `/mcp/https-url`;

    // Deploy the Python auth server with CloudFront
    const authServer = new McpAuthFargateServerConstruct(
      this,
      "AuthPythonServer",
      {
        platform: {
          vpc: props.vpc,
          cluster: this.cluster,
        },
        serverName: "AuthPython",
        serverPath: path.join(__dirname, "../../servers/sample-auth-python"),
        healthCheckPath: "/",
        environment: {
          PORT: "8080",
          AWS_REGION: this.region,
          COGNITO_USER_POOL_ID: props.cognitoUserPool.userPoolId,
          COGNITO_CLIENT_ID: props.userPoolClientId,
          COGNITO_DOMAIN: `mcp-server-${props.resourceSuffix}`,
          TOKEN_TABLE_NAME: tokenTable.tableName, // Pass the DynamoDB table name
        },
        secrets: {
          // Use Secrets Manager to securely inject the secret into the container
          COGNITO_CLIENT_SECRET:
            ecs.Secret.fromSecretsManager(cognitoClientSecret),
        },
        tokenTable: tokenTable, // Pass the table resource to grant permissions
        albSecurityGroup: this.albSecurityGroup,
        urlParameterName: paramName,
      }
    );

    // ****************************************************************
    // Model Context Prototcol Auth Server built on ECS Fargate
    // ****************************************************************

    // Deploy the Python weather server with CloudFront
    const weatherPythonServer = new McpFargateServerConstruct(
      this,
      "WeatherPythonServer",
      {
        platform: {
          vpc: props.vpc,
          cluster: this.cluster,
        },
        serverName: "WeatherPython",
        serverPath: path.join(
          __dirname,
          "../../servers/sample-weather-sse-python"
        ),
        healthCheckPath: "/weather-python/",
        environment: {
          PORT: "8080",
          BASE_PATH: "/weather-python",
          AWS_REGION: this.region,
          COGNITO_USER_POOL_ID: props.cognitoUserPool.userPoolId,
          COGNITO_CLIENT_ID: props.userPoolClientId,
          COGNITO_DOMAIN: `mcp-server-${props.resourceSuffix}`,
          TOKEN_TABLE_NAME: tokenTable.tableName, // Pass the DynamoDB table name
        },
        tokenTable: tokenTable, // Pass the table resource to grant permissions
        albSecurityGroup: this.albSecurityGroup,
        urlParameterName: paramName,
      }
    );

    // ****************************************************************
    // Model Context Prototcol Server(s) built on ECS Fargate
    // ****************************************************************

    // Deploy the NodeJs weather server with CloudFront
    const weatherNodeJsServer = new McpFargateServerConstruct(
      this,
      "WeatherNodeJsServer",
      {
        platform: {
          vpc: props.vpc,
          cluster: this.cluster,
        },
        serverName: "WeatherNodeJs",
        serverPath: path.join(
          __dirname,
          "../../servers/sample-weather-streamable-stateless-nodejs"
        ),
        healthCheckPath: "/weather-nodejs/",
        environment: {
          PORT: "8080",
          BASE_PATH: "/weather-nodejs",
          AWS_REGION: this.region,
          COGNITO_USER_POOL_ID: props.cognitoUserPool.userPoolId,
          COGNITO_CLIENT_ID: props.userPoolClientId,
          COGNITO_DOMAIN: `mcp-server-${props.resourceSuffix}`,
          TOKEN_TABLE_NAME: tokenTable.tableName, // Pass the DynamoDB table name
        },
        tokenTable: tokenTable, // Pass the table resource to grant permissions
        albSecurityGroup: this.albSecurityGroup,
        urlParameterName: paramName,
      }
    );

    // ****************************************************************
    // Model Context Prototcol Server(s) built on Lambda
    // ****************************************************************

    // Deploy the NodeJS weather server using Streamable HTTP Transport (according to 2025-03-26 specification)
    const weatherLambda = new nodejs.NodejsFunction(
      this,
      "WeatherNodeJsLambda",
      {
        runtime: lambda.Runtime.NODEJS_22_X,
        entry: path.join(
          __dirname,
          "../../servers/sample-lambda-streamablehttp-weather-nodejs/index.ts"
        ),
        handler: "handler",
        bundling: {
          // No externalModules since we want to bundle everything
          nodeModules: [
            "@modelcontextprotocol/sdk",
            "hono",
            "fetch-to-node",
            "zod",
            "node-fetch",
            "jose",
          ],
          minify: false, // For easier debugging
          sourceMap: true,
          format: nodejs.OutputFormat.ESM,
          target: "node22", // Target Node.js 22.x
        },
        timeout: cdk.Duration.minutes(1),
        memorySize: 1024,
        environment: {
          COGNITO_USER_POOL_ID: props.cognitoUserPool.userPoolId,
          COGNITO_CLIENT_ID: props.userPoolClientId,
          PORT: "8080",
        },
        vpc: props.vpc,
      }
    );

    const weatherNodeJsLambdaServer = new McpLambdaServerlessConstruct(
      this,
      "WeatherNodeJsLambdaServer",
      {
        vpc: props.vpc,
        function: weatherLambda,
      }
    );

    // Add suppression for Lambda basic execution role
    NagSuppressions.addResourceSuppressions(
      weatherLambda,
      [
        {
          id: "AwsSolutions-IAM4",
          reason:
            "Lambda function requires basic VPC and CloudWatch Logs permissions through managed policy",
          appliesTo: [
            "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
          ],
        },
      ],
      true
    );

    // Create either HTTP or HTTPS listener based on certificate presence
    const listener = certificateArn
      ? this.loadBalancer.addListener("HttpsListener", {
          port: 443,
          protocol: elbv2.ApplicationProtocol.HTTPS,
          certificates: [
            acm.Certificate.fromCertificateArn(
              this,
              "AlbCertificate",
              certificateArn
            ),
          ],
          open: false,
          defaultAction: elbv2.ListenerAction.fixedResponse(404, {
            contentType: "text/plain",
            messageBody: "No matching route found",
          }),
        })
      : this.loadBalancer.addListener("HttpListener", {
          port: 80,
          protocol: elbv2.ApplicationProtocol.HTTP,
          open: false,
          defaultAction: elbv2.ListenerAction.fixedResponse(404, {
            contentType: "text/plain",
            messageBody: "No matching route found",
          }),
        });

    // Add routing rules to the listener
    listener.addAction("AuthServerRoute", {
      priority: 10, // Lower number means higher priority
      conditions: [
        elbv2.ListenerCondition.pathPatterns([
          "/.well-known/*",
          "/register",
          "/authorize",
          "/callback",
          "/token",
        ]),
      ],
      action: elbv2.ListenerAction.forward([authServer.targetGroup]),
    });

    listener.addAction("WeatherPythonRoute", {
      priority: 20,
      conditions: [elbv2.ListenerCondition.pathPatterns(["/weather-python/*"])],
      action: elbv2.ListenerAction.forward([weatherPythonServer.targetGroup]),
    });

    listener.addAction("WeatherNodeJsRoute", {
      priority: 21,
      conditions: [elbv2.ListenerCondition.pathPatterns(["/weather-nodejs/*"])],
      action: elbv2.ListenerAction.forward([weatherNodeJsServer.targetGroup]),
    });

    // Add a rule to route auth-related paths to the auth server
    listener.addAction("WeatherNodeJsLambdaRoute", {
      priority: 22, // Lower number means higher priority
      conditions: [
        elbv2.ListenerCondition.pathPatterns(["/weather-nodejs-lambda/*"]),
      ],
      action: elbv2.ListenerAction.forward([
        weatherNodeJsLambdaServer.targetGroup,
      ]),
    });

    // Create CloudFront distribution with protocol matching ALB listener
    const albOrigin = new origins.LoadBalancerV2Origin(this.loadBalancer, {
      protocolPolicy: certificateArn
        ? cloudfront.OriginProtocolPolicy.HTTPS_ONLY
        : cloudfront.OriginProtocolPolicy.HTTP_ONLY,
      httpPort: 80,
      httpsPort: 443,
      connectionAttempts: 3,
      connectionTimeout: cdk.Duration.seconds(10),
      readTimeout: cdk.Duration.seconds(30),
      keepaliveTimeout: cdk.Duration.seconds(5),
    });

    const geoRestriction = cloudfront.GeoRestriction.allowlist(
      ...getAllowedCountries()
    );

    // Create the CloudFront distribution with conditional properties
    if (customDomain && certificateArn) {
      // With custom domain and certificate
      const certificate = acm.Certificate.fromCertificateArn(
        this,
        `MCPServerStackCertificate`,
        certificateArn
      );

      this.distribution = new cloudfront.Distribution(
        this,
        `MCPServerStackDistribution`,
        {
          defaultBehavior: {
            origin: albOrigin,
            allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
            cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
            viewerProtocolPolicy:
              cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
          },
          domainNames: [customDomain],
          certificate: certificate,
          enabled: true,
          minimumProtocolVersion:
            cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
          httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
          priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
          comment: `CloudFront distribution for MCP-Server Stack with custom domain`,
          geoRestriction,
          webAclId: cloudFrontWafArnParam.stringValue,
          logBucket: accessLogsBucket,
          logFilePrefix: "cloudfront-logs/",
        }
      );
    } else {
      // Default CloudFront domain
      this.distribution = new cloudfront.Distribution(
        this,
        `MCPServerStackDistribution`,
        {
          defaultBehavior: {
            origin: albOrigin,
            allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
            cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
            viewerProtocolPolicy:
              cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
          },
          enabled: true,
          httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
          priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
          comment: `CloudFront distribution for MCP-Server stack`,
          geoRestriction,
          webAclId: cloudFrontWafArnParam.stringValue,
          logBucket: accessLogsBucket,
          logFilePrefix: "cloudfront-logs/",
        }
      );
    }

    // Add suppressions for CloudFront TLS warnings
    NagSuppressions.addResourceSuppressions(this.distribution, [
      {
        id: "AwsSolutions-CFR4",
        reason:
          "Development environment using default CloudFront certificate without custom domain - TLS settings are managed by CloudFront",
      },
      {
        id: "AwsSolutions-CFR5",
        reason:
          "Development environment using HTTP-only communication to ALB origin which is internal to VPC",
      },
    ]);

    // Set the HTTPS URL
    const httpsUrl = `https://${this.distribution.distributionDomainName}`;

    // Create SSM parameter for the HTTPS URL
    const httpsUrlParameter = new ssm.StringParameter(this, `HttpsUrlParam`, {
      parameterName: paramName,
      stringValue: httpsUrl,
      description: `HTTPS URL for the MCP-Server Stack Distribution`,
      tier: ssm.ParameterTier.STANDARD,
    });

    // Output CloudFront distribution details
    new cdk.CfnOutput(this, "CloudFrontDistributions", {
      value: httpsUrl,
      description: "CloudFront HTTPS URLs for all MCP servers",
    });

    // Create a custom resource to update the Cognito app client redirect URIs
    const cognitoRedirectUpdaterFn = new lambda.Function(
      this,
      "CognitoRedirectUpdater",
      {
        runtime: lambda.Runtime.NODEJS_22_X,
        handler: "index.handler",
        code: lambda.Code.fromAsset(
          path.join(__dirname, "../lambdas/cognito-redirect-updater")
        ),
        timeout: cdk.Duration.seconds(60),
      }
    );

    // Add suppression for Lambda basic execution role
    NagSuppressions.addResourceSuppressions(
      cognitoRedirectUpdaterFn,
      [
        {
          id: "AwsSolutions-IAM4",
          reason:
            "Lambda function requires basic CloudWatch Logs permissions through managed policy",
          appliesTo: [
            "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
          ],
        },
      ],
      true
    );

    // Grant permissions to the Lambda function
    cognitoRedirectUpdaterFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:UpdateUserPoolClient",
        ],
        resources: [props.cognitoUserPool.userPoolArn],
      })
    );

    cognitoRedirectUpdaterFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ssm:GetParameter"],
        resources: [
          `arn:aws:ssm:${this.region}:${this.account}:parameter/mcp/cognito/app-client-user-id-${props.resourceSuffix}`,
        ],
      })
    );

    // Create the custom resource that uses our Lambda function
    new cdk.CustomResource(this, "CognitoRedirectUpdaterResource", {
      serviceToken: cognitoRedirectUpdaterFn.functionArn,
      properties: {
        // Adding a timestamp forces the custom resource to run on each deployment
        Timestamp: Date.now().toString(),
        UserPoolId: props.cognitoUserPool.userPoolId,
        CloudfrontUrl: httpsUrl,
        AppClientParamName: `/mcp/cognito/app-client-user-id-${props.resourceSuffix}`,
        Region: this.region,
      },
    });
  }
}
