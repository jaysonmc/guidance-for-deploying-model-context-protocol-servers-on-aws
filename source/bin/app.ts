#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { VpcStack } from "../lib/stacks/vpc-stack";
import { SecurityStack } from "../lib/stacks/security-stack";
import { MCPServerStack } from "../lib/stacks/mcp-server-stack";
import { CloudFrontWafStack } from "../lib/stacks/cloudfront-waf-stack";
import { Aspects } from "aws-cdk-lib";
import { AwsSolutionsChecks } from "cdk-nag";

const app = new cdk.App();

const resourceSuffix = app.node.addr
  .substring(0, 8)
  .toLowerCase()
  .replace(/[^a-z0-9-]/g, "");

// Get context values for existing VPC if provided
const existingVpcId = app.node.tryGetContext("existingVpcId");
const publicSubnetIds = app.node.tryGetContext("publicSubnetIds")?.split(",");
const privateSubnetIds = app.node.tryGetContext("privateSubnetIds")?.split(",");

// Create VPC stack (or use existing VPC)
const vpcStack = new VpcStack(app, "MCP-VPC", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  existingVpcId,
  publicSubnetIds,
  privateSubnetIds,
});

// Create security stack (Cognito + WAF)
const securityStack = new SecurityStack(app, "MCP-Security", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  vpc: vpcStack.vpc,
  resourceSuffix,
});

// Get the target region (where the MCP server stack will be deployed)
const targetRegion = process.env.CDK_DEFAULT_REGION || "us-west-2";

// Create CloudFront WAF stack in us-east-1 (required for CloudFront WAF)
const cloudFrontWafStack = new CloudFrontWafStack(app, "MCP-CloudFront-WAF", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: "us-east-1", // CloudFront WAF must be in us-east-1
  },
  resourceSuffix,
  targetRegion, // Pass the target region to the CloudFront WAF stack
});

// Create MCPServerStack which includes both platform and servers
const serverStack = new MCPServerStack(app, "MCP-Server", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  resourceSuffix,
  vpc: vpcStack.vpc,
  cognitoUserPool: securityStack.userPool,
  userPoolClientId: securityStack.appClientUser.userPoolClientId,
  userPoolClientSecret: securityStack.appClientUser.userPoolClientSecret,
});
serverStack.addDependency(cloudFrontWafStack);

// Tag all resources
cdk.Tags.of(app).add("Project", "MCP-Servers-On-AWS");

Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
