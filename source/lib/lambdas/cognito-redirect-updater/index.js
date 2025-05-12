const {
  CognitoIdentityProviderClient,
  UpdateUserPoolClientCommand,
  DescribeUserPoolClientCommand,
} = require("@aws-sdk/client-cognito-identity-provider");
const { SSMClient, GetParameterCommand } = require("@aws-sdk/client-ssm");
const https = require("https");
const url = require("url");

exports.handler = async function (event, context) {
  console.log("Event:", JSON.stringify(event, null, 2));

  try {
    // For CREATE and UPDATE events, we need to update the app client
    if (event.RequestType === "Create" || event.RequestType === "Update") {
      const props = event.ResourceProperties;
      const userPoolId = props.UserPoolId;
      const cloudfrontUrl = props.CloudfrontUrl;
      const appClientParamName = props.AppClientParamName;
      const region = props.Region;

      console.log("User Pool ID:", userPoolId);
      console.log("CloudFront URL:", cloudfrontUrl);
      console.log("App Client Parameter Name:", appClientParamName);

      // Get the app client ID from SSM parameter
      const ssmClient = new SSMClient({ region });
      const getParamResponse = await ssmClient.send(
        new GetParameterCommand({ Name: appClientParamName })
      );

      const appClientId = getParamResponse.Parameter.Value;
      console.log("App Client ID:", appClientId);

      // Get current app client configuration
      const cognitoClient = new CognitoIdentityProviderClient({ region });
      const describeResponse = await cognitoClient.send(
        new DescribeUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientId: appClientId,
        })
      );

      const currentAppClient = describeResponse.UserPoolClient;
      console.log(
        "Current App Client:",
        JSON.stringify(currentAppClient, null, 2)
      );

      // Add CloudFront URLs to redirect URIs if they don't exist already
      const callbackUrls = new Set(currentAppClient.CallbackURLs || []);
      const logoutUrls = new Set(currentAppClient.LogoutURLs || []);

      // Add base URL and callback URL
      callbackUrls.add(cloudfrontUrl);
      callbackUrls.add(`${cloudfrontUrl}/callback`);
      logoutUrls.add(cloudfrontUrl);
      logoutUrls.add(`${cloudfrontUrl}/callback`);

      // Update the app client with new redirect URIs
      console.log("Updated Callback URLs:", Array.from(callbackUrls));
      console.log("Updated Logout URLs:", Array.from(logoutUrls));

      await cognitoClient.send(
        new UpdateUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientId: appClientId,
          ClientName: currentAppClient.ClientName,
          RefreshTokenValidity: currentAppClient.RefreshTokenValidity,
          AccessTokenValidity: currentAppClient.AccessTokenValidity,
          IdTokenValidity: currentAppClient.IdTokenValidity,
          TokenValidityUnits: currentAppClient.TokenValidityUnits,
          ExplicitAuthFlows: currentAppClient.ExplicitAuthFlows,
          AllowedOAuthFlows: currentAppClient.AllowedOAuthFlows,
          AllowedOAuthScopes: currentAppClient.AllowedOAuthScopes,
          AllowedOAuthFlowsUserPoolClient:
            currentAppClient.AllowedOAuthFlowsUserPoolClient,
          CallbackURLs: Array.from(callbackUrls),
          LogoutURLs: Array.from(logoutUrls),
          SupportedIdentityProviders:
            currentAppClient.SupportedIdentityProviders,
          GenerateSecret: currentAppClient.GenerateSecret,
          PreventUserExistenceErrors:
            currentAppClient.PreventUserExistenceErrors,
        })
      );

      console.log("Successfully updated app client redirect URIs");
    }

    // Send success response back to CloudFormation
    await sendResponse(event, context, "SUCCESS", {
      Message: "Operation completed successfully",
    });
  } catch (error) {
    console.error("Error:", error);
    await sendResponse(event, context, "FAILED", { Error: error.message });
  }
};

// Helper function to send response to CloudFormation
async function sendResponse(event, context, responseStatus, responseData) {
  const responseBody = JSON.stringify({
    Status: responseStatus,
    Reason:
      responseStatus === "FAILED"
        ? "See the details in CloudWatch Log Stream: " + context.logStreamName
        : "See the details in CloudWatch Log Stream",
    PhysicalResourceId: context.logStreamName,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    NoEcho: false,
    Data: responseData,
  });

  console.log("Response body:", responseBody);

  const parsedUrl = url.parse(event.ResponseURL);

  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.path,
    method: "PUT",
    headers: {
      "Content-Type": "",
      "Content-Length": responseBody.length,
    },
  };

  return new Promise((resolve, reject) => {
    const request = https.request(options, function (response) {
      console.log("Status code:", response.statusCode);
      resolve();
    });

    request.on("error", function (error) {
      console.log("send response error:", error);
      reject(error);
    });

    request.write(responseBody);
    request.end();
  });
}
