#!/bin/bash
set -e

echo "Building CloudTrail query Python container..."
cd servers/cloudtrail-query-python
docker build -t cloudtrail-query-python .

echo "Running container locally..."
docker run -p 8080:8080 -e AWS_REGION=$(aws configure get region) cloudtrail-query-python
