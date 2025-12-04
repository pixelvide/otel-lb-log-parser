# Docker Deployment Guide

## Build and Run Locally

### 1. Build the Docker Image
```bash
cd go-alb-processor
docker build -t alb-processor:latest .
```

### 2. Run with Docker Compose
```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret

# Start the container
docker-compose up -d

# View logs
docker-compose logs -f alb-processor
```

### 3. Test Locally
```bash
# Make the test script executable
chmod +x test-lambda-local.sh

# Run the test
./test-lambda-local.sh
```

## Deploy to AWS Lambda (Container Image)

### 1. Create ECR Repository
```bash
aws ecr create-repository \
  --repository-name alb-processor \
  --region ap-south-1
```

### 2. Build and Push to ECR
```bash
# Login to ECR
aws ecr get-login-password --region ap-south-1 | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.ap-south-1.amazonaws.com

# Build for ARM64 (Graviton2 - cheaper and faster)
docker buildx build --platform linux/arm64 \
  -t <account-id>.dkr.ecr.ap-south-1.amazonaws.com/alb-processor:latest \
  --push .

# Or build for AMD64
docker buildx build --platform linux/amd64 \
  -t <account-id>.dkr.ecr.ap-south-1.amazonaws.com/alb-processor:latest \
  --push .
```

### 3. Create Lambda Function
```bash
aws lambda create-function \
  --function-name alb-log-processor \
  --package-type Image \
  --code ImageUri=<account-id>.dkr.ecr.ap-south-1.amazonaws.com/alb-processor:latest \
  --role arn:aws:iam::<account-id>:role/lambda-execution-role \
  --architectures arm64 \
  --timeout 300 \
  --memory-size 512 \
  --environment Variables="{
    SIGNOZ_OTLP_ENDPOINT=http://your-endpoint:4318/v1/logs,
    MAX_BATCH_SIZE=500,
    MAX_RETRIES=3
  }"
```

### 4. Add S3 Trigger
```bash
# Add S3 bucket notification
aws s3api put-bucket-notification-configuration \
  --bucket your-alb-logs-bucket \
  --notification-configuration file://s3-notification.json
```

**s3-notification.json:**
```json
{
  "LambdaFunctionConfigurations": [
    {
      "LambdaFunctionArn": "arn:aws:lambda:ap-south-1:<account>:function:alb-log-processor",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {
          "FilterRules": [
            {"Name": "suffix", "Value": ".gz"}
          ]
        }
      }
    }
  ]
}
```

### 5. Update Function
```bash
# Rebuild and push new image
docker buildx build --platform linux/arm64 \
  -t <account-id>.dkr.ecr.ap-south-1.amazonaws.com/alb-processor:latest \
  --push .

# Update Lambda function
aws lambda update-function-code \
  --function-name alb-log-processor \
  --image-uri <account-id>.dkr.ecr.ap-south-1.amazonaws.com/alb-processor:latest
```

## Testing the Lambda

### Test with AWS CLI
```bash
# Create test event
cat > event.json << EOF
{
  "Records": [{
    "s3": {
      "bucket": {"name": "your-bucket"},
      "object": {"key": "path/to/log.gz"}
    }
  }]
}
EOF

# Invoke function
aws lambda invoke \
  --function-name alb-log-processor \
  --payload file://event.json \
  output.json

# View output
cat output.json
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SIGNOZ_OTLP_ENDPOINT` | OTLP HTTP endpoint | `http://localhost:4318/v1/logs` |
| `BASIC_AUTH_USERNAME` | Optional basic auth username | - |
| `BASIC_AUTH_PASSWORD` | Optional basic auth password | - |
| `MAX_BATCH_SIZE` | Max logs per batch | `500` |
| `MAX_RETRIES` | HTTP retry attempts | `3` |

## Troubleshooting

### View Lambda Logs
```bash
aws logs tail /aws/lambda/alb-log-processor --follow
```

### Check Container Locally
```bash
docker run -it --rm alb-processor:latest /bin/sh
```

### Memory/Performance Issues
- Increase Lambda memory: `--memory-size 1024`
- Use ARM64 (Graviton2): `--architectures arm64`
- Adjust batch size: `MAX_BATCH_SIZE=250`
