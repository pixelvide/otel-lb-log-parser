#!/bin/bash
# Local test script for Lambda function

# Example S3 event payload
cat > test-event.json << 'EOF'
{
  "Records": [
    {
      "eventVersion": "2.1",
      "eventSource": "aws:s3",
      "awsRegion": "ap-south-1",
      "eventTime": "2025-12-04T10:00:00.000Z",
      "eventName": "ObjectCreated:Put",
      "s3": {
        "bucket": {
          "name": "your-bucket-name",
          "arn": "arn:aws:s3:::your-bucket-name"
        },
        "object": {
          "key": "logs/alb-log.gz",
          "size": 1024
        }
      }
    }
  ]
}
EOF

# Invoke the Lambda function locally
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
  -d @test-event.json

echo ""
echo "Test complete!"
